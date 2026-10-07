"""Mirror video transport over the raw TCP media-data channel.

The receiver takes screen video on a plain TCP connection to the ``dataPort``
returned by the type-110 SETUP. Each video message is one H.264 access unit::

    128-byte header:
        [0:4]    payload length          uint32 LE (bytes after the header)
        [4:8]    message type            00 00 06 00 = encrypted video frame
                                         01 00 06 00 = plaintext avcC config
        [8:16]   presentation timestamp  uint64 LE (monotonic)
        [16:24]  config only: width, height as float32 LE
        [40:64]  display geometry (see build_geometry)
        rest     zero
    payload:
        AES-128-CTR ciphertext, ONE CONTINUOUS keystream for the whole
        stream (no per-frame reset). Plaintext = the access unit in AVCC
        form: for each NAL, 4-byte big-endian length prefix + NAL bytes.

The first message is the plaintext avcC config; it does not advance the
keystream. The key/iv come from
:func:`~pyatv.protocols.airplay.mirror.framing.derive_tcp_stream_key_iv`.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from typing import List, Optional

_LOGGER = logging.getLogger(__name__)

#: message types in the 128-byte header (bytes [4:8]).
_VIDEO_DATA_TYPE = b"\x00\x00\x06\x00"  # encrypted AES-CTR video frame
_CONFIG_TYPE = b"\x01\x00\x06\x00"  # PLAINTEXT avcC decoder config (first)
_HEADER_LEN = 128

#: VCL NAL types (a coded slice) — used to group NALs into access units.
#: ``session.py``'s live path tests only (1, 5); 2-4 are Extended-profile data
#: partitions that Baseline/Main/High never emit. Keep the two in step.
_VCL_TYPES = frozenset(range(1, 6))


class RawVideoTCPChannel(asyncio.Protocol):
    """Plain TCP connection to the receiver's video ``dataPort``.

    No HAP/ChaCha layer: the only encryption is the AES-CTR applied to each
    frame payload before it is queued here.
    """

    def __init__(self) -> None:
        """Start with no transport and nothing sent."""
        self.transport: Optional[asyncio.Transport] = None
        self._sent = 0
        self._bytes = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Record the transport and log the peer."""
        self.transport = transport  # type: ignore[assignment]
        peer = transport.get_extra_info("peername")
        _LOGGER.info("raw video TCP channel connected to %s", peer)

    def data_received(self, data: bytes) -> None:
        """Log anything the receiver pushes back; nothing is expected."""
        _LOGGER.info(
            "raw video channel got %d inbound bytes: %s",
            len(data),
            data[:32].hex(),
        )

    def eof_received(self) -> Optional[bool]:  # pylint: disable=useless-return
        """Warn on a half-close and let the transport close."""
        _LOGGER.warning("raw video channel: receiver sent EOF (half-close)")
        # A false-y return tells asyncio to close the transport. Explicit
        # because mypy requires a return for ``-> Optional[bool]``.
        return None

    def send(self, data: bytes) -> None:
        """Write one already-framed message to the socket."""
        if self.transport is None or self.transport.is_closing():
            return
        self.transport.write(data)
        self._sent += 1
        self._bytes += len(data)
        if self._sent % 200 == 0:
            _LOGGER.info(
                "VIDEO SENT %d messages, %d bytes (raw TCP dataPort)",
                self._sent,
                self._bytes,
            )

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Warn with the totals sent before the channel dropped."""
        _LOGGER.warning(
            "raw video TCP channel LOST after %d msgs / %d bytes: %s",
            self._sent,
            self._bytes,
            exc,
        )


def build_geometry(
    surface_w: float,
    surface_h: float,
    origin_x: float,
    origin_y: float,
    content_w: float,
    content_h: float,
) -> bytes:
    """Pack the 6-float display-geometry field that lives at header offset 40.

    Six float32 LE: surface w/h, content origin x/y, content w/h; constant for
    a session. The receiver requires a non-zero rect: a zeroed field gets the
    stream closed after the first frame.
    """
    return struct.pack(
        "<ffffff",
        surface_w,
        surface_h,
        origin_x,
        origin_y,
        content_w,
        content_h,
    )


def build_data_header(
    payload_len: int,
    timestamp: int,
    geometry: bytes = b"",
    msg_type: bytes = _VIDEO_DATA_TYPE,
    dims: tuple = (),
) -> bytes:
    """Build the 128-byte TCP-dialect media-data header for a payload.

    ``dims`` = (width, height), written at offset 16 as two float32 LE. The
    config message must carry the source dimensions there or the receiver
    cannot configure the mirror surface (black screen); video frames leave
    [16:24] zero.
    """
    header = bytearray(_HEADER_LEN)
    struct.pack_into("<I", header, 0, payload_len & 0xFFFFFFFF)
    header[4:8] = msg_type
    struct.pack_into("<Q", header, 8, timestamp & 0xFFFFFFFFFFFFFFFF)
    if dims:
        struct.pack_into("<ff", header, 16, float(dims[0]), float(dims[1]))
    if geometry:
        header[40 : 40 + len(geometry)] = geometry[:24]
    return bytes(header)


def build_avcc_config(sps: bytes, pps: bytes) -> bytes:
    """Build an AVCDecoderConfigurationRecord (avcC) from raw SPS/PPS NALs.

    Sent in plaintext as the first data-channel message (type 0x01000600) so
    the receiver can initialise its H.264 decoder before any encrypted frame
    arrives. NALs are without start codes.
    """
    out = bytearray()
    out.append(0x01)  # configurationVersion
    out.append(sps[1])  # AVCProfileIndication
    out.append(sps[2])  # profile_compatibility
    out.append(sps[3])  # AVCLevelIndication
    out.append(0xFF)  # 6 reserved bits + lengthSizeMinusOne=3
    out.append(0xE1)  # 3 reserved bits + numOfSequenceParameterSets=1
    out += struct.pack(">H", len(sps))
    out += sps
    out.append(0x01)  # numOfPictureParameterSets=1
    out += struct.pack(">H", len(pps))
    out += pps
    return bytes(out)


def to_avcc(nalus: List[bytes]) -> bytes:
    """Concatenate NAL units (no start codes) as AVCC: 4-byte BE length + NAL."""
    out = bytearray()
    for nal in nalus:
        out += struct.pack(">I", len(nal))
        out += nal
    return bytes(out)


def group_access_units(nalus: List[bytes], nal_type) -> List[List[bytes]]:
    """Group a flat NAL list into access units.

    Non-VCL NALs (SPS/PPS/SEI/AUD) attach to the following VCL NAL; each VCL
    NAL (coded slice) closes an access unit, so e.g. SEI+IDR travel in one
    message.
    """
    units: List[List[bytes]] = []
    pending: List[bytes] = []
    for nal in nalus:
        pending.append(nal)
        if nal_type(nal) in _VCL_TYPES:
            units.append(pending)
            pending = []
    if pending:
        units.append(pending)
    return units
