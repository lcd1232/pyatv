"""AirParrot-dialect mirror video transport (reverse-engineered 2026-08-23).

Unlike the macOS-AVConference / Viceroy path (UDP RTP + SRTP), a real tvOS 26
receiver driven by AirParrot 3 takes screen video over a **raw TCP** media-data
channel with this framing (verified by decrypting AirParrot's live stream, see
docs/superpowers/specs/2026-08-23-mirror-video-key-handoff.md SESSION 3):

    per message (one H.264 access unit):
        128-byte header:
            [0:4]   payload length      uint32 LE  (bytes after the header)
            [4:8]   0x00 0x00 0x06 0x00 (video-data type/flags)
            [8:16]  presentation timestamp uint64 LE (monotonic)
            [16:128] zero
        payload:
            AES-128-CTR ciphertext, ONE CONTINUOUS keystream for the whole
            stream (no per-frame reset). Plaintext = the access unit in AVCC
            form: for each NAL, 4-byte big-endian length prefix + NAL bytes.

The key/iv are the SQAirPlayClientSessionDeriveKeyAndIV-derived values (see
session.py PROVEN block): key = sha512("AirPlayStreamKey"+id || secret16)[:16].
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
#:
#: There is a SECOND definition of "is this NAL a coded slice" in
#: ``session.py``'s live-encoder path, which tests only ``t in (1, 5)``. The two
#: agree on every stream that exists in practice: 2/3/4 are data partitions A/B/C,
#: which only the Extended profile may emit and Baseline/Main/High forbid, so no
#: encoder feeding either path produces one. They are therefore NOT a bug today —
#: but they are two definitions of one concept, and only this note keeps the next
#: reader from having to rediscover that. Change one and check the other.
_VCL_TYPES = frozenset(range(1, 6))


class RawVideoTCPChannel(asyncio.Protocol):
    """Plain TCP connection to the receiver's video ``dataPort``.

    No HAP/ChaCha layer (unlike :class:`AbstractHAPChannel`) — the AirParrot
    media-data channel is raw TCP; the only encryption is the AES-CTR applied
    to each frame payload before it is queued here.
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
        # The receiver may push a greeting/control byte back; log it.
        _LOGGER.info(
            "raw video channel got %d inbound bytes: %s",
            len(data),
            data[:32].hex(),
        )

    def eof_received(self) -> Optional[bool]:  # pylint: disable=useless-return
        """Warn on a half-close and let the transport close."""
        _LOGGER.warning("raw video channel: receiver sent EOF (half-close)")
        # A false-y return tells asyncio to close the transport.  This is
        # spelled out rather than falling off the end because mypy reads
        # `-> Optional[bool]` as requiring a return statement; pylint then
        # calls that return useless, so exactly one of the two gates has to
        # be told.  mypy is the one whose complaint is about the signature.
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

    Observed in AirParrot's stream as a constant per-session block, e.g.
    surface 3324x2160, origin 337x51, content 3164.7x2056.1. The receiver
    appears to require a non-zero rect (a zeroed field gets the stream closed
    after the first frame).
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
    """Build the 128-byte AirParrot media-data header for a payload.

    ``dims`` = (width, height) floats written at offset 16 (two little-endian
    float32). AirParrot's CONFIG frame (type 0x01000600) carries the source
    surface dimensions there so the receiver can size its decoder/display;
    video frames leave [16:24] zero. Omitting it leaves the receiver unable to
    configure the mirror surface (black screen).
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

    AirParrot sends this PLAINTEXT as the first data-channel message (header
    type 0x01000600) so the receiver can initialise its H.264 decoder before
    any encrypted frame arrives. NALs are without start codes.
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
    NAL (coded slice) closes an access unit. Mirrors AirParrot's per-frame
    message grouping (e.g. SEI+IDR in one message, a lone slice in the next).
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
