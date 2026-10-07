"""RTP packetization for the AirPlay 2 mirroring video stream.

Derived from a capture of a real macOS sender mirroring to an Apple TV
(tvOS 26.6), recorded through ``atvproxy``'s media relay — see
``docs/superpowers/specs/2026-08-22-fply-phase28-ground-truth-capture.md``.

Each datagram on the negotiated UDP ``dataPort`` is a standard RTP packet
carrying a 4-byte header extension::

    0                   1                   2                   3
    |V=2|P|X=1| CC=0 |M|   PT=100    |        sequence number        |
    |                           timestamp (90 kHz)                  |
    |                              SSRC                             |
    |        extension id           |      extension length = 1     |
    |   0   | fragment count|        frame counter                  |

A video frame is one ``(SSRC, timestamp)`` group:

* the frame's encrypted bytes are split across consecutive sequence numbers,
* every packet of the frame repeats the same timestamp and fragment count,
* the marker bit is set on the **last** packet only.

Verified against 7044 frames in the capture: the marker bit was on the last
packet and nowhere else in every single frame, sequence numbers were
consecutive within every frame, and the fragment count matched the group size
for all 71 multi-packet frames.
"""

from __future__ import annotations

import secrets
import struct
from typing import Any, List, Optional

#: RTP payload type used for the mirroring video stream.
PAYLOAD_TYPE_MIRROR = 100

#: Header extension id seen on the majority of packets. A second value,
#: ``0x9001``, also occurs; it is constant within a frame and does not
#: correlate with fragmentation, so its meaning is still unknown.
EXTENSION_ID = 0x9011
EXTENSION_ID_ALT = 0x9001

#: Timestamps advance on a 90 kHz clock (a one-second gap in the capture
#: showed a delta of exactly 90000).
CLOCK_RATE = 90_000

#: Largest payload the real sender put in one datagram was ~1360 bytes
#: including headers; keep clear of it.
MAX_PAYLOAD = 1330

_RTP_HEADER = struct.Struct(">BBHII")
_EXTENSION_HEADER = struct.Struct(">HH")


class RtpPacketizer:
    """Split encrypted mirror frames into RTP datagrams."""

    def __init__(
        self,
        ssrc: Optional[int] = None,
        payload_type: int = PAYLOAD_TYPE_MIRROR,
        extension_id: int = EXTENSION_ID,
        max_payload: int = MAX_PAYLOAD,
    ) -> None:
        """Initialize a packetizer for one video sub-stream."""
        if max_payload <= 0:
            raise ValueError(f"max_payload must be positive, got {max_payload}")
        self.ssrc = secrets.randbits(32) if ssrc is None else ssrc
        self.payload_type = payload_type
        self.extension_id = extension_id
        self.max_payload = max_payload
        self._sequence = secrets.randbits(16)
        self._frame_counter = 0

    def packetize(
        self,
        payload: bytes,
        timestamp: int,
        encryptor: Any = None,
        frame_counter: Optional[int] = None,
    ) -> List[bytes]:
        """Return the datagrams carrying one frame.

        With ``encryptor`` (a :class:`~pyatv.protocols.airplay.mirror.srtp.
        SrtpVideoEncryptor`) the *plaintext* frame is split into fragments and
        each fragment's payload is SRTP-encrypted keyed by that packet's RTP
        sequence number (the SRTP IV is per-packet). Without it the payload is
        assumed already-encrypted and only split.

        An empty payload still produces one packet, matching the sender's
        behaviour of never emitting a frame with zero fragments.
        """
        chunks = [
            payload[offset : offset + self.max_payload]
            for offset in range(0, len(payload), self.max_payload)
        ] or [b""]
        if len(chunks) > 0xFF:
            raise ValueError(
                f"frame needs {len(chunks)} fragments, more than the "
                "fragment-count byte can express"
            )

        if frame_counter is None:
            frame_counter = self._frame_counter & 0xFFFF
            self._frame_counter += 1
        else:
            frame_counter &= 0xFFFF

        packets = []
        for index, chunk in enumerate(chunks):
            last = index == len(chunks) - 1
            sequence = self._sequence & 0xFFFF
            header = _RTP_HEADER.pack(
                0x90,  # version 2, extension present
                self.payload_type | (0x80 if last else 0x00),
                sequence,
                timestamp & 0xFFFFFFFF,
                self.ssrc & 0xFFFFFFFF,
            )
            extension = (
                _EXTENSION_HEADER.pack(self.extension_id, 1)
                + bytes([0x00, len(chunks)])
                + struct.pack(">H", frame_counter)
            )
            if encryptor is not None:
                chunk = encryptor.encrypt(sequence, chunk)
            packets.append(header + extension + chunk)
            self._sequence = (self._sequence + 1) & 0xFFFF
        return packets


def parse_header(packet: bytes) -> dict:
    """Parse an RTP mirror packet header (used by tests and capture tooling)."""
    if len(packet) < 20:
        raise ValueError(f"packet too short: {len(packet)} bytes")
    byte0, byte1, sequence, timestamp, ssrc = _RTP_HEADER.unpack(packet[:12])
    extension_id, extension_words = _EXTENSION_HEADER.unpack(packet[12:16])
    return {
        "version": byte0 >> 6,
        "extension": bool((byte0 >> 4) & 1),
        "marker": bool(byte1 >> 7),
        "payload_type": byte1 & 0x7F,
        "sequence": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "extension_id": extension_id,
        "extension_words": extension_words,
        "fragment_count": packet[17],
        "frame_counter": struct.unpack(">H", packet[18:20])[0],
        "payload": packet[20:],
    }
