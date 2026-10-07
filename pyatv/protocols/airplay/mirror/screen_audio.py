"""TCP-dialect screen-AUDIO packetization (RE'd 2026-08-24).

Unlike the video stream (raw TCP, 128-byte header, AES-CTR), the reference
sender's screen audio is **UDP/RTP** carrying **AAC-ELD** (44100 Hz stereo, 480
samples/frame), each frame **AES-128-CBC** encrypted (whole 16-byte blocks only;
the trailing ``len % 16`` bytes are sent in the clear). Source: reverse-engineering of
``_APOAudioConnectionSendFrame`` @0x10008ea9c and ``_init_ap_audio_data_pkt``
@0x1001b183c.

Key model (CONFIRMED via DeriveAudioKeyAndIV @0x1a05d0): the audio key is
``secret16 = sha512(raw16 || pair32)[:16]`` — the SAME secret16 as the video
stream but WITHOUT the "AirPlayStreamKey" labeling step. ``raw16`` is the value
wrapped in the audio ``ekey`` (the receiver unwraps it); ``pair32`` is the media
pair-verify shared secret. The IV is the sender-chosen ``eiv`` sent in SETUP.

This module implements only the packetization + framing + encryption; producing
the AAC-ELD frames (Apple AudioConverter ``kAudioFormatMPEG4AAC_ELD``) and the
system-audio source are separate concerns.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyatv.protocols.raop.packets import SyncPacket

#: RTP payload type for the TCP dialect's screen-audio stream (byte 1 = M<<7 | PT).
AUDIO_RTP_PT = 0x60  # marker=0, PT=96
#: Samples per AAC-ELD frame (RTP timestamp increment per packet, 44100 Hz).
AUDIO_SAMPLES_PER_FRAME = 480
AUDIO_SAMPLE_RATE = 44100


def encrypt_audio_frame(key: bytes, iv: bytes, aac_frame: bytes) -> bytes:
    """AES-128-CBC encrypt an AAC-ELD frame, as the reference sender does.

    Only whole 16-byte blocks are encrypted; the trailing ``len % 16`` bytes are
    appended in the clear. The IV is the constant ``eiv`` for every packet (not
    chained across packets).
    """
    if len(key) != 16:
        raise ValueError(f"audio key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"audio iv (eiv) must be 16 bytes, got {len(iv)}")
    whole = len(aac_frame) & ~0x0F
    if whole:
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        head = enc.update(aac_frame[:whole]) + enc.finalize()
    else:
        head = b""
    return head + aac_frame[whole:]


def build_audio_rtp_packet(
    seq: int, timestamp: int, payload: bytes, ssrc: int = 0
) -> bytes:
    """Return a 12-byte RTP header + ``payload``.

    Header = ``80 60 | seq(BE16) | timestamp(BE32) | ssrc(BE32)``.
    """
    header = struct.pack(
        ">BBHII",
        0x80,  # V=2, P=0, X=0, CC=0
        AUDIO_RTP_PT,  # M=0, PT=96
        seq & 0xFFFF,
        timestamp & 0xFFFFFFFF,
        ssrc & 0xFFFFFFFF,
    )
    return header + payload


class ScreenAudioPacketizer:
    """Stateful RTP audio packetizer (seq + timestamp bookkeeping)."""

    def __init__(
        self,
        key: bytes,
        iv: bytes,
        ssrc: int = 0,
        spf: int = AUDIO_SAMPLES_PER_FRAME,
        base_ts: int = 0,
    ) -> None:
        """Packetize under *key*/*iv*, numbering from *base_ts* and seq 0."""
        self._key = key
        self._iv = iv
        self._ssrc = ssrc
        self._spf = spf
        self._seq = 0
        self._ts = base_ts & 0xFFFFFFFF

    def next_packet(self, aac_frame: bytes) -> bytes:
        """Encrypt one AAC-ELD frame and wrap it in the next RTP packet."""
        payload = encrypt_audio_frame(self._key, self._iv, aac_frame)
        pkt = build_audio_rtp_packet(self._seq, self._ts, payload, self._ssrc)
        self._seq = (self._seq + 1) & 0xFFFF
        self._ts = (self._ts + self._spf) & 0xFFFFFFFF
        return pkt

    @property
    def seq(self) -> int:
        """Return the sequence number the next packet will carry."""
        return self._seq

    @property
    def timestamp(self) -> int:
        """Return the RTP timestamp the next packet will carry."""
        return self._ts


def audio_setup_stream_params(stream_connection_id: int) -> dict:
    """Return the type-96 SETUP ``streams[0]`` dict for screen audio.

    Values RE'd from the reference sender's negotiation callback (@0x10008e1a4):
    AAC-ELD (audioFormat 0x1000000), ct=8, spf=480, latency 3750, 2x redundancy.
    The caller adds ``ekey``/``eiv`` and the top-level session fields.
    """
    return {
        "type": 96,
        "streamConnectionID": stream_connection_id,
        "latencyMin": 3750,
        "latencyMax": 3750,
        "redundantAudio": 2,
        "ct": 8,
        "spf": AUDIO_SAMPLES_PER_FRAME,
        "audioFormat": 0x1000000,
        "usingScreen": True,
    }


def build_audio_sync_packet(
    first: bool, timestamp: int, latency: int, ntp: int
) -> bytes:
    """Build one screen-audio timing SYNC packet (RAOP's wire format).

    *ntp* must come from the same clock as the ``TimingServer`` --
    ``raop_timing.ntp_now()``, seconds since 1900 in 32.32 fixed point. Pass
    a Unix-epoch time instead and the receiver correlates two epochs about
    2.2e9 seconds apart, re-syncing on every sync packet: roughly one audible
    glitch a second, with nothing failing anywhere else.

    *timestamp* is the packetizer's current RTP timestamp; the receiver is
    told ``timestamp - latency`` as "now without latency", wrapped to 32 bits.
    The extension bit is set on the first packet of a session only.
    """
    return SyncPacket.encode(
        0x80 | (0x10 if first else 0),  # proto (extension bit on first)
        0xD4,  # marker | PT 84
        0x0004,  # seqno (matches the reference sender)
        (timestamp - latency) & 0xFFFFFFFF,  # now_without_latency
        ntp >> 32,  # last_sync_sec
        ntp & 0xFFFFFFFF,  # last_sync_frac
        timestamp & 0xFFFFFFFF,  # now
    )
