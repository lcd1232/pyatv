"""Tests for the AirParrot screen-audio packetization (RTP + AES-CBC)."""

import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from pyatv.protocols.airplay.mirror import airparrot_audio as a
from pyatv.protocols.raop import timing


def test_rtp_header_layout():
    pkt = a.build_audio_rtp_packet(0x1234, 0xAABBCCDD, b"payload", ssrc=0)
    assert pkt[0] == 0x80
    assert pkt[1] == 0x60  # marker=0, PT=96
    ver, ptb, seq, ts, ssrc = struct.unpack(">BBHII", pkt[:12])
    assert seq == 0x1234
    assert ts == 0xAABBCCDD
    assert ssrc == 0
    assert pkt[12:] == b"payload"


def test_cbc_whole_blocks_only_remainder_clear():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    frame = bytes(range(37))  # 37 = 2*16 + 5 -> 5 trailing clear bytes
    out = a.encrypt_audio_frame(key, iv, frame)
    assert len(out) == 37
    # trailing 5 bytes are cleartext
    assert out[32:] == frame[32:]
    # first 32 bytes decrypt back to the original whole blocks
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    assert dec.update(out[:32]) + dec.finalize() == frame[:32]


def test_cbc_short_frame_all_clear():
    key = bytes(16)
    iv = bytes(16)
    frame = b"\x01\x02\x03"  # < 16 bytes -> entirely clear
    assert a.encrypt_audio_frame(key, iv, frame) == frame


def test_packetizer_seq_and_timestamp_advance():
    key = bytes(16)
    iv = bytes(16)
    p = a.AirParrotAudioPacketizer(key, iv, ssrc=0x11223344)
    p1 = p.next_packet(b"\x00" * 20)
    p2 = p.next_packet(b"\x00" * 20)
    s1, t1 = struct.unpack(">HI", p1[2:8])
    s2, t2 = struct.unpack(">HI", p2[2:8])
    assert s2 == s1 + 1
    assert t2 == t1 + a.AUDIO_SAMPLES_PER_FRAME  # +480 per packet
    assert struct.unpack(">I", p1[8:12])[0] == 0x11223344


def test_setup_params_match_airparrot():
    params = a.audio_setup_stream_params(0xDEADBEEF)
    assert params["type"] == 96
    assert params["audioFormat"] == 0x1000000  # AAC-ELD
    assert params["ct"] == 8
    assert params["spf"] == 480
    assert params["redundantAudio"] == 2
    assert params["streamConnectionID"] == 0xDEADBEEF


def test_encrypt_rejects_a_wrong_length_key():
    """AES-128 needs exactly 16 bytes; the error must name the size given."""
    with pytest.raises(ValueError, match="audio key must be 16 bytes, got 8"):
        a.encrypt_audio_frame(b"\x00" * 8, b"\x01" * 16, b"frame")


def test_encrypt_rejects_a_wrong_length_iv():
    """The eiv is a 16-byte CBC IV; the error must say so and name the size."""
    with pytest.raises(ValueError, match=r"audio iv \(eiv\) must be 16 bytes, got 4"):
        a.encrypt_audio_frame(b"\x00" * 16, b"\x01" * 4, b"frame")


def test_packetizer_exposes_the_next_sequence_number():
    """``seq`` reports the sequence the *next* packet will carry."""
    packetizer = a.AirParrotAudioPacketizer(b"\x00" * 16, b"\x01" * 16)

    assert packetizer.seq == 0
    packetizer.next_packet(bytes(32))
    assert packetizer.seq == 1
    # And it agrees with what the packet on the wire actually said.
    packet = packetizer.next_packet(bytes(32))
    assert struct.unpack_from(">H", packet, 2)[0] == 1
    assert packetizer.seq == 2


def test_sync_packet_layout():
    """Field placement, and the extension bit that marks the first packet."""
    pkt = a.build_audio_sync_packet(True, timestamp=0x11223344, latency=0x100, ntp=0)
    proto, ptb, seq, nowl, secs, frac, now = struct.unpack(">BBHIIII", pkt[:20])
    assert proto == 0x90, "extension bit not set on the first sync"
    assert ptb == 0xD4  # marker | PT 84
    assert seq == 0x0004
    assert now == 0x11223344
    assert nowl == 0x11223344 - 0x100

    later = a.build_audio_sync_packet(False, timestamp=1, latency=0, ntp=0)
    assert later[0] == 0x80, "extension bit set on a packet that is not the first"


def test_sync_packet_now_without_latency_wraps_at_32_bits():
    """``timestamp - latency`` is a 32-bit RTP clock and may go negative.

    Nothing clamps the subtraction, so a session whose latency exceeds the
    timestamp -- every session, for the first ~50 ms at 44.1 kHz -- relies on
    the wrap being taken mod 2**32 rather than packing a negative int.
    """
    pkt = a.build_audio_sync_packet(False, timestamp=0, latency=2205, ntp=0)
    (nowl,) = struct.unpack(">I", pkt[4:8])
    assert nowl == (0 - 2205) & 0xFFFFFFFF == 0xFFFFF763


def test_sync_packet_carries_the_ntp_epoch_not_the_unix_one():
    """The sync clock must be the TimingServer's, seconds since 1900.

    This is the bug the code comment describes: feed the builder a Unix-epoch
    time and the receiver correlates two epochs about 2.2e9 seconds apart,
    re-syncing on every sync packet -- roughly one audible glitch a second,
    with every test still green.  Only a check on the *epoch* catches it,
    because both values are plausible 32-bit seconds counts.
    """
    ntp = timing.ntp_now()
    pkt = a.build_audio_sync_packet(False, timestamp=0, latency=0, ntp=ntp)
    secs, frac = struct.unpack(">II", pkt[8:16])
    assert (secs, frac) == (ntp >> 32, ntp & 0xFFFFFFFF)

    # 1900 and 1970 are 2_208_988_800 seconds apart; the packet must sit in
    # the older epoch, so a Unix timestamp would be far too small.
    assert (
        secs - int(time.time()) > 2_000_000_000
    ), "sync packet carries a Unix-epoch time, not the TimingServer's NTP one"
