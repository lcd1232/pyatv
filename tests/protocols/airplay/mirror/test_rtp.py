"""RTP packetization tests, pinned to a captured real macOS sender.

Ground truth: docs/superpowers/specs/airplay_capture/proxy_captures/, recorded
through atvproxy's media relay. 7044 frames were analysed; the invariants
asserted here held without exception.
"""

import struct

import pytest

from pyatv.protocols.airplay.mirror import rtp

# First datagram of the captured session, verbatim (first 20 bytes).
CAPTURED_HEADER = bytes.fromhex("90e4c4bd00000000e7e9f72990110001000107 02")


def test_header_matches_the_captured_sender_layout():
    packets = rtp.RtpPacketizer(ssrc=0xE7E9F729).packetize(b"payload", 0)
    header = packets[0][:20]

    assert header[0] == 0x90  # version 2, extension present
    assert header[1] == 0x80 | rtp.PAYLOAD_TYPE_MIRROR  # marker on a lone packet
    assert struct.unpack(">I", header[4:8])[0] == 0  # timestamp
    assert struct.unpack(">I", header[8:12])[0] == 0xE7E9F729  # ssrc
    assert struct.unpack(">H", header[12:14])[0] == rtp.EXTENSION_ID
    assert struct.unpack(">H", header[14:16])[0] == 1  # one 32-bit ext word
    assert header[16] == 0x00
    assert header[17] == 1  # fragment count


def test_captured_header_parses_as_expected():
    """The layout we implement decodes a real captured packet."""
    parsed = rtp.parse_header(CAPTURED_HEADER + b"\x00" * 8)
    assert parsed["version"] == 2
    assert parsed["extension"] is True
    assert parsed["marker"] is True
    assert parsed["payload_type"] == 100
    assert parsed["ssrc"] == 0xE7E9F729
    assert parsed["extension_id"] == rtp.EXTENSION_ID
    assert parsed["fragment_count"] == 1


def test_marker_is_set_only_on_the_last_fragment():
    packets = rtp.RtpPacketizer().packetize(b"x" * 5000, 1234)
    assert len(packets) > 1
    markers = [rtp.parse_header(p)["marker"] for p in packets]
    assert markers[-1] is True
    assert not any(markers[:-1])


def test_fragments_share_timestamp_and_fragment_count():
    packets = rtp.RtpPacketizer().packetize(b"y" * 4000, 90000)
    parsed = [rtp.parse_header(p) for p in packets]
    assert {p["timestamp"] for p in parsed} == {90000}
    assert {p["fragment_count"] for p in parsed} == {len(packets)}
    assert {p["ssrc"] for p in parsed} == {parsed[0]["ssrc"]}


def test_sequence_numbers_are_consecutive_and_wrap():
    packetizer = rtp.RtpPacketizer()
    packetizer._sequence = 0xFFFE  # force a wrap mid-frame
    packets = packetizer.packetize(b"z" * (rtp.MAX_PAYLOAD * 3), 0)
    seqs = [rtp.parse_header(p)["sequence"] for p in packets]
    assert seqs == [0xFFFE, 0xFFFF, 0x0000]


def test_frame_counter_advances_per_frame_not_per_packet():
    packetizer = rtp.RtpPacketizer()
    first = packetizer.packetize(b"a" * 3000, 0)
    second = packetizer.packetize(b"b" * 10, 3000)
    assert {rtp.parse_header(p)["frame_counter"] for p in first} == {0}
    assert {rtp.parse_header(p)["frame_counter"] for p in second} == {1}


def test_payload_reassembles_in_sequence_order():
    payload = bytes(range(256)) * 20
    packets = rtp.RtpPacketizer().packetize(payload, 0)
    rejoined = b"".join(rtp.parse_header(p)["payload"] for p in packets)
    assert rejoined == payload


def test_no_fragment_exceeds_the_datagram_budget():
    packets = rtp.RtpPacketizer().packetize(b"q" * 20000, 0)
    assert all(len(p) <= 20 + rtp.MAX_PAYLOAD for p in packets)


def test_empty_payload_still_emits_one_packet():
    packets = rtp.RtpPacketizer().packetize(b"", 0)
    assert len(packets) == 1
    assert rtp.parse_header(packets[0])["fragment_count"] == 1


def test_rejects_a_frame_needing_too_many_fragments():
    packetizer = rtp.RtpPacketizer(max_payload=1)
    with pytest.raises(ValueError, match="fragment-count"):
        packetizer.packetize(b"x" * 300, 0)


def test_timestamp_clock_is_90khz():
    """A one-second gap in the capture showed a delta of exactly 90000."""
    assert rtp.CLOCK_RATE == 90_000


def test_packetizer_rejects_non_positive_max_payload():
    """max_payload divides the frame; zero would loop forever building chunks."""
    with pytest.raises(ValueError, match="max_payload must be positive, got 0"):
        rtp.RtpPacketizer(max_payload=0)


def test_parse_header_rejects_a_runt_packet():
    """A datagram shorter than the fixed header cannot be unpacked."""
    with pytest.raises(ValueError, match="packet too short: 8 bytes"):
        rtp.parse_header(b"\x90\xe4" + bytes(6))


def test_packetize_encrypts_each_fragment_with_its_sequence_number():
    """With an encryptor the *plaintext* is split, then each part encrypted.

    The SRTP IV is per-packet and keyed by that packet's RTP sequence number,
    so the encryptor must see the sequence the header actually carries.
    """

    class _RecordingEncryptor:
        def __init__(self):
            self.calls = []

        def encrypt(self, sequence, chunk):
            self.calls.append((sequence, chunk))
            return b"\xff" * len(chunk)

    encryptor = _RecordingEncryptor()
    packetizer = rtp.RtpPacketizer(ssrc=0x11223344, max_payload=4)
    packets = packetizer.packetize(b"ABCDEFGH", timestamp=90000, encryptor=encryptor)

    assert len(packets) == 2
    assert [chunk for _seq, chunk in encryptor.calls] == [b"ABCD", b"EFGH"]
    # Each call's sequence must match the sequence in that packet's header.
    for (seq, _chunk), packet in zip(encryptor.calls, packets):
        assert rtp.parse_header(packet)["sequence"] == seq
    # And the ciphertext, not the plaintext, is what goes on the wire.
    for packet in packets:
        assert packet[20:] == b"\xff" * 4


def test_extension_flag_reads_its_own_bit_not_the_whole_byte():
    """X is bit 4 of byte 0, read in isolation from the bits above it.

    Every packet this module *builds* carries byte0 == 0x90, where X is set,
    so no assertion on our own output can tell a masked read of that bit from
    one that merely notices the byte is non-zero. Only a header with the high
    version bits set *while* X is clear separates the two: 0x80 is a
    version-2 packet with no extension, exactly what a non-mirror RTP sender
    on the same port would emit.
    """
    parsed = rtp.parse_header(bytes([0x80, 0xE4]) + bytes(18))

    assert parsed["version"] == 2  # the bits above X really are set
    assert parsed["extension"] is False


def test_255_fragments_is_allowed_and_256_is_refused():
    """The exact edge of the fragment-count byte, from both sides.

    The count goes on the wire as ``bytes([0x00, len(chunks)])``, so 255 is
    the largest expressible and 256 would make ``bytes()`` raise something
    unhelpful about an integer being out of range. The guard exists to say
    what actually went wrong first, which means it has to fire at 256 and
    not at 255 -- and 255 fragments is a real frame, not a contrived one:
    at the default payload size that is a keyframe of a few hundred KB.

    Written ``>=`` the guard reads the same and rejects a frame the format
    can carry. Nothing else in the suite reaches this many fragments, so
    that change went unnoticed.
    """
    packer = rtp.RtpPacketizer(ssrc=1, max_payload=1)

    packets = packer.packetize(b"\x01" * 255, timestamp=0)
    assert len(packets) == 255
    assert packets[0][17] == 255, "the count byte should carry 255"

    with pytest.raises(ValueError, match="fragment-count byte"):
        packer.packetize(b"\x01" * 256, timestamp=0)


def test_a_packet_one_byte_short_of_a_header_is_refused_cleanly():
    """19 bytes must be a ValueError, not a struct.error from inside.

    ``parse_header`` reads ``packet[18:20]`` for the frame counter, so a
    19-byte packet gives ``struct.unpack`` a one-byte buffer and it raises
    something about needing two. The length guard is there to say what is
    actually wrong before that happens, which makes 20 the exact number:
    anything lower and the guard stops covering the last field it protects.

    A 20-byte packet is already parsed elsewhere in this file, so the edge
    was covered from above and not from below -- lowering the guard to 19
    changed nothing that failed.
    """
    with pytest.raises(ValueError, match="too short"):
        rtp.parse_header(bytes(19))

    parsed = rtp.parse_header(bytes(20))
    assert parsed["payload"] == b"", "a bare header has no payload"
    assert parsed["frame_counter"] == 0
