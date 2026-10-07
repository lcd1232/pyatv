"""Round-trip our sender output through a receiver-shaped parser.

This mimics what UxPlay's ``raop_rtp_mirror_thread`` does with the bytes we
put on the wire: read the 128-byte little-endian header, take ``payload_size``
bytes, then either parse an avcC record (packet type 1) or decrypt an H.264
NAL with the per-stream key (packet type 0).

It proves the pieces agree with each other -- header layout, key derivation,
per-packet block alignment and avcC packing -- without needing a device.
"""

import struct

from pyatv.protocols.airplay.mirror import framing

FAIRPLAY_KEY = bytes(range(16))
STREAM_CONNECTION_ID = -3735921725222598274  # a real sender's (negative) value


class _Receiver:
    """The receiver half: derives keys the same way and parses the stream."""

    def __init__(self, aes_key: bytes, stream_connection_id: int) -> None:
        key, iv = framing.derive_stream_keys(aes_key, stream_connection_id)
        self.decryptor = framing.MirrorEncryptor.from_key_iv(key, iv)
        self.nals: list = []
        self.codec: list = []

    def feed(self, packet: bytes) -> None:
        header = framing.MirrorHeader.unpack(packet)
        payload = packet[framing.HEADER_LEN : framing.HEADER_LEN + header.payload_size]
        assert len(payload) == header.payload_size

        if header.payload_type == framing.PACKET_TYPE_CODEC:
            sps_size = struct.unpack(">H", payload[6:8])[0]
            sps = payload[8 : 8 + sps_size]
            pps_size = struct.unpack(">H", payload[sps_size + 9 : sps_size + 11])[0]
            pps = payload[sps_size + 11 : sps_size + 11 + pps_size]
            self.codec.append((sps, pps))
            width = struct.unpack_from("<f", header.metadata, 56 - 16)[0]
            height = struct.unpack_from("<f", header.metadata, 60 - 16)[0]
            self.dimensions = (int(width), int(height))
        else:
            # AES-CTR is symmetric; the receiver restarts each packet on a
            # block boundary exactly as the sender does.
            self.nals.append(self.decryptor.encrypt(payload))
            self.decryptor.start_fresh_block()


def _sender_packets(nals, sps, pps, width=1280, height=720):
    """Produce the same packets MirrorSession's video producer would."""
    key, iv = framing.derive_stream_keys(FAIRPLAY_KEY, STREAM_CONNECTION_ID)
    encryptor = framing.MirrorEncryptor.from_key_iv(key, iv)

    avcc = framing.build_avcc(sps, pps)
    codec_header = framing.MirrorHeader(
        payload_size=len(avcc),
        payload_type=framing.PACKET_TYPE_CODEC,
        timestamp_ntp=0,
        flags=0,
        metadata=framing.build_codec_metadata(width, height),
    )
    yield codec_header.pack() + avcc

    for index, nal in enumerate(nals):
        header = framing.MirrorHeader(
            payload_size=len(nal),
            payload_type=framing.PACKET_TYPE_VIDEO,
            timestamp_ntp=index * 3000,
            flags=0,
        )
        packet = framing.pack_mirror_frame(encryptor, header, nal)
        encryptor.start_fresh_block()
        yield packet


def test_receiver_recovers_codec_config_and_dimensions():
    sps = bytes([0x67, 0x64, 0x00, 0x1F, 0xAC, 0xD9, 0x41])
    pps = bytes([0x68, 0xEB, 0xE3, 0xCB])
    receiver = _Receiver(FAIRPLAY_KEY, STREAM_CONNECTION_ID)

    for packet in _sender_packets([], sps, pps, 1920, 1080):
        receiver.feed(packet)

    assert receiver.codec == [(sps, pps)]
    assert receiver.dimensions == (1920, 1080)


def test_receiver_decrypts_every_nal_including_unaligned_lengths():
    """Payload lengths that are not multiples of 16 must not desynchronise."""
    sps = bytes([0x67, 0x64, 0x00, 0x1F])
    pps = bytes([0x68, 0xEB])
    # Deliberately mix lengths across and around the 16-byte block size.
    nals = [
        bytes([0x65]) + bytes([i % 251]) * n
        for i, n in enumerate([1, 15, 16, 17, 33, 100])
    ]

    receiver = _Receiver(FAIRPLAY_KEY, STREAM_CONNECTION_ID)
    for packet in _sender_packets(nals, sps, pps):
        receiver.feed(packet)

    assert receiver.nals == nals


def test_receiver_derives_the_same_keys_from_the_unsigned_id():
    """The receiver formats the ID with %llu; sender and receiver must agree."""
    unsigned = STREAM_CONNECTION_ID & 0xFFFFFFFFFFFFFFFF
    sps, pps = bytes([0x67, 0x64, 0x00, 0x1F]), bytes([0x68, 0xEB])
    nals = [bytes([0x65, 0xAA, 0xBB])]

    receiver = _Receiver(FAIRPLAY_KEY, unsigned)  # unsigned spelling
    for packet in _sender_packets(nals, sps, pps):  # sender used the signed one
        receiver.feed(packet)

    assert receiver.nals == nals


def test_wrong_stream_connection_id_fails_to_decrypt():
    """Sanity check that the key derivation is actually load-bearing."""
    sps, pps = bytes([0x67, 0x64, 0x00, 0x1F]), bytes([0x68, 0xEB])
    nals = [bytes([0x65, 0x11, 0x22, 0x33])]

    receiver = _Receiver(FAIRPLAY_KEY, STREAM_CONNECTION_ID + 1)
    for packet in _sender_packets(nals, sps, pps):
        receiver.feed(packet)

    assert receiver.nals != nals


def test_payload_size_in_header_matches_the_bytes_that_follow():
    sps, pps = bytes([0x67, 0x64, 0x00, 0x1F]), bytes([0x68, 0xEB])
    for packet in _sender_packets([b"\x65" * 37], sps, pps):
        header = framing.MirrorHeader.unpack(packet)
        assert len(packet) == framing.HEADER_LEN + header.payload_size
