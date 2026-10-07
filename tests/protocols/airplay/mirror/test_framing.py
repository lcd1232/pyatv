"""Tests for pyatv.protocols.airplay.mirror.framing."""

import hashlib
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import pytest

from pyatv.protocols.airplay.mirror import framing


def test_video_header_pack_unpack_round_trip():
    h = framing.MirrorHeader(
        payload_size=1500,
        payload_type=framing.PAYLOAD_TYPE_VIDEO,
        timestamp_ntp=0x1234567890ABCDEF,
        flags=0,
    )
    encoded = h.pack()
    assert len(encoded) == framing.HEADER_LEN
    decoded = framing.MirrorHeader.unpack(encoded)
    assert decoded == h


def test_audio_header_pack_unpack_round_trip():
    h = framing.MirrorHeader(
        payload_size=24,
        payload_type=framing.PAYLOAD_TYPE_AUDIO,
        timestamp_ntp=0xDEADBEEFCAFEBABE,
        flags=framing.FLAG_KEYFRAME,
    )
    encoded = h.pack()
    decoded = framing.MirrorHeader.unpack(encoded)
    assert decoded == h


def test_aes_ctr_encrypt_decrypt_round_trip():
    key = b"\x00" * 16
    iv = b"\x01" * 16
    plaintext = b"hello, world!" * 10
    cipher_a = framing.aes_ctr(key, iv)
    cipher_b = framing.aes_ctr(key, iv)
    encrypted = cipher_a.update(plaintext)
    decrypted = cipher_b.update(encrypted)
    assert decrypted == plaintext


def test_oversize_payload_size_rejected_at_pack():
    h = framing.MirrorHeader(
        payload_size=2**32,
        payload_type=framing.PAYLOAD_TYPE_VIDEO,
        timestamp_ntp=0,
        flags=0,
    )
    with pytest.raises(ValueError):
        h.pack()


def test_mirror_encryptor_continuous_keystream_across_payloads():
    """Two consecutive payloads should NOT decrypt with a fresh cipher.

    The reference sender uses one continuous keystream across all frames. The cipher
    state advances across boundaries, so a receiver decrypting frame N
    must NOT reset the counter back to IV for frame N+1.
    """
    key = b"\x00" * 16
    iv = b"\x01" * 16
    enc = framing.MirrorEncryptor.from_key_iv(key, iv)
    plaintext_a = b"frame-A-payload-of-length-32-byt"
    plaintext_b = b"frame-B-payload-of-length-32-byt"
    cipher_a = enc.encrypt(plaintext_a)
    cipher_b = enc.encrypt(plaintext_b)
    # If the keystream were reset per call, cipher_a and cipher_b would be
    # the same (same plaintext = same ciphertext). They must differ.
    assert cipher_a != cipher_b


def test_mirror_encryptor_decrypts_with_continuous_state():
    """Decryption with a matching encryptor (continuous state) round-trips."""
    key = b"\x00" * 16
    iv = b"\x01" * 16
    enc = framing.MirrorEncryptor.from_key_iv(key, iv)
    dec = framing.MirrorEncryptor.from_key_iv(key, iv)
    msgs = [b"hello-frame-1!" * 8, b"hello-frame-2!" * 5, b"x" * 100]
    encrypted = [enc.encrypt(m) for m in msgs]
    decrypted = [dec.encrypt(e) for e in encrypted]  # CTR is symmetric
    assert decrypted == msgs


def test_pack_mirror_frame_keeps_header_in_clear():
    """Mirror frame = MirrorHeader.pack() (cleartext) || encrypted payload."""
    key = b"\x00" * 16
    iv = b"\x01" * 16
    enc = framing.MirrorEncryptor.from_key_iv(key, iv)
    header = framing.MirrorHeader(
        payload_size=20,
        payload_type=framing.PAYLOAD_TYPE_VIDEO,
        timestamp_ntp=0xCAFEBABE,
        flags=0,
    )
    payload = b"hello-mirror-payload"
    frame = framing.pack_mirror_frame(enc, header, payload)
    assert frame[: framing.HEADER_LEN] == header.pack()
    assert frame[framing.HEADER_LEN :] != payload  # encrypted
    assert len(frame[framing.HEADER_LEN :]) == len(payload)


# ---------------------------------------------------------------------------
# 128-byte big-endian header + per-stream key derivation
#
# Reference: UxPlay lib/raop_rtp_mirror.c (header parsing) and
# lib/mirror_buffer.c (mirror_buffer_init_aes).
# ---------------------------------------------------------------------------


def test_header_is_128_bytes_little_endian():
    """UxPlay reads these with byteutils_get_int/_long, which are little-endian.

    The ``_be`` variants exist separately and are not used for these fields.
    """
    header = framing.MirrorHeader(
        payload_size=0x11223344,
        payload_type=framing.PACKET_TYPE_VIDEO,
        timestamp_ntp=0xAABBCCDDEEFF0011,
        flags=0,
    )
    packed = header.pack()
    assert len(packed) == 128
    assert packed[0:4] == b"\x44\x33\x22\x11"
    assert packed[8:16] == b"\x11\x00\xff\xee\xdd\xcc\xbb\xaa"
    # everything past the 16-byte prefix is metadata/padding
    assert packed[16:] == b"\x00" * 112


def test_packet_types_match_receiver_expectations():
    assert framing.PACKET_TYPE_VIDEO == 0x00
    assert framing.PACKET_TYPE_CODEC == 0x01
    # The RTSP stream type is a different namespace and must not be confused
    # with the per-packet payload type.
    assert framing.STREAM_TYPE_VIDEO == 110


def test_derive_stream_keys_is_deterministic_and_16_bytes():
    key, iv = framing.derive_stream_keys(b"\x11" * 16, 12345)
    again, again_iv = framing.derive_stream_keys(b"\x11" * 16, 12345)
    assert (key, iv) == (again, again_iv)
    assert len(key) == 16 and len(iv) == 16
    assert key != iv


def test_derive_stream_keys_treats_connection_id_as_unsigned():
    """A real sender's streamConnectionID is a signed int64, often negative.

    The receiver formats it with %llu, so the signed and unsigned spellings of
    the same 64-bit value must derive the same key.
    """
    negative = -3735921725222598274
    unsigned = negative & 0xFFFFFFFFFFFFFFFF
    assert framing.derive_stream_keys(
        b"\x22" * 16, negative
    ) == framing.derive_stream_keys(b"\x22" * 16, unsigned)


def test_derive_stream_keys_varies_with_connection_id():
    first, _ = framing.derive_stream_keys(b"\x33" * 16, 1)
    second, _ = framing.derive_stream_keys(b"\x33" * 16, 2)
    assert first != second


def test_start_fresh_block_advances_to_block_boundary():
    """Each packet restarts on an AES block boundary."""
    key, iv = b"\x01" * 16, b"\x02" * 16
    aligned = framing.MirrorEncryptor.from_key_iv(key, iv)
    aligned.encrypt(b"x" * 5)
    aligned.start_fresh_block()
    after_reset = aligned.encrypt(b"y" * 16)

    # A second encryptor that consumed exactly one whole block must produce
    # the same keystream position.
    reference = framing.MirrorEncryptor.from_key_iv(key, iv)
    reference.encrypt(b"z" * 16)
    assert after_reset == reference.encrypt(b"y" * 16)


def test_start_fresh_block_is_a_noop_when_already_aligned():
    key, iv = b"\x04" * 16, b"\x05" * 16
    enc = framing.MirrorEncryptor.from_key_iv(key, iv)
    enc.encrypt(b"a" * 32)
    enc.start_fresh_block()
    got = enc.encrypt(b"b" * 8)

    ref = framing.MirrorEncryptor.from_key_iv(key, iv)
    ref.encrypt(b"a" * 32)
    assert got == ref.encrypt(b"b" * 8)


def test_build_avcc_matches_receiver_parsing_offsets():
    """The receiver reads SPS length at 6 and PPS length at sps_size + 9.

    Reference: UxPlay raop_rtp_mirror.c ``byteutils_get_short_be(payload, 6)``
    and ``byteutils_get_short_be(payload, sps_size + 9)``.
    """
    import struct

    sps = bytes([0x67, 0x64, 0x00, 0x1F, 0xAC, 0xD9])
    pps = bytes([0x68, 0xEB, 0xE3, 0xCB])
    avcc = framing.build_avcc(sps, pps)

    assert avcc[0] == 1  # configurationVersion
    assert avcc[1:4] == sps[1:4]  # profile / compatibility / level
    sps_size = struct.unpack(">H", avcc[6:8])[0]
    assert sps_size == len(sps)
    assert avcc[8 : 8 + sps_size] == sps
    pps_size = struct.unpack(">H", avcc[sps_size + 9 : sps_size + 11])[0]
    assert pps_size == len(pps)
    assert avcc[sps_size + 11 : sps_size + 11 + pps_size] == pps


def test_build_avcc_rejects_short_sps():
    with pytest.raises(ValueError):
        framing.build_avcc(b"\x67", b"\x68\x00")


def test_codec_metadata_places_dimensions_where_receiver_reads_them():
    """Dimensions are little-endian floats at header offsets 16/20, 40/44, 48/52, 56/60."""
    import struct

    tail = framing.build_codec_metadata(1280, 720)
    assert len(tail) == framing.HEADER_LEN - framing.HEADER_PREFIX_LEN

    for offset_w, offset_h in ((16, 20), (40, 44), (48, 52), (56, 60)):
        got_w = struct.unpack_from("<f", tail, offset_w - framing.HEADER_PREFIX_LEN)[0]
        got_h = struct.unpack_from("<f", tail, offset_h - framing.HEADER_PREFIX_LEN)[0]
        assert (got_w, got_h) == (1280.0, 720.0)

    # Everything from header offset 64 on is zero.
    assert tail[64 - framing.HEADER_PREFIX_LEN :] == bytes(framing.HEADER_LEN - 64)


def test_codec_metadata_fits_in_a_header():
    header = framing.MirrorHeader(
        payload_size=0,
        payload_type=framing.PACKET_TYPE_CODEC,
        timestamp_ntp=0,
        flags=0,
        metadata=framing.build_codec_metadata(1920, 1080),
    )
    assert len(header.pack()) == framing.HEADER_LEN


# ---------------------------------------------------------------------------
# MirrorHeader: field guards and the pack/unpack round trip as a property.
# ---------------------------------------------------------------------------


def _header(**overrides):
    fields = dict(payload_size=0, payload_type=0, timestamp_ntp=0, flags=0)
    fields.update(overrides)
    return framing.MirrorHeader(**fields)


@pytest.mark.parametrize(
    "field,value",
    [
        ("payload_size", -1),
        ("payload_size", 2**32),
        ("payload_type", -1),
        ("payload_type", 2**16),
        ("flags", -1),
        ("flags", 2**16),
        ("timestamp_ntp", -1),
        ("timestamp_ntp", 2**64),
    ],
)
def test_pack_rejects_out_of_range_fields(field, value):
    """Every header field is range-checked before struct.pack sees it."""
    with pytest.raises(ValueError, match=f"{field} out of range"):
        _header(**{field: value}).pack()


@pytest.mark.parametrize(
    "field,value",
    [
        ("payload_size", 2**32 - 1),
        ("payload_type", 2**16 - 1),
        ("flags", 2**16 - 1),
        ("timestamp_ntp", 2**64 - 1),
    ],
)
def test_pack_accepts_the_field_maxima(field, value):
    """The guards are inclusive at the top of each field's range."""
    assert len(_header(**{field: value}).pack()) == framing.HEADER_LEN


def test_metadata_longer_than_the_tail_is_rejected():
    tail = framing.HEADER_LEN - framing.HEADER_PREFIX_LEN
    with pytest.raises(ValueError, match="metadata too long"):
        _header(metadata=bytes(tail + 1))


def test_short_metadata_is_zero_padded_to_the_tail():
    header = _header(metadata=b"\xaa\xbb")
    tail = framing.HEADER_LEN - framing.HEADER_PREFIX_LEN
    assert header.metadata == b"\xaa\xbb" + bytes(tail - 2)
    assert header.pack()[framing.HEADER_PREFIX_LEN :] == header.metadata


def test_unpack_accepts_a_bare_16_byte_prefix():
    """A 16-byte prefix is a legal input; metadata comes back zero-filled."""
    full = framing.MirrorHeader(
        payload_size=7,
        payload_type=framing.PACKET_TYPE_STATS,
        timestamp_ntp=0x0102030405060708,
        flags=framing.FLAG_KEYFRAME,
    )
    assert framing.MirrorHeader.unpack(full.pack()[:16]) == full


def test_pack_unpack_round_trips_over_the_whole_field_space():
    """Property: unpack(pack(h)) == h for arbitrary in-range field values."""
    import random

    rnd = random.Random(4242)
    tail = framing.HEADER_LEN - framing.HEADER_PREFIX_LEN
    for _ in range(200):
        header = framing.MirrorHeader(
            payload_size=rnd.randrange(2**32),
            payload_type=rnd.randrange(2**16),
            timestamp_ntp=rnd.randrange(2**64),
            flags=rnd.randrange(2**16),
            metadata=bytes(rnd.randrange(256) for _ in range(tail)),
        )
        packed = header.pack()
        assert len(packed) == framing.HEADER_LEN
        assert framing.MirrorHeader.unpack(packed) == header


# ---------------------------------------------------------------------------
# Block ciphers checked against NIST SP 800-38A's own vectors.
#
# The AES modes here have published test vectors, so they are proven against
# those rather than pinned to whatever the code returns today: a silently
# wrong mode or IV wiring is exactly the class of bug that negotiates fine and
# renders nothing.
# ---------------------------------------------------------------------------

# NIST SP 800-38A, Appendix F -- AES-128 key and the shared 4-block plaintext.
_NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_NIST_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
# F.2.1 CBC-AES128.Encrypt
_NIST_CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_NIST_CBC_CIPHERTEXT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)
# F.5.1 CTR-AES128.Encrypt
_NIST_CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
_NIST_CTR_CIPHERTEXT = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)


def test_aes_ctr_matches_nist_sp800_38a_f_5_1():
    """PROOF: AES-128-CTR with a 128-bit big-endian counter block."""
    assert (
        framing.aes_ctr(_NIST_KEY, _NIST_CTR_IV).update(_NIST_PLAINTEXT)
        == _NIST_CTR_CIPHERTEXT
    )


def test_mirror_encryptor_keystream_matches_nist_sp800_38a_f_5_1():
    """PROOF: the running keystream is plain AES-CTR across call boundaries."""
    enc = framing.MirrorEncryptor.from_key_iv(_NIST_KEY, _NIST_CTR_IV)
    out = b"".join(enc.encrypt(_NIST_PLAINTEXT[i : i + 16]) for i in range(0, 64, 16))
    assert out == _NIST_CTR_CIPHERTEXT
    assert enc.key == _NIST_KEY
    assert enc.iv == _NIST_CTR_IV


def test_aes_cbc_encrypt_matches_nist_sp800_38a_f_2_1():
    """PROOF: AES-128-CBC over a whole number of blocks."""
    assert (
        framing.aes_cbc_encrypt(_NIST_KEY, _NIST_CBC_IV, _NIST_PLAINTEXT)
        == _NIST_CBC_CIPHERTEXT
    )


def test_aes_cbc_encrypt_leaves_the_partial_trailing_block_in_the_clear():
    """AirPlay's CBC remainder handling: only ``len // 16 * 16`` is encrypted."""
    ragged = _NIST_PLAINTEXT + b"\xaa\xbb\xcc"
    out = framing.aes_cbc_encrypt(_NIST_KEY, _NIST_CBC_IV, ragged)
    assert len(out) == len(ragged)
    assert out[:64] == _NIST_CBC_CIPHERTEXT
    assert out[64:] == b"\xaa\xbb\xcc"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x01", id="one-byte"),
        pytest.param(b"\x01" * 15, id="fifteen-bytes"),
    ],
)
def test_aes_cbc_encrypt_passes_sub_block_data_straight_through(data):
    assert framing.aes_cbc_encrypt(_NIST_KEY, _NIST_CBC_IV, data) == data


def test_aes_cbc_applies_the_iv_fresh_on_every_call():
    """CBC keeps no cross-call state, so a whole access unit must be one call."""
    first = framing.aes_cbc_encrypt(_NIST_KEY, _NIST_CBC_IV, _NIST_PLAINTEXT[:16])
    second = framing.aes_cbc_encrypt(_NIST_KEY, _NIST_CBC_IV, _NIST_PLAINTEXT[16:32])
    assert first == _NIST_CBC_CIPHERTEXT[:16]
    # Chained (correct) output for block 2 differs from a fresh-IV encryption.
    assert second != _NIST_CBC_CIPHERTEXT[16:32]


@pytest.mark.parametrize(
    "fn,message",
    [
        (framing.aes_ctr, "AES-CTR key must be 16 bytes"),
        (
            lambda key, iv: framing.aes_cbc_encrypt(key, iv, b""),
            "AES-CBC key must be 16 bytes",
        ),
    ],
)
def test_ciphers_reject_a_wrong_length_key(fn, message):
    with pytest.raises(ValueError, match=message):
        fn(bytes(15), bytes(16))


@pytest.mark.parametrize(
    "fn,message",
    [
        (framing.aes_ctr, "AES-CTR IV must be 16 bytes"),
        (
            lambda key, iv: framing.aes_cbc_encrypt(key, iv, b""),
            "AES-CBC IV must be 16 bytes",
        ),
    ],
)
def test_ciphers_reject_a_wrong_length_iv(fn, message):
    with pytest.raises(ValueError, match=message):
        fn(bytes(16), bytes(17))


# ---------------------------------------------------------------------------
# encrypt_frame / encrypt_frame_cbc: header in the clear, payload encrypted.
# ---------------------------------------------------------------------------


def test_encrypt_frame_is_header_plus_aes_ctr_payload():
    header = _header(payload_size=64, payload_type=framing.PACKET_TYPE_VIDEO)
    frame = framing.encrypt_frame(_NIST_KEY, _NIST_CTR_IV, header, _NIST_PLAINTEXT)
    assert frame[: framing.HEADER_LEN] == header.pack()
    assert frame[framing.HEADER_LEN :] == _NIST_CTR_CIPHERTEXT


def test_encrypt_frame_cbc_is_header_plus_aes_cbc_payload():
    header = _header(payload_size=64, payload_type=framing.PACKET_TYPE_VIDEO)
    frame = framing.encrypt_frame_cbc(_NIST_KEY, _NIST_CBC_IV, header, _NIST_PLAINTEXT)
    assert frame[: framing.HEADER_LEN] == header.pack()
    assert frame[framing.HEADER_LEN :] == _NIST_CBC_CIPHERTEXT


@pytest.mark.parametrize(
    "fn,iv",
    [
        (framing.encrypt_frame, _NIST_CTR_IV),
        (framing.encrypt_frame_cbc, _NIST_CBC_IV),
    ],
    ids=["ctr", "cbc"],
)
def test_encrypt_frame_rejects_a_header_that_lies_about_the_size(fn, iv):
    """A header whose payload_size disagrees with the payload desyncs the receiver."""
    header = _header(payload_size=63, payload_type=framing.PACKET_TYPE_VIDEO)
    with pytest.raises(ValueError, match="!= len\\(payload\\)"):
        fn(_NIST_KEY, iv, header, _NIST_PLAINTEXT)


def test_pack_mirror_frame_rejects_a_header_that_lies_about_the_size():
    enc = framing.MirrorEncryptor.from_key_iv(_NIST_KEY, _NIST_CTR_IV)
    header = _header(payload_size=5, payload_type=framing.PACKET_TYPE_VIDEO)
    with pytest.raises(ValueError, match="!= len\\(payload\\)"):
        framing.pack_mirror_frame(enc, header, b"much longer than five")


# ---------------------------------------------------------------------------
# ChaChaVideoEncryptor.
#
# The AEAD itself is RFC 8439 (delegated to ``cryptography``); what is pinned
# here is Apple's nonce convention -- 4 zero bytes then an 8-byte
# little-endian per-frame counter -- which has no published definition.
# ---------------------------------------------------------------------------


def test_chacha_encryptor_rejects_a_wrong_length_key():
    with pytest.raises(ValueError, match="must be 32 bytes"):
        framing.ChaChaVideoEncryptor(bytes(16))


def test_chacha_encryptor_exposes_its_key():
    key = bytes(range(32))
    assert framing.ChaChaVideoEncryptor(key).key == key


def test_chacha_nonce_is_a_little_endian_counter_bumped_once_per_frame():
    """CHARACTERIZATION of the nonce layout, decrypted with the raw AEAD."""
    key = bytes(range(32))
    enc = framing.ChaChaVideoEncryptor(key)
    aead = ChaCha20Poly1305(key)
    for counter in range(3):
        frame = f"frame-{counter}".encode()
        out = enc.encrypt(frame)
        assert len(out) == len(frame) + 16  # ciphertext || Poly1305 tag
        nonce = bytes(4) + counter.to_bytes(8, "little")
        assert aead.decrypt(nonce, out, None) == frame
    assert enc._counter == 3


def test_chacha_uses_the_instance_aad_by_default():
    key = bytes(range(32))
    aad = framing.build_codec_metadata(1280, 720)
    enc = framing.ChaChaVideoEncryptor(key, aad=aad)
    out = enc.encrypt(b"payload")
    nonce = bytes(4) + (0).to_bytes(8, "little")
    assert ChaCha20Poly1305(key).decrypt(nonce, out, aad) == b"payload"


def test_chacha_per_call_aad_overrides_the_instance_default():
    """Apple authenticates the verbatim 128-byte frame header as the AAD."""
    key = bytes(range(32))
    enc = framing.ChaChaVideoEncryptor(key, aad=b"instance-default")
    header = _header(payload_size=7, payload_type=framing.PACKET_TYPE_VIDEO).pack()
    out = enc.encrypt(b"payload", aad=header)
    nonce = bytes(4) + (0).to_bytes(8, "little")
    assert ChaCha20Poly1305(key).decrypt(nonce, out, header) == b"payload"


def test_chacha_start_fresh_block_is_a_noop():
    """Duck-types :class:`MirrorEncryptor` without disturbing the counter."""
    enc = framing.ChaChaVideoEncryptor(bytes(range(32)))
    enc.encrypt(b"a")
    enc.start_fresh_block()
    assert enc._counter == 1


# ---------------------------------------------------------------------------
# Apple-specific key derivations: no published reference exists for these, so
# they are pinned rather than proven.
# ---------------------------------------------------------------------------


def test_derive_stream_keys_rejects_a_wrong_length_secret():
    with pytest.raises(ValueError, match="aes_key must be 16 bytes"):
        framing.derive_stream_keys(b"\x11" * 15, 1)


def test_derive_stream_keys_is_label_then_id_then_secret():
    """CHARACTERIZATION: SHA512(label + decimal(id) || secret)[:16], two digests."""
    secret = bytes(range(16))
    key, iv = framing.derive_stream_keys(secret, 12345)
    assert key == hashlib.sha512(b"AirPlayStreamKey12345" + secret).digest()[:16]
    assert iv == hashlib.sha512(b"AirPlayStreamIV12345" + secret).digest()[:16]


def test_derive_tcp_stream_key_iv_rejects_a_wrong_length_secret():
    with pytest.raises(ValueError, match="raw16 must be 16 bytes"):
        framing.derive_tcp_stream_key_iv(bytes(15), bytes(32), 1)


def test_derive_tcp_stream_key_iv_folds_raw16_with_the_pair_secret():
    """Characterize the reference sender's ``DeriveKeyAndIV`` (flag=True path)."""
    raw16, pair32 = bytes(range(16)), bytes(range(32, 64))
    secret16 = hashlib.sha512(raw16 + pair32).digest()[:16]
    key, iv = framing.derive_tcp_stream_key_iv(raw16, pair32, 527657112)
    assert key == hashlib.sha512(b"AirPlayStreamKey527657112" + secret16).digest()[:16]
    assert iv == hashlib.sha512(b"AirPlayStreamIV527657112" + secret16).digest()[:16]
    # With the fold disabled, raw16 is the secret and the result is
    # derive_stream_keys' output for the same id.
    assert framing.derive_tcp_stream_key_iv(
        raw16, pair32, 527657112, flag=False
    ) == framing.derive_stream_keys(raw16, 527657112)


def test_derive_tcp_stream_key_iv_treats_the_connection_id_as_unsigned():
    negative = -3735921725222598274
    raw16, pair32 = bytes(range(16)), bytes(range(32))
    assert framing.derive_tcp_stream_key_iv(
        raw16, pair32, negative
    ) == framing.derive_tcp_stream_key_iv(raw16, pair32, negative & 0xFFFFFFFFFFFFFFFF)


def test_constants_defined_in_two_modules_still_agree():
    """Three values are written out in two modules each.

    Each pair is one protocol fact with two definitions, so nothing makes
    them move together:

    * the 128-byte media-data header -- `framing.HEADER_LEN` and
      `tcp_stream._HEADER_LEN`;
    * the 90 kHz video clock -- `rtp.CLOCK_RATE`, which stamps the RTP
      timestamp, and `pacer.VIDEO_CLOCK_HZ`, which decides when a frame is
      due.  These two diverging is the worst of the three: frames would go
      out carrying timestamps that disagree with the rate they are paced
      at, and the receiver would drift rather than fail;
    * the HTTP `User-Agent` both handshakes send.

    Consolidating them is a production change.  This asserts they have not
    drifted meanwhile, and fails whichever side moves.

    `framing.STREAM_TYPE_AUDIO` (96) and `screen_audio.AUDIO_RTP_PT`
    (0x60) are deliberately NOT compared: they collide in value and are
    different things -- a stream identifier and an RTP payload-type byte
    with the marker bit clear -- which `framing.py` already says in a
    comment above its own definition.
    """
    from pyatv.protocols.airplay.mirror import (  # noqa: PLC0415
        fairplay,
        fply,
        pacer,
        rtp,
        tcp_stream,
    )

    assert framing.HEADER_LEN == tcp_stream._HEADER_LEN  # noqa: SLF001
    assert rtp.CLOCK_RATE == pacer.VIDEO_CLOCK_HZ
    assert fairplay.USER_AGENT == fply.USER_AGENT


def test_the_stream_key_labels_are_pinned_and_spelled_once():
    """``AirPlayStreamKey``/``AirPlayStreamIV`` are domain separators.

    ``session.py``'s ``MIRROR_KEYBUF_WINDOW`` sweep used to spell both labels
    inline, a second copy of the derivation in ``framing``.  A drift between
    the two would derive keys no receiver agrees with, and would do it
    silently -- the sweep is env-gated, so nothing runs it in CI.

    The sweep now calls ``stream_key_iv_from_secret``, which exists because
    the sweep's secret is a slice of the SAP context and need not be 16
    bytes, so it cannot go through ``derive_tcp_stream_key_iv`` and its
    length check.  These vectors pin the labels themselves: changing either
    string, or the digest, or the truncation, changes them.
    """
    key, iv = framing.stream_key_iv_from_secret(bytes(range(20)), 0x1122334455667788)
    assert key.hex() == "07b8707d3c121b4cc3d03a73bde5b405"
    assert iv.hex() == "8dc4657ba5d2417feca55728cfe6f322"

    # The public entry point is the same derivation with secret16 computed
    # for it, so flag=False must agree with calling the tail directly.
    raw16 = bytes(range(16))
    assert framing.derive_tcp_stream_key_iv(
        raw16, bytes(range(32)), 99, flag=False
    ) == framing.stream_key_iv_from_secret(raw16, 99)

    # ...and its flag=True path stays pinned too.
    key2, iv2 = framing.derive_tcp_stream_key_iv(raw16, bytes(range(32)), 7)
    assert key2.hex() == "b4a9f2f205a64fff1400b863cbd3033c"
    assert iv2.hex() == "47d4794311465256f9b332516b8126a5"


def test_stream_key_iv_accepts_the_odd_sized_windows_the_sweep_produces():
    """The sweep slices arbitrary windows out of the SAP context.

    ``derive_tcp_stream_key_iv`` rejects anything but 16 bytes, which
    is why the sweep cannot use it; this one must accept whatever length the
    window has, and give a distinct key per length.
    """
    keys = set()
    for size in (1, 7, 14, 16, 20, 36, 64):
        key, iv = framing.stream_key_iv_from_secret(bytes(size), 1)
        assert len(key) == 16 and len(iv) == 16
        keys.add(key)
    assert len(keys) == 7, "different window sizes collapsed to the same key"

    with pytest.raises(ValueError, match="raw16 must be 16 bytes"):
        framing.derive_tcp_stream_key_iv(bytes(20), bytes(32), 1)


def test_one_video_frame_costs_a_fraction_of_its_frame_budget():
    """Not a benchmark -- a guard on the per-frame streaming path.

    Every frame is length-prefixed into avcC, AES-CTR encrypted against the
    continuous keystream, and given a 128-byte data header.  Measured, that
    is around 10us for a 58 KB frame against the 16.7ms a 60 fps frame gets:
    four orders of magnitude of headroom, which is why ``session.py`` can
    pace off wall-clock time and treat the encrypt cost as free.

    The threshold is deliberately loose -- 1ms, still sixteen times inside
    the budget and a hundred times the measured cost -- so a slow or noisy
    runner cannot fail it.  What it catches is someone reintroducing
    per-frame work of a different order: deriving a key per frame, hashing
    the payload, or re-reading a file.
    """
    import os
    import time

    from pyatv.protocols.airplay.mirror import tcp_stream

    nalus = [bytes([0x65]) + os.urandom(58 * 1024), bytes([0x06]) + os.urandom(200)]
    encryptor = framing.MirrorEncryptor.from_key_iv(bytes(16), bytes(16))
    geometry = bytes(24)

    def one_frame(index: int) -> bytes:
        avcc = tcp_stream.to_avcc(nalus)
        ciphertext = encryptor.encrypt(avcc)
        header = tcp_stream.build_data_header(
            len(ciphertext), index * 16_666_667, geometry
        )
        return header + ciphertext

    one_frame(0)  # warm imports and the cipher

    frames = 100
    start = time.monotonic()
    for index in range(frames):
        one_frame(index)
    per_frame = (time.monotonic() - start) / frames

    assert per_frame < 1e-3, (
        f"{per_frame * 1e6:.0f}us per frame; a 60 fps frame budget is 16667us "
        "and this path used to take about 10us"
    )


def test_an_sps_too_short_to_carry_a_profile_is_refused():
    """Four bytes is the exact minimum, and three fails silently without it.

    ``build_avcc`` copies ``sps[1:4]`` into the record as profile,
    compatibility and level. Python slices short rather than raising, so a
    three-byte SPS produces a two-byte field and an avcC that is one byte
    shorter than every offset after it assumes -- the receiver then reads
    the SPS length from the wrong place. Nothing raises and nothing renders.

    ``test_build_avcc_matches_receiver_parsing_offsets`` builds a valid
    record and checks those offsets, so the guard was covered from above.
    Lowering it to three changed nothing that failed.
    """
    with pytest.raises(ValueError, match="SPS too short"):
        framing.build_avcc(b"\x67\x42\x00", b"\x68\xce")

    ok = framing.build_avcc(b"\x67\x42\x00\x1f", b"\x68\xce")
    assert ok[1:4] == b"\x42\x00\x1f", "the profile triple must survive intact"


def test_the_datastream_salt_spells_the_stream_id_unsigned():
    """``%llu``, which is what the mask in front of it is for.

    The receiver formats ``streamConnectionID`` as an unsigned 64-bit value.
    Python has no such thing, so a negative id has to be masked back into
    range before it is spelled -- ``str(-1)`` is ``"-1"`` where the receiver
    wrote ``"18446744073709551615"``, and the two derive different keys
    from the same session.

    Every id the suite generates is already positive, so dropping the mask
    changes nothing anywhere else.
    """
    verifier = MagicMock()
    verifier.encryption_keys.return_value = (b"\x11" * 32, b"\x22" * 32)

    framing.derive_datastream_video_key(verifier, -1)

    salt = verifier.encryption_keys.call_args.args[0]
    assert salt == "DataStream-Salt18446744073709551615", salt
