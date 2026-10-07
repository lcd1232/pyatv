"""Tests for pyatv.protocols.airplay.mirror.framing."""

import hashlib

import pytest

from pyatv.protocols.airplay.mirror import framing


def test_aes_ctr_encrypt_decrypt_round_trip():
    key = b"\x00" * 16
    iv = b"\x01" * 16
    plaintext = b"hello, world!" * 10
    cipher_a = framing.aes_ctr(key, iv)
    cipher_b = framing.aes_ctr(key, iv)
    encrypted = cipher_a.update(plaintext)
    decrypted = cipher_b.update(encrypted)
    assert decrypted == plaintext


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


# ---------------------------------------------------------------------------
# Block ciphers checked against NIST SP 800-38A's own vectors.
#
# The AES mode here has published test vectors, so they are proven against
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


def test_ciphers_reject_a_wrong_length_key():
    with pytest.raises(ValueError, match="AES-CTR key must be 16 bytes"):
        framing.aes_ctr(bytes(15), bytes(16))


def test_ciphers_reject_a_wrong_length_iv():
    with pytest.raises(ValueError, match="AES-CTR IV must be 16 bytes"):
        framing.aes_ctr(bytes(16), bytes(17))


# ---------------------------------------------------------------------------
# Apple-specific key derivations: no published reference exists for these, so
# they are pinned rather than proven.
# ---------------------------------------------------------------------------


def test_derive_tcp_stream_key_iv_rejects_a_wrong_length_secret():
    with pytest.raises(ValueError, match="raw16 must be 16 bytes"):
        framing.derive_tcp_stream_key_iv(bytes(15), bytes(32), 1)


def test_derive_tcp_stream_key_iv_folds_raw16_with_the_pair_secret():
    """Characterize the reference sender's ``DeriveKeyAndIV``."""
    raw16, pair32 = bytes(range(16)), bytes(range(32, 64))
    secret16 = hashlib.sha512(raw16 + pair32).digest()[:16]
    key, iv = framing.derive_tcp_stream_key_iv(raw16, pair32, 527657112)
    assert key == hashlib.sha512(b"AirPlayStreamKey527657112" + secret16).digest()[:16]
    assert iv == hashlib.sha512(b"AirPlayStreamIV527657112" + secret16).digest()[:16]


def test_derive_tcp_stream_key_iv_treats_the_connection_id_as_unsigned():
    negative = -3735921725222598274
    raw16, pair32 = bytes(range(16)), bytes(range(32))
    assert framing.derive_tcp_stream_key_iv(
        raw16, pair32, negative
    ) == framing.derive_tcp_stream_key_iv(raw16, pair32, negative & 0xFFFFFFFFFFFFFFFF)


def test_constants_defined_in_two_modules_still_agree():
    """The HTTP `User-Agent` both handshakes send is written out twice.

    It is one protocol fact with two definitions, so nothing makes them move
    together.  Consolidating them is a production change.  This asserts they
    have not drifted meanwhile, and fails whichever side moves.
    """
    from pyatv.protocols.airplay.mirror import fairplay, fply  # noqa: PLC0415

    assert fairplay.USER_AGENT == fply.USER_AGENT


def test_the_stream_key_labels_are_pinned_and_spelled_once():
    """``AirPlayStreamKey``/``AirPlayStreamIV`` are domain separators.

    A drift in either would derive keys no receiver agrees with, and would do
    it silently.  These vectors pin the labels themselves: changing either
    string, or the digest, or the truncation, changes them.
    """
    key, iv = framing.stream_key_iv_from_secret(bytes(range(20)), 0x1122334455667788)
    assert key.hex() == "07b8707d3c121b4cc3d03a73bde5b405"
    assert iv.hex() == "8dc4657ba5d2417feca55728cfe6f322"

    # The public entry point is the same derivation with secret16 computed
    # for it, and stays pinned too.
    raw16 = bytes(range(16))
    assert framing.derive_tcp_stream_key_iv(
        raw16, bytes(range(32)), 99
    ) == framing.stream_key_iv_from_secret(
        framing.stream_secret16(raw16, bytes(range(32))), 99
    )
    key2, iv2 = framing.derive_tcp_stream_key_iv(raw16, bytes(range(32)), 7)
    assert key2.hex() == "b4a9f2f205a64fff1400b863cbd3033c"
    assert iv2.hex() == "47d4794311465256f9b332516b8126a5"


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
