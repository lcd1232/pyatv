"""Tests for the SRTP AES-128-CTR mirror-video encryptor."""

import hashlib
import hmac
import random
import struct
import sys
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.kbkdf import (
    KBKDFHMAC,
    CounterLocation,
    Mode,
)
import pytest

from pyatv.protocols.airplay.mirror import srtp


def test_derive_master_key_salt_splits_32_bytes():
    ds = bytes(range(32))
    mk, ms = srtp.derive_master_key_salt(ds)
    assert mk == ds[:16]
    assert ms == ds[16:30]


def test_srtp_iv_rfc3711_layout():
    salt = bytes(range(14))
    iv = srtp.srtp_iv(salt, ssrc=0x01020304, roc=0, seq=0x1122)
    # salt in bytes 0..13, then XOR of ssrc @4..7 and seq @12..13
    expect = bytearray(salt) + bytearray(2)
    for i, b in enumerate(struct.pack(">I", 0x01020304)):
        expect[4 + i] ^= b
    expect[12] ^= 0x11
    expect[13] ^= 0x22
    assert iv == bytes(expect)


def test_encrypt_is_aes_ctr_and_roundtrips():
    mk, ms = srtp.derive_master_key_salt(bytes(range(32)))
    enc = srtp.SrtpVideoEncryptor(mk, ms, ssrc=0xAABBCCDD, use_kdf=True)
    payload = bytes(range(100))
    ct = enc.encrypt(0x2000, payload)
    assert len(ct) == len(payload) and ct != payload
    sk, ss = srtp.derive_session_key_salt(mk, ms, 0xAABBCCDD, use_kdf=True)
    iv = srtp.srtp_iv(ss, 0xAABBCCDD, 0, 0x2000)
    pt = Cipher(algorithms.AES(sk), modes.CTR(iv)).decryptor().update(ct)
    assert pt == payload


def test_roc_increments_on_sequence_wrap():
    mk, ms = srtp.derive_master_key_salt(bytes(range(32)))
    enc = srtp.SrtpVideoEncryptor(mk, ms, ssrc=1, use_kdf=False)
    enc.encrypt(0xFFFE, b"a" * 16)
    assert enc._roc == 0
    enc.encrypt(0x0001, b"b" * 16)  # wrapped
    assert enc._roc == 1


def test_roc_trailer_appends_four_bytes():
    mk, ms = srtp.derive_master_key_salt(bytes(range(32)))
    enc = srtp.SrtpVideoEncryptor(mk, ms, ssrc=1, use_kdf=False)
    enc.roc_trailer = True
    out = enc.encrypt(0x10, b"x" * 20)
    assert len(out) == 24
    assert out[-4:] == struct.pack(">I", 0)


# ---------------------------------------------------------------------------
# Published-reference tests.
#
# The functions below implement constructions that have a normative
# definition, so they are checked against that definition's own test vectors
# -- not against what the code happens to return today.  A wrong key
# derivation negotiates cleanly and renders nothing, which is precisely the
# failure this module exists to avoid, so "it did not change" is not enough.
# ---------------------------------------------------------------------------

# RFC 3711 Appendix B.3, "Key Derivation Test Vectors" (KDR = 0, index 0).
_RFC3711_MASTER_KEY = bytes.fromhex("E1F97A0D3E018BE0D64FA32C06DE4139")
_RFC3711_MASTER_SALT = bytes.fromhex("0EC675AD498AFEEBB6960B3AABE6")
_RFC3711_CIPHER_KEY = bytes.fromhex("C61E7A93744F39EE10734AFE3FF7A087")
_RFC3711_CIPHER_SALT = bytes.fromhex("30CBBC08863D8C85D49DB34A9AE1")
_RFC3711_AUTH_KEY = bytes.fromhex("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4")


@pytest.mark.parametrize(
    "label,out_len,expected",
    [
        (0x00, 16, _RFC3711_CIPHER_KEY),  # session encryption key
        (0x01, 20, _RFC3711_AUTH_KEY),  # session authentication key
        (0x02, 14, _RFC3711_CIPHER_SALT),  # session salt
    ],
    ids=["cipher-key", "auth-key", "cipher-salt"],
)
def test_srtp_aes_cm_prf_matches_rfc3711_appendix_b3(label, out_len, expected):
    """PROOF: the AES-CM PRF reproduces RFC 3711's own key-derivation vectors.

    The auth-key label is not used by this codebase (the negotiated suite is
    AuthNone), but deriving it exercises the multi-block keystream path and is
    a published value, so it pins the construction beyond a single block.
    """
    got = srtp.srtp_aes_cm_prf(
        _RFC3711_MASTER_KEY, _RFC3711_MASTER_SALT, label, out_len
    )
    assert got == expected


def test_derive_srtp_session_aescm_matches_rfc3711_appendix_b3():
    """PROOF: the (key, salt) pair equals RFC 3711 B.3 for the same master."""
    session_key, session_salt = srtp.derive_srtp_session_aescm(
        _RFC3711_MASTER_KEY, _RFC3711_MASTER_SALT
    )
    assert session_key == _RFC3711_CIPHER_KEY
    assert session_salt == _RFC3711_CIPHER_SALT


# RFC 3711 Appendix B.2, "AES-CM Test Vectors".
_RFC3711_B2_SESSION_KEY = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
_RFC3711_B2_SESSION_SALT = bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD")
_RFC3711_B2_KEYSTREAM = bytes.fromhex(
    "E03EAD0935C95E80E166B16DD92B4EB4"
    "D23513162B02D0F72A43A2FE4A5F97AB"
    "41E95B3BB0A2E8DD477901E4FCA894C0"
)


def test_srtp_iv_matches_rfc3711_appendix_b2():
    """PROOF: SSRC=0, ROC=0, SEQ=0 gives RFC 3711 B.2's counter block."""
    iv = srtp.srtp_iv(_RFC3711_B2_SESSION_SALT, ssrc=0, roc=0, seq=0)
    assert iv == bytes.fromhex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000")


def test_encryptor_reproduces_rfc3711_appendix_b2_keystream():
    """PROOF: encrypting zeros yields RFC 3711 B.2's AES-CM keystream segment.

    This is the end-to-end check on ``srtp_iv`` plus the AES-CTR wiring in
    :meth:`SrtpVideoEncryptor.encrypt`: with ``use_kdf=False`` the session
    key/salt are used verbatim, so the keystream must be the published one.
    """
    enc = srtp.SrtpVideoEncryptor(
        _RFC3711_B2_SESSION_KEY, _RFC3711_B2_SESSION_SALT, ssrc=0, use_kdf=False
    )
    assert enc.session_key == _RFC3711_B2_SESSION_KEY
    assert enc.encrypt(0, bytes(48)) == _RFC3711_B2_KEYSTREAM


def _rfc3711_iv_reference(session_salt: bytes, ssrc: int, roc: int, seq: int) -> bytes:
    """RFC 3711 4.1.1 written as arithmetic rather than byte fiddling.

    ``IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)`` where the packet
    index ``i = 2^16 * ROC + SEQ``.
    """
    index = (roc << 16) | seq
    value = (int.from_bytes(session_salt, "big") << 16) ^ (ssrc << 64) ^ (index << 16)
    return (value & ((1 << 128) - 1)).to_bytes(16, "big")


def test_srtp_iv_equals_the_rfc3711_arithmetic_definition():
    """PROOF: the byte-XOR loop agrees with the RFC's arithmetic definition.

    Random SSRC/ROC/SEQ triples plus the values that straddle the ROC/SEQ
    boundary inside the 48-bit packet index.
    """
    rnd = random.Random(20260831)
    salts = [bytes(rnd.randrange(256) for _ in range(14)) for _ in range(4)]
    cases = [
        (0, 0, 0),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF),
        (0x01020304, 1, 0x0000),
        (0x01020304, 0, 0xFFFF),
    ] + [
        (rnd.randrange(2**32), rnd.randrange(2**32), rnd.randrange(2**16))
        for _ in range(100)
    ]
    for salt in salts:
        for ssrc, roc, seq in cases:
            assert srtp.srtp_iv(salt, ssrc, roc, seq) == _rfc3711_iv_reference(
                salt, ssrc, roc, seq
            ), (salt.hex(), ssrc, roc, seq)


@pytest.mark.parametrize("out_len", [1, 16, 30, 31, 32, 33, 64, 65])
def test_sp800_108_matches_an_independent_kbkdf(out_len):
    """PROOF: the counter-mode KDF matches ``cryptography``'s SP 800-108 KDF.

    ``KBKDFHMAC`` in counter mode with ``rlen=4``, ``llen=4`` and the counter
    before the fixed data is exactly NIST SP 800-108's
    ``K(i) = PRF(K, [i]_32 || Label || 0x00 || Context || [L]_32)``.  Lengths
    either side of the 32-byte SHA-256 block boundary pin the truncation.
    """
    key = bytes(range(32))
    label = b"kdf-label"
    context = struct.pack(">I", 0xDEADBEEF)
    reference = KBKDFHMAC(
        algorithm=hashes.SHA256(),
        mode=Mode.CounterMode,
        length=out_len,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
    ).derive(key)
    assert srtp._sp800_108_ctr_hmac_sha256(key, label, context, out_len) == reference


def test_derive_session_key_salt_is_the_sp800_108_kdf_over_ssrc():
    """The KDF path feeds MasterSalt as Label and the big-endian SSRC as Context."""
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    key, salt = srtp.derive_session_key_salt(master_key, master_salt, 0x11223344)
    okm = srtp._sp800_108_ctr_hmac_sha256(
        master_key, master_salt, struct.pack(">I", 0x11223344), 30
    )
    assert (key, salt) == (okm[:16], okm[16:])
    assert len(key) == 16 and len(salt) == 14


def test_derive_session_key_salt_without_kdf_passes_master_material_through():
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    assert srtp.derive_session_key_salt(
        master_key, master_salt, 0x99, use_kdf=False
    ) == (master_key, master_salt)


def test_derive_session_key_salt_varies_with_ssrc():
    """Each of the four mirror SSRCs must get its own keystream."""
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    derived = {
        srtp.derive_session_key_salt(master_key, master_salt, ssrc)
        for ssrc in (1, 2, 3, 4)
    }
    assert len(derived) == 4


# ---------------------------------------------------------------------------
# derive_datastream_master: the HKDF construction has a published definition
# (RFC 5869); the salt/info strings do not -- they are Apple's.  So the HKDF
# itself is proven and the string composition is pinned.
# ---------------------------------------------------------------------------


def _rfc5869_hkdf(hashmod, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF, written out rather than delegated to ``cryptography``.

    Delegating would be circular -- ``derive_datastream_master`` already calls
    ``cryptography``'s HKDF.  Self-checked against RFC 5869's own vectors in
    :func:`test_rfc5869_reference_implementation_is_itself_correct`.
    """
    hash_len = hashmod().digest_size
    prk = hmac.new(salt, ikm, hashmod).digest()
    block, okm = b"", b""
    for counter in range(1, -(-length // hash_len) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashmod).digest()
        okm += block
    return okm[:length]


def test_rfc5869_reference_implementation_is_itself_correct():
    """RFC 5869 Appendix A cases 1 and 3, so the oracle above can be trusted."""
    # Test Case 1: SHA-256, with salt and info.
    assert _rfc5869_hkdf(
        hashlib.sha256,
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    ) == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    # Test Case 3: SHA-256, zero-length salt and info.
    assert _rfc5869_hkdf(
        hashlib.sha256, bytes.fromhex("0b" * 22), bytes(32), b"", 42
    ) == bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_derive_datastream_master_is_plain_rfc5869_hkdf_sha512():
    """PROOF (of the HKDF part): matches an independent RFC 5869 HKDF-SHA512.

    The salt/info strings are Apple's and have no published definition; what
    is proven here is that they are fed through a standard HKDF and split at
    32 bytes, not that the strings themselves are the right ones.
    """
    shared = bytes(range(32, 64))
    media_key, master_salt = srtp.derive_datastream_master(shared, 12345)
    expected = _rfc5869_hkdf(
        hashlib.sha512,
        shared,
        b"DataStream-Salt12345",
        b"DataStream-Output-Encryption-Key",
        46,
    )
    assert media_key == expected[:32]
    assert master_salt == expected[32:46]
    assert len(media_key) == 32 and len(master_salt) == 14


def test_derive_datastream_master_formats_connection_id_unsigned():
    """CHARACTERIZATION: streamConnectionID is spelled ``%llu``, not ``%lld``.

    Real senders put a signed int64 in the SETUP plist and it is frequently
    negative; the receiver formats it unsigned, so both spellings of the same
    64-bit value must derive the same master.  There is no published reference
    for this -- it is Apple's convention, pinned here.
    """
    negative = -3735921725222598274
    unsigned = negative & 0xFFFFFFFFFFFFFFFF
    shared = bytes(range(32))
    assert srtp.derive_datastream_master(
        shared, negative
    ) == srtp.derive_datastream_master(shared, unsigned)
    # ...and the decimal spelling really is the unsigned one.
    assert (
        srtp.derive_datastream_master(shared, negative)[0]
        == _rfc5869_hkdf(
            hashlib.sha512,
            shared,
            b"DataStream-Salt" + str(unsigned).encode(),
            b"DataStream-Output-Encryption-Key",
            46,
        )[:32]
    )


def test_derive_datastream_master_varies_with_connection_id():
    shared = bytes(range(32))
    assert srtp.derive_datastream_master(shared, 1) != srtp.derive_datastream_master(
        shared, 2
    )


@pytest.mark.parametrize("length", [0, 15, 29])
def test_derive_master_key_salt_rejects_short_material(length):
    with pytest.raises(ValueError, match="datastream key too short"):
        srtp.derive_master_key_salt(bytes(length))


def test_derive_master_key_salt_accepts_exactly_30_bytes():
    material = bytes(range(30))
    assert srtp.derive_master_key_salt(material) == (material[:16], material[16:30])


# ---------------------------------------------------------------------------
# CCKeyDerivationHMac -- Apple's own SPI, macOS only, no published definition,
# so everything below is characterization.
# ---------------------------------------------------------------------------

_DARWIN_ONLY = pytest.mark.skipif(
    sys.platform != "darwin", reason="CCKeyDerivationHMac is macOS-only"
)


@_DARWIN_ONLY
def test_cc_key_derivation_hmac_returns_30_deterministic_bytes():
    """CHARACTERIZATION: the SPI runs and is a function of key/salt/SSRC."""
    media_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    first = srtp._cc_key_derivation_hmac(media_key, master_salt, 0x11223344)
    assert len(first) == 30
    assert first == srtp._cc_key_derivation_hmac(media_key, master_salt, 0x11223344)
    assert first != srtp._cc_key_derivation_hmac(media_key, master_salt, 0x11223345)
    assert first != srtp._cc_key_derivation_hmac(media_key, bytes(14), 0x11223344)


@_DARWIN_ONLY
def test_cc_key_derivation_hmac_takes_explicit_context_over_the_ssrc():
    media_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    assert srtp._cc_key_derivation_hmac(
        media_key, master_salt, 0, context_bytes=struct.pack(">I", 0x11223344)
    ) == srtp._cc_key_derivation_hmac(media_key, master_salt, 0x11223344)


@_DARWIN_ONLY
def test_apples_cc_kdf_and_the_sp800_108_kdf_do_not_agree():
    """FINDING, pinned: the module's two "Apple" session KDFs disagree.

    ``derive_session_key_salt(use_kdf=True)`` documents itself as "Apple's
    per-stream keying" and uses SP 800-108 CTR-HMAC-SHA256, while
    ``SrtpVideoEncryptor.from_shared_key(session_kdf=True)`` calls Apple's real
    ``CCKeyDerivationHMac``.  Given identical MediaKey/MasterSalt/SSRC the two
    produce different session material, so at most one of them can be what the
    receiver does.  This records the disagreement rather than asserting either
    is correct; if a future change makes them agree that is a real result, and
    this test should then be deleted rather than adjusted.
    """
    media_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    cc_okm = srtp._cc_key_derivation_hmac(media_key, master_salt, 0x11223344)
    sp_key, sp_salt = srtp.derive_session_key_salt(media_key, master_salt, 0x11223344)
    assert (cc_okm[:16], cc_okm[16:30]) != (sp_key, sp_salt)


def test_cc_key_derivation_hmac_raises_when_the_spi_fails():
    with patch("ctypes.CDLL") as cdll:
        cdll.return_value.CCKeyDerivationHMac.return_value = -4300
        with pytest.raises(OSError, match="rc=-4300"):
            srtp._cc_key_derivation_hmac(bytes(32), bytes(14), 1)


# ---------------------------------------------------------------------------
# SrtpVideoEncryptor.from_shared_key
# ---------------------------------------------------------------------------


def test_from_shared_key_without_session_kdf_uses_the_master_material():
    shared = bytes(range(32))
    enc = srtp.SrtpVideoEncryptor.from_shared_key(
        shared, stream_connection_id=-42, ssrc=0xAABBCCDD, session_kdf=False
    )
    media_key, master_salt = srtp.derive_datastream_master(shared, -42)
    assert enc.session_key == media_key[:16]
    assert enc._session_salt == master_salt
    assert enc._ssrc == 0xAABBCCDD
    assert enc._roc == 0 and enc._prev_seq is None and enc.roc_trailer is False

    payload = bytes(range(64))
    ciphertext = enc.encrypt(7, payload)
    iv = srtp.srtp_iv(master_salt, 0xAABBCCDD, 0, 7)
    cipher = Cipher(algorithms.AES(media_key[:16]), modes.CTR(iv))
    assert ciphertext == cipher.encryptor().update(payload)


@_DARWIN_ONLY
def test_from_shared_key_with_session_kdf_uses_apples_spi():
    shared = bytes(range(32))
    enc = srtp.SrtpVideoEncryptor.from_shared_key(
        shared, stream_connection_id=99, ssrc=5, session_kdf=True
    )
    media_key, master_salt = srtp.derive_datastream_master(shared, 99)
    okm = srtp._cc_key_derivation_hmac(media_key, master_salt, 5)
    assert enc.session_key == okm[:16]
    assert enc._session_salt == okm[16:30]


def test_from_shared_key_masks_the_ssrc_to_32_bits():
    enc = srtp.SrtpVideoEncryptor.from_shared_key(
        bytes(32), stream_connection_id=1, ssrc=0x1AABBCCDD, session_kdf=False
    )
    assert enc._ssrc == 0xAABBCCDD


def test_encrypt_masks_the_sequence_number_to_16_bits():
    """Only the low 16 bits of the sequence reach the IV; the rest is the ROC."""
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    a = srtp.SrtpVideoEncryptor(master_key, master_salt, ssrc=1, use_kdf=False)
    b = srtp.SrtpVideoEncryptor(master_key, master_salt, ssrc=1, use_kdf=False)
    assert a.encrypt(0x1234, b"x" * 32) == b.encrypt(0x9991234 & 0xFFFF, b"x" * 32)


def test_roc_does_not_advance_on_ordinary_or_reordered_sequences():
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))
    enc = srtp.SrtpVideoEncryptor(master_key, master_salt, ssrc=1, use_kdf=False)
    for seq in (0x1000, 0x1001, 0x0FFF, 0x1002):  # includes one reordered packet
        enc.encrypt(seq, b"y" * 8)
    assert enc._roc == 0


def test_the_roll_over_boundary_is_a_gap_strictly_wider_than_half_the_space():
    """Exactly half a sequence space back is a reorder, not a wrap.

    ``_update_roc`` calls it a wrap when ``seq < prev - 0x8000``, so a
    backwards jump of exactly 0x8000 is *not* one and 0x8001 is. Which side
    the boundary sits on is a convention -- the gap is ambiguous, and could
    equally be a wrap with catastrophic loss or a very late packet -- but it
    decides the ROC, the ROC keys the cipher, and a session that disagrees
    with the receiver about it decrypts to noise from that packet on.

    ``test_roc_does_not_advance_on_ordinary_or_reordered_sequences`` covers
    a small reorder and ``test_roc_increments_on_sequence_wrap`` a plain
    wrap; neither goes near the edge, so moving it by one went unnoticed.
    """
    master_key, master_salt = srtp.derive_master_key_salt(bytes(range(32)))

    exact = srtp.SrtpVideoEncryptor(master_key, master_salt, ssrc=1, use_kdf=False)
    exact.encrypt(0x8000, b"z" * 8)
    exact.encrypt(0x0000, b"z" * 8)  # a gap of exactly 0x8000
    assert exact._roc == 0, "a gap of exactly half the space is not a wrap"

    beyond = srtp.SrtpVideoEncryptor(master_key, master_salt, ssrc=1, use_kdf=False)
    beyond.encrypt(0x8001, b"z" * 8)
    beyond.encrypt(0x0000, b"z" * 8)  # one wider
    assert beyond._roc == 1, "one past the boundary is a wrap"
