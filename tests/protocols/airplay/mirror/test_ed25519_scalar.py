"""Tests for raw-scalar ed25519 signing used by the media pair-verify."""

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from pyatv.protocols.airplay.mirror import ed25519_scalar


def _scalar_and_pub_from_seed(seed: bytes):
    """Return (clamped_scalar, public_key) for an ed25519 seed.

    Mirrors what a device stores: the clamped expanded scalar (not the seed).
    """
    import hashlib

    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return bytes(a), pub


def test_scalar_signature_verifies_under_pubkey():
    seed = os.urandom(32)
    scalar, pub = _scalar_and_pub_from_seed(seed)
    message = os.urandom(64)

    sig = ed25519_scalar.sign_with_scalar(scalar, pub, message)

    assert len(sig) == 64
    # A standard verifier accepts it under the matching public key.
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)


def test_scalar_signature_random_nonce_still_valid():
    seed = os.urandom(32)
    scalar, pub = _scalar_and_pub_from_seed(seed)
    message = b"eph_pub||server_pub stand-in"

    sig1 = ed25519_scalar.sign_with_scalar(scalar, pub, message)
    sig2 = ed25519_scalar.sign_with_scalar(scalar, pub, message)

    # Random nonce -> different signatures, both valid.
    assert sig1 != sig2
    Ed25519PublicKey.from_public_bytes(pub).verify(sig1, message)
    Ed25519PublicKey.from_public_bytes(pub).verify(sig2, message)


def test_wrong_message_rejected():
    seed = os.urandom(32)
    scalar, pub = _scalar_and_pub_from_seed(seed)
    sig = ed25519_scalar.sign_with_scalar(scalar, pub, b"message-a")

    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, b"message-b")
        raise AssertionError("signature must not verify for a different message")
    except InvalidSignature:
        pass


def test_xrecover_corrects_a_wrong_first_candidate_root():
    """``_xrecover`` needs the ``*_I`` correction for half of all ``y``.

    The first candidate ``x = xx**((P+3)//8)`` is only a square root of ``xx``
    when ``xx`` is a fourth power; otherwise it is off by the factor ``I``
    (sqrt(-1) mod P) and must be corrected. The base point's ``y`` happens not
    to need it, so nothing else in the module executes that branch.
    """
    P = ed25519_scalar._P
    D = ed25519_scalar._D

    y = 3
    xx = (y * y - 1) * ed25519_scalar._inv(D * y * y + 1) % P
    naive = pow(xx, (P + 3) // 8, P)
    assert (naive * naive - xx) % P != 0, "y=3 must need the correction"

    x = ed25519_scalar._xrecover(y)

    # The corrected value really is a square root of xx...
    assert (x * x - xx) % P == 0
    # ...and it is the canonical (even) one the encoding requires.
    assert x % 2 == 0
