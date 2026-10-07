"""Ed25519 signing from a raw clamped scalar (no seed / no nonce prefix).

The AirPlay 2 raw *media* pair-verify requires the client to sign M3 with
an ed25519 identity the receiver has registered through a raw
``/pair-setup``; a fresh identity is rejected with HTTP 500.  Such an
identity may only be available as its clamped expanded scalar ``a``, not
the RFC 8032 seed, and ``cryptography`` only signs from the seed.

This module implements the minimal edwards25519 arithmetic needed to sign
directly from ``a``.  Ed25519 does not require the deterministic
prefix-derived nonce: any nonce ``r`` yields ``sig = R ‖ S`` with
``R = r·B`` and ``S = (r + H(R‖A‖M)·a) mod L``, which verifies under the
public key ``A = a·B``.  ``r`` is derived from a random value instead.
"""

from __future__ import annotations

import hashlib
import os

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = (-121665 * _inv(121666)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX % _P, _BY % _P)


def _edwards(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    denom = _inv(1 + _D * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _P
    return (x3 % _P, y3 % _P)


def _scalarmult(pt, e: int):
    result = (0, 1)
    addend = pt
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _encodepoint(pt) -> bytes:
    x, y = pt
    data = bytearray(y.to_bytes(32, "little"))
    data[31] |= (x & 1) << 7
    return bytes(data)


def sign_with_scalar(
    scalar: bytes, public_key: bytes, message: bytes, nonce: bytes = b""
) -> bytes:
    """Return a 64-byte ed25519 signature over *message*.

    ``scalar`` is the 32-byte little-endian clamped private scalar ``a``;
    ``public_key`` is the corresponding 32-byte ``A = a·B``. The signature
    verifies under ``public_key`` with any standard ed25519 verifier.
    """
    a = int.from_bytes(scalar, "little")
    if not nonce:
        nonce = os.urandom(32)
    r = int.from_bytes(hashlib.sha512(nonce + message).digest(), "little") % _L
    big_r = _encodepoint(_scalarmult(_B, r))
    k = (
        int.from_bytes(hashlib.sha512(big_r + public_key + message).digest(), "little")
        % _L
    )
    s = (r + k * a) % _L
    return big_r + s.to_bytes(32, "little")
