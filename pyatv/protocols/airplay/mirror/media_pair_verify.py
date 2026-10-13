"""Raw media pair-verify for the AirPlay 2 mirror sender.

The mirror stream keys are derived from the X25519 shared secret of this
pair-verify, not of pyatv's HAP pair-verify:

    M1 = 01 00 00 00 || client X25519 public (32) || client ed25519 public (32)
    M2 = receiver X25519 public (32) || AES-CTR(receiver signature) (64)
    M3 = 00 00 00 00 || AES-CTR(sign(client X25519 pub || receiver X25519 pub))

    key = SHA-512("Pair-Verify-AES-Key" || shared)[:16]
    iv  = SHA-512("Pair-Verify-AES-IV" || shared)[:16]

M3's signature is encrypted with the keystream after M2's (bytes 64:128).
The receiver only accepts an ed25519 identity it has registered; any other
is refused with HTTP 500 at M1. A HAP pair-verify on the same connection
also makes the receiver refuse this one, so it must be the connection's only
pair-verify.
"""

from __future__ import annotations

import hashlib
import logging
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import ed25519_scalar
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

#: Length of the X25519 shared secret this returns.
SHARED_SECRET_LENGTH = 32

#: The ed25519 identity the pair-verify signs with: the reference sender's,
#: which is registered with the receiver. pyatv cannot register an identity of its
#: own yet, so this is the one the receiver accepts. The scalar is the
#: clamped expanded scalar, not the RFC 8032 seed.
IDENTITY_PUBLIC = bytes.fromhex(
    "5392b494c3c613b5691f0c189187d658d24616b89eb0a7625708d2b6001aa0dd"
)
IDENTITY_SCALAR = bytes.fromhex(
    "f02d7f7ab6b1b508079755fc9aae1f39e601caa0cfeeae2c66cdac01edb5e958"
)


def _body_bytes(body) -> bytes:
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return body.encode("latin-1") if body else b""


async def media_pair_verify(rtsp: RtspSession) -> bytes:
    """Run the raw media pair-verify and return the 32-byte shared secret.

    Signs with :data:`IDENTITY_PUBLIC` / :data:`IDENTITY_SCALAR`. The result
    is the ``pair_secret`` a :class:`MirrorSession` derives its stream keys
    from.
    """

    async def _post(body: bytes):
        return await rtsp.exchange(
            "POST",
            uri="/pair-verify",
            content_type="application/octet-stream",
            body=body,
            allow_error=True,
        )

    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()

    resp = await _post(struct.pack("<I", 1) + ephemeral_public + IDENTITY_PUBLIC)
    if resp.code != 200:
        raise exceptions.AuthenticationError(
            f"media pair-verify M1 returned HTTP {resp.code} "
            "(is the identity registered with the receiver?)"
        )
    m2 = _body_bytes(resp.body)
    if len(m2) < 96:
        raise exceptions.ProtocolError(f"media pair-verify M2 is {len(m2)} bytes")
    server_public = m2[0:32]

    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(server_public))
    aes_key = hashlib.sha512(b"Pair-Verify-AES-Key" + shared).digest()[:16]
    aes_iv = hashlib.sha512(b"Pair-Verify-AES-IV" + shared).digest()[:16]
    ctr = Cipher(algorithms.AES(aes_key), modes.CTR(aes_iv)).encryptor()
    ctr.update(m2[32:96])  # skip the keystream that covered M2's signature

    signature = ed25519_scalar.sign_with_scalar(
        IDENTITY_SCALAR, IDENTITY_PUBLIC, ephemeral_public + server_public
    )
    resp = await _post(struct.pack("<I", 0) + ctr.update(signature))
    if resp.code != 200:
        raise exceptions.AuthenticationError(
            f"media pair-verify M3 returned HTTP {resp.code}"
        )
    _LOGGER.debug("Media pair-verify complete")
    return shared
