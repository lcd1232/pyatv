"""Raw media pair-verify for the AirPlay 2 mirror sender.

The mirror stream keys are derived from the X25519 shared secret of this
pair-verify, not of pyatv's HAP pair-verify:

    M1 = 01 00 00 00 || client X25519 public (32) || client ed25519 public (32)
    M2 = receiver X25519 public (32) || AES-CTR(receiver signature) (64)
    M3 = 00 00 00 00 || AES-CTR(sign(client X25519 pub || receiver X25519 pub))

    key = SHA-512("Pair-Verify-AES-Key" || shared)[:16]
    iv  = SHA-512("Pair-Verify-AES-IV" || shared)[:16]

M3's signature is encrypted with the keystream after M2's (bytes 64:128).
The receiver only accepts an ed25519 identity it has registered (with the
one-time PIN pairing in :mod:`.media_pairing`); any other is refused with
HTTP 500 at M1. A HAP pair-verify on the same connection also makes the
receiver refuse this one, so it must be the connection's only pair-verify.
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
from pyatv.protocols.airplay.mirror.media_pairing import MediaIdentity
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

#: Length of the X25519 shared secret this returns.
SHARED_SECRET_LENGTH = 32


def _body_bytes(body) -> bytes:
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    return body.encode("latin-1") if body else b""


async def media_pair_verify(rtsp: RtspSession, identity: MediaIdentity) -> bytes:
    """Run the raw media pair-verify and return the 32-byte shared secret.

    Signs with *identity*, which must be registered with the receiver
    (:func:`.register_media_identity`). The result is the ``pair_secret`` a
    :class:`MirrorSession` derives its stream keys from.
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

    resp = await _post(struct.pack("<I", 1) + ephemeral_public + identity.public_key)
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
        identity.scalar, identity.public_key, ephemeral_public + server_public
    )
    resp = await _post(struct.pack("<I", 0) + ctr.update(signature))
    if resp.code != 200:
        raise exceptions.AuthenticationError(
            f"media pair-verify M3 returned HTTP {resp.code}"
        )
    _LOGGER.debug("Media pair-verify complete")
    return shared
