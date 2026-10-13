"""Tests for the raw media pair-verify of the mirror sender."""

import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import MediaIdentity, media_pair_verify

#: A registered identity, as after the one-time PIN pairing.
IDENTITY = MediaIdentity.generate()


class _Response:
    def __init__(self, code, body=b""):
        self.code = code
        self.body = body


class _FakeReceiver:
    """Receiver side of the media pair-verify, speaking through ``exchange``."""

    def __init__(self, registered: bytes, m3_code: int = 200):
        self.registered = registered
        self.m3_code = m3_code
        self.signature_ok = False
        self.shared = b""
        self._ctr = None
        self._signed = b""
        self._client_ed = b""

    async def exchange(self, method, uri, content_type, body, allow_error):
        assert (method, uri) == ("POST", "/pair-verify")
        assert content_type == "application/octet-stream"
        assert allow_error
        state = struct.unpack("<I", body[:4])[0]
        if state == 1:
            return self._m1(body)
        return self._m3(body)

    def _m1(self, body):
        assert len(body) == 68
        client_x, client_ed = body[4:36], body[36:68]
        if client_ed != self.registered:
            return _Response(500)
        self._client_ed = client_ed
        server = X25519PrivateKey.generate()
        server_x = server.public_key().public_bytes_raw()
        self.shared = server.exchange(X25519PublicKey.from_public_bytes(client_x))
        key = hashlib.sha512(b"Pair-Verify-AES-Key" + self.shared).digest()[:16]
        iv = hashlib.sha512(b"Pair-Verify-AES-IV" + self.shared).digest()[:16]
        self._ctr = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        self._signed = client_x + server_x
        server_sig = Ed25519PrivateKey.generate().sign(server_x + client_x)
        return _Response(200, server_x + self._ctr.update(server_sig))

    def _m3(self, body):
        assert len(body) == 68
        assert body[:4] == b"\x00\x00\x00\x00"
        signature = self._ctr.update(body[4:])
        Ed25519PublicKey.from_public_bytes(self._client_ed).verify(
            signature, self._signed
        )
        self.signature_ok = True
        return _Response(self.m3_code)


@pytest.mark.asyncio
async def test_returns_the_shared_secret_after_a_valid_signature():
    receiver = _FakeReceiver(registered=IDENTITY.public_key)

    shared = await media_pair_verify(receiver, IDENTITY)

    assert receiver.signature_ok
    assert len(shared) == 32
    assert shared == receiver.shared


@pytest.mark.asyncio
async def test_an_unregistered_identity_is_an_authentication_error():
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()

    with pytest.raises(exceptions.AuthenticationError, match="M1 returned HTTP 500"):
        await media_pair_verify(_FakeReceiver(registered=other), IDENTITY)


@pytest.mark.asyncio
async def test_a_refused_m3_is_an_authentication_error():
    receiver = _FakeReceiver(IDENTITY.public_key, m3_code=470)

    with pytest.raises(exceptions.AuthenticationError, match="M3 returned HTTP 470"):
        await media_pair_verify(receiver, IDENTITY)
