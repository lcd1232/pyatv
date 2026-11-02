"""MFiSAP handshake for the AirPlay 2 mirror sender.

Four messages -- M1/M2 on ``/fp-setup``, M3/M4 on ``/auth-setup`` --
derive the AES-128-CTR key and IV that encrypt mirror frame payloads end
to end:

    M1  = header byte || sender X25519 public key (32)
    M2  = receiver X25519 public key (32) || cert_len (4, BE)
          || sig_len (4, BE) || cert || sig
    M3  = cert || AES-CTR(sig)
    key = SHA-1("AES-KEY" || 00 || shared)[:16]
    iv  = SHA-1("AES-IV" || 00 || shared)[:16]

The sender's X25519 scalar is HKDF-SHA512 over 32 random bytes.  Only
standard primitives from the ``cryptography`` dependency are used.
"""

from __future__ import annotations

from enum import Enum, auto
import logging
import secrets
import struct
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pyatv import exceptions
from pyatv.protocols.airplay.mirror.framing import MirrorEncryptor, aes_ctr

_LOGGER = logging.getLogger(__name__)

HKDF_SALT = b"MFiSAP-ECDH-Salt"
HKDF_INFO = b"MFiSAP-ECDH-Info"

# Default M1[0] header byte ("client hello").
DEFAULT_M1_HEADER_BYTE = 0x01


class _State(Enum):
    INIT = auto()
    AWAITING_M2 = auto()
    DONE = auto()


def _sha1(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA1())
    h.update(data)
    return h.finalize()


class MFiSAPHandshake:
    """4-message MFiSAP handshake state machine."""

    def __init__(self, header_byte: int = DEFAULT_M1_HEADER_BYTE) -> None:
        """Start an MFiSAP handshake whose M1 carries *header_byte*."""
        self._header_byte = header_byte & 0xFF
        self._state = _State.INIT
        self._scalar_key: x25519.X25519PrivateKey | None = None
        self._aes_key: bytes | None = None
        self._aes_iv: bytes | None = None
        self._stream_encryptor: MirrorEncryptor | None = None

    def build_m1(self) -> bytes:
        """Return the 33-byte M1 body to POST to /fp-setup."""
        if self._state is not _State.INIT:
            raise RuntimeError(f"build_m1 in state {self._state}")

        ikm = secrets.token_bytes(32)
        scalar = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=HKDF_SALT,
            info=HKDF_INFO,
        ).derive(ikm)
        self._scalar_key = x25519.X25519PrivateKey.from_private_bytes(scalar)
        pubkey = self._scalar_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        self._state = _State.AWAITING_M2
        return bytes([self._header_byte]) + pubkey

    def consume_m2_build_m3(self, m2: bytes) -> bytes:
        """Parse M2, derive keys, return M3 body to POST to /auth-setup."""
        if self._state is not _State.AWAITING_M2:
            raise RuntimeError(f"consume_m2_build_m3 in state {self._state}")
        if len(m2) < 40:
            raise ValueError(f"M2 too short: {len(m2)} bytes (need >= 40)")

        server_pubkey_raw = m2[0:32]
        cert_len, sig_len = struct.unpack(">II", m2[32:40])
        if len(m2) < 40 + cert_len + sig_len:
            raise ValueError(
                f"M2 truncated: need {40 + cert_len + sig_len} bytes, " f"got {len(m2)}"
            )
        cert = m2[40 : 40 + cert_len]
        sig = m2[40 + cert_len : 40 + cert_len + sig_len]

        server_pubkey = x25519.X25519PublicKey.from_public_bytes(server_pubkey_raw)
        assert self._scalar_key is not None
        shared = self._scalar_key.exchange(server_pubkey)

        # SHA-1 KDF; the labels include their trailing NUL (8 and 7 bytes)
        self._aes_key = _sha1(b"AES-KEY\x00" + shared)[:16]
        self._aes_iv = _sha1(b"AES-IV\x00" + shared)[:16]

        # The same AES-CTR cipher instance encrypts the M3 sig AND every
        # subsequent mirror frame — continuous keystream.
        self._stream_encryptor = MirrorEncryptor(aes_ctr(self._aes_key, self._aes_iv))
        encrypted_sig = self._stream_encryptor.encrypt(sig)

        self._state = _State.DONE
        return cert + encrypted_sig

    @property
    def aes_key(self) -> bytes:
        """Return the negotiated 16-byte AES key."""
        if self._aes_key is None:
            raise RuntimeError("handshake not complete")
        return self._aes_key

    @property
    def aes_iv(self) -> bytes:
        """Return the negotiated 16-byte AES IV."""
        if self._aes_iv is None:
            raise RuntimeError("handshake not complete")
        return self._aes_iv

    @property
    def stream_encryptor(self) -> MirrorEncryptor:
        """The session's continuous-keystream AES-CTR encryptor.

        State has been advanced past the M3 sig encryption; subsequent
        `encrypt(...)` calls on this object continue the keystream from
        where M3 left off.
        """
        if self._stream_encryptor is None:
            raise RuntimeError("handshake not complete")
        return self._stream_encryptor


class HttpConnection(Protocol):
    """Protocol for HTTP connection with send_and_receive method."""

    async def send_and_receive(
        self,
        method: str,
        uri: str,
        **kwargs,
    ) -> Any:
        """Send HTTP request and receive response."""


USER_AGENT = "AirPlay/550.10"


async def run_handshake(
    connection: HttpConnection,
    header_byte: int = DEFAULT_M1_HEADER_BYTE,
) -> MFiSAPHandshake:
    """Run the full MFiSAP handshake over an existing HTTP connection.

    Returns the completed `MFiSAPHandshake` whose `stream_encryptor`
    can then be used to encrypt mirror frame payloads.
    """
    sm = MFiSAPHandshake(header_byte=header_byte)

    m1 = sm.build_m1()
    resp1 = await connection.send_and_receive(
        "POST",
        "/fp-setup",
        user_agent=USER_AGENT,
        content_type="application/octet-stream",
        headers={"X-Apple-HKP": "3"},
        body=m1,
    )
    if resp1.code != 200:
        raise exceptions.ProtocolError(f"/fp-setup returned HTTP {resp1.code}")

    m2 = (
        resp1.body
        if isinstance(resp1.body, (bytes, bytearray))
        else bytes(resp1.body, "latin-1")
    )
    m3 = sm.consume_m2_build_m3(m2)

    resp2 = await connection.send_and_receive(
        "POST",
        "/auth-setup",
        user_agent=USER_AGENT,
        content_type="application/octet-stream",
        headers={"X-Apple-HKP": "3"},
        body=m3,
    )
    if resp2.code != 200:
        raise exceptions.ProtocolError(f"/auth-setup returned HTTP {resp2.code}")

    # M4 carries nothing the sender needs; HTTP 200 completes the handshake.
    return sm
