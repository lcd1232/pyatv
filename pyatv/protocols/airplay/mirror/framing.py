"""AES-CTR stream encryptor and the mirror stream key derivation.

Video frames are AES-128-CTR encrypted with one continuous keystream (see
:mod:`~pyatv.protocols.airplay.mirror.tcp_stream` for the framing), keyed by
:func:`derive_tcp_stream_key_iv`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_ctr(key: bytes, iv: bytes) -> Any:
    """Return a cryptography AES-CTR encryptor/decryptor (symmetric)."""
    if len(key) != 16:
        raise ValueError(f"AES-CTR key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CTR IV must be 16 bytes, got {len(iv)}")
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


class MirrorEncryptor:
    """Stateful AES-128-CTR encryptor with continuous keystream.

    One cipher state runs across the whole stream: each ``encrypt()`` call
    continues the keystream where the previous one stopped, with no
    per-frame reset.
    """

    def __init__(self, encryptor: Any, key: bytes = b"", iv: bytes = b"") -> None:
        """Wrap *encryptor*, remembering the *key* and *iv* it was built from."""
        self._encryptor = encryptor
        self._key = key
        self._iv = iv

    @classmethod
    def from_key_iv(cls, key: bytes, iv: bytes) -> "MirrorEncryptor":
        """Build an encryptor over AES-CTR with *key* and *iv*."""
        return cls(aes_ctr(key, iv), key=key, iv=iv)

    @property
    def key(self) -> bytes:
        """Return the 16-byte AES key this encryptor was built with."""
        return self._key

    @property
    def iv(self) -> bytes:
        """Return the 16-byte AES IV this encryptor was built with."""
        return self._iv

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt (or decrypt — CTR is symmetric) `data` with the running keystream."""
        return self._encryptor.update(data)


def derive_tcp_stream_key_iv(
    raw16: bytes, pair32: bytes, stream_connection_id: int
) -> tuple:
    """Return (key, iv) for a mirror media stream.

    ``raw16`` is the secret wrapped in ``ekey``; ``pair32`` is the X25519
    shared secret of the media connection's pair-verify::

        secret16 = sha512(raw16 ‖ pair32)[:16]
        key      = sha512("AirPlayStreamKey"
                          + decimal(streamConnectionID) ‖ secret16)[:16]
        iv       = sha512("AirPlayStreamIV"
                          + decimal(streamConnectionID) ‖ secret16)[:16]

    The stream is AES-128-CTR (128-bit BE counter starting at ``iv``,
    continuous keystream). ``stream_connection_id`` is the id sent in that
    stream's SETUP.
    """
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    return stream_key_iv_from_secret(
        stream_secret16(raw16, pair32), stream_connection_id
    )


def stream_secret16(raw16: bytes, pair32: bytes) -> bytes:
    """Return ``sha512(raw16 || pair32)[:16]``, the stream key secret."""
    return hashlib.sha512(raw16 + bytes(pair32)).digest()[:16]


def stream_key_iv_from_secret(
    secret: bytes, stream_connection_id: int
) -> tuple[bytes, bytes]:
    """Label the secret with the stream id and hash it down to (key, iv).

    The id is formatted as an unsigned decimal string after the label.
    """
    sid = stream_connection_id & 0xFFFFFFFFFFFFFFFF
    key = hashlib.sha512(f"AirPlayStreamKey{sid}".encode() + secret).digest()[:16]
    iv = hashlib.sha512(f"AirPlayStreamIV{sid}".encode() + secret).digest()[:16]
    return key, iv
