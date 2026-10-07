"""SRTP-style AES-128-CTR encryption for the AirPlay 2 mirror video stream.

The negotiated cipher suite is
``VCMediaStreamCipherSuiteCipherAES128AuthNoneRCCM3`` -- AES-128 in CTR mode
(big-endian counter) with no authentication tag. The captured stream matches:
RTP, a stream cipher (payloads not block-aligned), no auth tag, 4 SSRCs each
with their own keystream, an **8-byte plaintext sub-header** on each RTP payload
(``90 TT 00 01 00 NN CC CC`` -- TT=type, NN=fragment count, CCCC=big-endian
per-frame counter) and encryption starting at payload offset 8. pyatv's
``rtp.py`` already emits this framing; it is NOT the blocker.

**KEY SOURCE -- IMPORTANT (settled 2026-08-23 with ground truth):** the mirror
video is **FairPlay (X-Apple-ET:32) keyed**, NOT pair-verify keyed. A ground-
truth atvproxy capture (exact pair-verify shared secret + exact ciphertext) was
run against ~6400 recipe variants -- every HKDF-SHA512/SHA512/HMAC over the
shared secret, with all ``DataStream-*`` salts/infos plus ``encryptionSeed`` and
``streamConnectionID`` in every position/encoding -- and NONE decrypt to H.264.
So the AES key comes from the FairPlay SAP handshake ``keybuf``, not from any
function of the pair-verify secret. See memory note
``project-mirror-not-pairverify-keyed`` and ``fairplay_sap/``.

The DataStream/pair-verify derivations below (``derive_datastream_master``,
``from_shared_key``) are RETAINED only as disproven A/B baselines -- they are
NOT the real key path. The real key is
``SHA512(f"AirPlayStreamKey{id}" || keybuf)[:16]`` where ``keybuf`` is the
FairPlay SAP secret (see ``fairplay_sap.sap_secret``).

Per-packet IV (RFC 3711):
``IV = (session_salt << 16) XOR (SSRC << 64) XOR (packet_index << 16)``,
``packet_index = 2^16 * ROC + SEQ``; counter reset per RTP packet.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_datastream_master(shared_key: bytes, stream_connection_id: int) -> tuple:
    """Derive the SRTP (MediaKey 32B, MasterSalt 14B) for the mirror video.

    Static analysis of Apple's ``screenstreamudp`` sender path (Phase 29 agent):
    a 46-byte master blob = HKDF-SHA512 over the **raw pair-verify Curve25519
    shared secret** with ``salt = "DataStream-Salt" + decimal(streamConnectionID)``
    and ``info = "DataStream-Output-Encryption-Key"`` (the sender's Output key,
    which the receiver uses to decrypt). MediaKey = master[0:32], MasterSalt =
    master[32:46]. This is keyed by pair-verify, NOT FairPlay (proven: the
    captured control channel decrypts with this shared secret).
    """
    unsigned_id = stream_connection_id & 0xFFFFFFFFFFFFFFFF
    salt = b"DataStream-Salt" + str(unsigned_id).encode()
    master = HKDF(
        algorithm=hashes.SHA512(),
        length=46,
        salt=salt,
        info=b"DataStream-Output-Encryption-Key",
    ).derive(shared_key)
    return master[:32], master[32:46]


def _cc_key_derivation_hmac(
    media_key: bytes, master_salt: bytes, ssrc: int, context_bytes: bytes = b""
) -> bytes:
    """Apple's SRTP session-key KDF (CCKeyDerivationHMac alg=6, SHA-256).

    Derives 30 bytes (16-byte session key + 14-byte session salt) from the
    32-byte MediaKey with the 4-byte big-endian SSRC as context and MasterSalt
    as salt. macOS-only (libcommonCrypto). Raises OSError if unavailable.
    """
    cc = ctypes.CDLL("/usr/lib/system/libcommonCrypto.dylib")
    fn = cc.CCKeyDerivationHMac
    fn.restype = ctypes.c_int
    fn.argtypes = [ctypes.c_uint32] * 3 + [ctypes.c_void_p, ctypes.c_size_t] * 6
    out = (ctypes.c_uint8 * 30)()
    ctx = context_bytes if context_bytes else struct.pack(">I", ssrc & 0xFFFFFFFF)
    rc = fn(
        6,
        0xA,
        0,
        ctypes.c_char_p(media_key),
        len(media_key),
        None,
        0,
        ctypes.c_char_p(ctx),
        len(ctx),
        None,
        0,
        ctypes.c_char_p(master_salt),
        len(master_salt),
        ctypes.cast(out, ctypes.c_void_p),
        30,
    )
    if rc != 0:
        raise OSError(f"CCKeyDerivationHMac failed rc={rc}")
    return bytes(out)


#: SRTP AES-128 uses a 16-byte session key and a 14-byte session salt.
SESSION_KEY_LEN = 16
SESSION_SALT_LEN = 14


def derive_master_key_salt(datastream_key: bytes) -> tuple:
    """Split the 32-byte DataStream-Output HKDF key into (master_key, master_salt).

    SRTP AES-128 needs a 16-byte master key and a 14-byte master salt; Apple's
    keyMaterial carries them as the head of the DataStream-derived key.
    """
    if len(datastream_key) < SESSION_KEY_LEN + SESSION_SALT_LEN:
        raise ValueError(
            f"datastream key too short: {len(datastream_key)} bytes, "
            f"need >= {SESSION_KEY_LEN + SESSION_SALT_LEN}"
        )
    return (
        datastream_key[:SESSION_KEY_LEN],
        datastream_key[SESSION_KEY_LEN : SESSION_KEY_LEN + SESSION_SALT_LEN],
    )


def _sp800_108_ctr_hmac_sha256(
    key: bytes, label: bytes, context: bytes, out_len: int
) -> bytes:
    """NIST SP800-108 counter-mode KDF with PRF = HMAC-SHA256.

    ``K(i) = HMAC(key, [i]_32 || Label || 0x00 || Context || [L]_32)``.
    """
    blocks = (out_len + 31) // 32
    length_bits = out_len * 8
    out = b""
    for i in range(1, blocks + 1):
        msg = (
            struct.pack(">I", i)
            + label
            + b"\x00"
            + context
            + struct.pack(">I", length_bits)
        )
        out += hmac.new(key, msg, hashlib.sha256).digest()
    return out[:out_len]


def derive_session_key_salt(
    master_key: bytes, master_salt: bytes, ssrc: int, use_kdf: bool = True
) -> tuple:
    """Derive the per-SSRC (session_key, session_salt).

    With ``use_kdf`` the SP800-108 HMAC-SHA256 KDF is applied with the SSRC as
    context (Apple's per-stream keying). Without it the master key/salt are used
    directly (a fallback to validate the master material independently of the
    KDF construction).
    """
    if not use_kdf:
        return master_key[:SESSION_KEY_LEN], master_salt[:SESSION_SALT_LEN]
    context = struct.pack(">I", ssrc & 0xFFFFFFFF)
    okm = _sp800_108_ctr_hmac_sha256(
        master_key, master_salt, context, SESSION_KEY_LEN + SESSION_SALT_LEN
    )
    return okm[:SESSION_KEY_LEN], okm[SESSION_KEY_LEN:]


def srtp_iv(session_salt: bytes, ssrc: int, roc: int, seq: int) -> bytes:
    """Build the 16-byte AES-CTR counter block for one RTP packet (RFC 3711)."""
    iv = bytearray(session_salt[:SESSION_SALT_LEN]) + bytearray(2)  # 16 bytes
    ssrc_b = struct.pack(">I", ssrc & 0xFFFFFFFF)
    for i in range(4):
        iv[4 + i] ^= ssrc_b[i]
    roc_b = struct.pack(">I", roc & 0xFFFFFFFF)
    for i in range(4):
        iv[8 + i] ^= roc_b[i]
    iv[12] ^= (seq >> 8) & 0xFF
    iv[13] ^= seq & 0xFF
    return bytes(iv)


def srtp_aes_cm_prf(
    master_key: bytes, master_salt: bytes, label: int, out_len: int
) -> bytes:
    """RFC 3711 SRTP key-derivation PRF (AES-128 counter mode), KDR=0.

    ``x = (master_salt padded to 16B) XOR (label << 48)`` at salt byte 7, then
    ``AES-CM(master_key, x)`` keystream truncated to ``out_len``. Labels: 0x00 =
    session encryption key, 0x02 = session salt (RFC 3711 4.3.1/4.3.3).
    """
    iv = bytearray(master_salt[:14]) + b"\x00\x00"
    iv[7] ^= label & 0xFF
    ks = Cipher(algorithms.AES(master_key), modes.CTR(bytes(iv))).encryptor()
    return ks.update(b"\x00" * out_len)[:out_len]


def derive_srtp_session_aescm(master_key: bytes, master_salt: bytes) -> tuple:
    """Standard SRTP session (key16, salt14) from a master key/salt via AES-CM."""
    session_key = srtp_aes_cm_prf(master_key, master_salt, 0x00, SESSION_KEY_LEN)
    session_salt = srtp_aes_cm_prf(master_key, master_salt, 0x02, SESSION_SALT_LEN)
    return session_key, session_salt


class SrtpVideoEncryptor:
    """AES-128-CTR SRTP encryptor for one video SSRC (no auth tag)."""

    def __init__(
        self,
        master_key: bytes,
        master_salt: bytes,
        ssrc: int,
        use_kdf: bool = True,
    ) -> None:
        self._session_key, self._session_salt = derive_session_key_salt(
            master_key, master_salt, ssrc, use_kdf
        )
        self._ssrc = ssrc & 0xFFFFFFFF
        self._roc = 0
        self._prev_seq: int | None = None

    @classmethod
    def from_shared_key(
        cls,
        shared_key: bytes,
        stream_connection_id: int,
        ssrc: int,
        session_kdf: bool = True,
    ) -> "SrtpVideoEncryptor":
        """Build from the raw pair-verify secret via the DataStream recipe.

        ``session_kdf`` runs Apple's CCKeyDerivationHMac (macOS-only) to derive
        the per-SSRC session key/salt from the 32-byte MediaKey; otherwise the
        MediaKey's first 16 bytes and the MasterSalt are used directly.
        """
        media_key, master_salt = derive_datastream_master(
            shared_key, stream_connection_id
        )
        self = cls.__new__(cls)
        if session_kdf:
            okm = _cc_key_derivation_hmac(media_key, master_salt, ssrc)
            self._session_key, self._session_salt = okm[:16], okm[16:30]
        else:
            self._session_key, self._session_salt = media_key[:16], master_salt
        self._ssrc = ssrc & 0xFFFFFFFF
        self._roc = 0
        self._prev_seq = None
        self.roc_trailer = False
        return self

    @property
    def session_key(self) -> bytes:
        """Return the derived SRTP session key."""
        return self._session_key

    def _update_roc(self, seq: int) -> None:
        """Track the roll-over counter from 16-bit sequence-number wraps."""
        if self._prev_seq is not None and seq < self._prev_seq - 0x8000:
            # sequence wrapped past 0xFFFF -> 0
            self._roc = (self._roc + 1) & 0xFFFFFFFF
        self._prev_seq = seq

    #: When True, append the 4-byte big-endian ROC as an RCCM3 trailer after the
    #: ciphertext (RFC 4771 ROC-carrying mechanism, mode 3). Toggled for on-device
    #: validation via the ``MIRROR_SRTP_ROC_TRAILER`` env var in session.py.
    roc_trailer: bool = False

    def encrypt(self, seq: int, payload: bytes) -> bytes:
        """AES-128-CTR encrypt one RTP packet payload keyed by its sequence."""
        self._update_roc(seq & 0xFFFF)
        iv = srtp_iv(self._session_salt, self._ssrc, self._roc, seq & 0xFFFF)
        cipher = Cipher(algorithms.AES(self._session_key), modes.CTR(iv))
        out = cipher.encryptor().update(payload)
        if self.roc_trailer:
            out += struct.pack(">I", self._roc & 0xFFFFFFFF)
        return out
