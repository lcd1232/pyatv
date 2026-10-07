"""Mirror frame header packing + AES-CTR helpers.

Reference: UxPlay's ``lib/raop_rtp_mirror.c`` (``raop_rtp_mirror_thread``) and
``lib/mirror_buffer.c``, which parse what a real sender emits.

The mirror frame header is **128 bytes, little-endian**, followed by the
payload:

===========  =====  ===============================================
offset       size   meaning
===========  =====  ===============================================
0            4      payload size, excluding this header (uint32 LE)
4-5          2      payload type (see ``PAYLOAD_TYPE_*``)
6-7          2      payload option
8            8      NTP timestamp / PTS (uint64 LE)
16-127       112    metadata: width/height and floats the receiver
                    reads at offsets 16, 20, 40, 44, 48, 52, 56, 60
===========  =====  ===============================================

Only the payload is encrypted; the header travels in cleartext. Video NALs
(type 0) are AES-CTR encrypted, while SPS/PPS codec parameters (type 1) are
sent in the clear.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

#: RTSP ``streams[].type`` values (what the SETUP body negotiates) -- these are
#: stream identifiers, NOT the per-packet payload type below.
STREAM_TYPE_VIDEO = 110
STREAM_TYPE_AUDIO = 96

#: Backwards-compatible aliases for the stream type constants.
PAYLOAD_TYPE_VIDEO = STREAM_TYPE_VIDEO
PAYLOAD_TYPE_AUDIO = STREAM_TYPE_AUDIO

#: Per-packet payload types carried in bytes 4-5 of the frame header.
PACKET_TYPE_VIDEO = 0x00  #: AES-CTR encrypted VCL NAL
PACKET_TYPE_CODEC = 0x01  #: SPS/PPS codec parameters, sent unencrypted
PACKET_TYPE_KEEPALIVE = 0x02
PACKET_TYPE_STATS = 0x05  #: streaming performance info (binary plist)

FLAG_KEYFRAME = 0x0001

#: ``payload_size``, ``payload_type``, ``payload_option``, ``timestamp``.
#: Little-endian -- UxPlay parses these with ``byteutils_get_int`` /
#: ``byteutils_get_long``, which are the native little-endian readers (the
#: ``_be`` variants exist separately and are NOT used here). Padded out to the
#: full 128-byte header.
HEADER_FMT = "<IHHQ"
HEADER_PREFIX_LEN = struct.calcsize(HEADER_FMT)
HEADER_LEN = 128
assert HEADER_PREFIX_LEN == 16


@dataclass(frozen=True)
class MirrorHeader:
    """One mirror frame header (128 bytes on the wire)."""

    payload_size: int
    payload_type: int
    timestamp_ntp: int
    flags: int
    metadata: bytes = b""

    def __post_init__(self) -> None:
        """Normalize metadata to the fixed 112-byte tail."""
        tail = HEADER_LEN - HEADER_PREFIX_LEN
        if len(self.metadata) > tail:
            raise ValueError(f"metadata too long: {len(self.metadata)}")
        if len(self.metadata) != tail:
            object.__setattr__(self, "metadata", self.metadata.ljust(tail, b"\x00"))

    def pack(self) -> bytes:
        """Serialize to the full 128-byte little-endian header."""
        if not 0 <= self.payload_size < 2**32:
            raise ValueError(f"payload_size out of range: {self.payload_size}")
        if not 0 <= self.payload_type < 2**16:
            raise ValueError(f"payload_type out of range: {self.payload_type}")
        if not 0 <= self.flags < 2**16:
            raise ValueError(f"flags out of range: {self.flags}")
        if not 0 <= self.timestamp_ntp < 2**64:
            raise ValueError(f"timestamp_ntp out of range: {self.timestamp_ntp}")
        prefix = struct.pack(
            HEADER_FMT,
            self.payload_size,
            self.payload_type,
            self.flags,
            self.timestamp_ntp,
        )
        return prefix + self.metadata

    @classmethod
    def unpack(cls, data: bytes) -> "MirrorHeader":
        """Parse a 128-byte header (a 16-byte prefix is also accepted)."""
        size, ptype, flags, ts = struct.unpack(HEADER_FMT, data[:HEADER_PREFIX_LEN])
        return cls(
            payload_size=size,
            payload_type=ptype,
            timestamp_ntp=ts,
            flags=flags,
            metadata=bytes(data[HEADER_PREFIX_LEN:HEADER_LEN]),
        )


def aes_ctr(key: bytes, iv: bytes) -> Any:
    """Return a cryptography AES-CTR encryptor/decryptor (symmetric)."""
    if len(key) != 16:
        raise ValueError(f"AES-CTR key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CTR IV must be 16 bytes, got {len(iv)}")
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def encrypt_frame(
    key: bytes,
    iv: bytes,
    header: MirrorHeader,
    payload: bytes,
) -> bytes:
    """Encrypt payload with AES-CTR(key, iv), prepend the mirror header."""
    if header.payload_size != len(payload):
        raise ValueError(
            f"header.payload_size ({header.payload_size}) "
            f"!= len(payload) ({len(payload)})"
        )
    cipher = aes_ctr(key, iv)
    return header.pack() + cipher.update(payload)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC encrypt the whole-block prefix of *data*.

    Static analysis of Apple's ``AirPlayReceiver`` (the "Using legacy CBC
    Cryptor for decryption" path, ``AES_CBCFrame_Init``/``_Final``) shows screen
    video is AES-128-CBC, not the CTR that :func:`aes_ctr` implements. Only the
    ``len(data) // 16 * 16`` whole-block prefix is encrypted; the trailing
    ``len(data) % 16`` bytes travel in the clear (AirPlay's standard CBC
    remainder handling). The IV is applied fresh per call, i.e. per access unit
    -- CBC keeps no cross-call running state, so an entire H.264 access unit
    must be encrypted as ONE call, then packetized (never re-init per RTP
    fragment).
    """
    if len(key) != 16:
        raise ValueError(f"AES-CBC key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"AES-CBC IV must be 16 bytes, got {len(iv)}")
    whole = (len(data) // 16) * 16
    if whole == 0:
        return data
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data[:whole]) + enc.finalize() + data[whole:]


def encrypt_frame_cbc(
    key: bytes,
    iv: bytes,
    header: MirrorHeader,
    payload: bytes,
) -> bytes:
    """AES-128-CBC variant of :func:`encrypt_frame` (header stays cleartext)."""
    if header.payload_size != len(payload):
        raise ValueError(
            f"header.payload_size ({header.payload_size}) "
            f"!= len(payload) ({len(payload)})"
        )
    return header.pack() + aes_cbc_encrypt(key, iv, payload)


class ChaChaVideoEncryptor:
    """ChaCha20-Poly1305 AEAD encryptor for the tvOS 26 screen-mirroring path.

    Static analysis of Apple's ``AirPlayReceiver`` (``aprscreen``, Phase 29 /
    agent trace) shows modern screen video is **ChaCha20-Poly1305**, not AES:

    - 32-byte key from ``DataStream-Output-Encryption-Key`` HKDF (see
      :func:`derive_datastream_video_key`),
    - nonce = 8-byte little-endian frame counter starting at 0, padded to 12
      bytes (4 zero bytes prefix -- pyatv's ``Chacha20Cipher8byteNonce``
      convention), incremented once per frame,
    - AAD = an optional per-frame header (Apple uses the frame header; the exact
      bytes on the RTP path are still being pinned, so it is configurable),
    - output = ``ciphertext || 16-byte Poly1305 tag``.

    Exposes the same ``encrypt(bytes) -> bytes`` / ``start_fresh_block()`` duck
    type as :class:`MirrorEncryptor` so the video producer needs no change. One
    ``encrypt`` call == one frame == one nonce.
    """

    def __init__(self, key: bytes, aad: Optional[bytes] = None) -> None:
        """Take the 32-byte ChaCha20-Poly1305 *key* and optional *aad*."""
        if len(key) != 32:
            raise ValueError(f"ChaCha20-Poly1305 key must be 32 bytes, got {len(key)}")
        self._key = key
        self._aead = ChaCha20Poly1305(key)
        self._counter = 0
        self._aad = aad

    @property
    def key(self) -> bytes:
        """32-byte ChaCha20-Poly1305 key."""
        return self._key

    def _nonce(self) -> bytes:
        # 12-byte nonce: 4 zero bytes then the 8-byte LE counter.
        return b"\x00\x00\x00\x00" + self._counter.to_bytes(8, "little")

    def encrypt(self, data: bytes, aad: Optional[bytes] = None) -> bytes:
        """Encrypt one frame; returns ``ciphertext || tag`` and bumps the counter.

        ``aad`` overrides the per-instance default. Apple's receiver
        authenticates the 128-byte frame header verbatim as the AAD (Phase 29
        agent trace of ``aprscreen``: ``add_aad(header, 0x80)``), so the sender
        passes the identical 128-byte header here.
        """
        out = self._aead.encrypt(self._nonce(), data, self._aad if aad is None else aad)
        self._counter += 1
        return out

    def start_fresh_block(self) -> None:
        """No-op; ChaCha20-Poly1305 has no block-boundary keystream state."""


def derive_datastream_video_key(verifier: Any, stream_connection_id: int) -> bytes:
    """Derive the 32-byte screen-video ChaCha key from the pair-verify secret.

    Matches Apple's receiver ``_GetDataStreamSecurityKeys`` /
    ``PairingSessionDeriveKey``: HKDF-SHA512 over the HAP pair-verify shared
    secret with ``salt = "DataStream-Salt" + decimal(streamConnectionID)`` and
    ``info = "DataStream-Output-Encryption-Key"`` (the "Output" of the pair).
    ``verifier.encryption_keys`` is exactly this HKDF (see
    ``pyatv.auth.hap_srp.hkdf_expand``); it returns ``(output_key, input_key)``
    and the sender uses the **output** key. ``streamConnectionID`` is formatted
    unsigned (``%llu``).
    """
    unsigned_id = stream_connection_id & 0xFFFFFFFFFFFFFFFF
    output_key, _input_key = verifier.encryption_keys(
        "DataStream-Salt" + str(unsigned_id),
        "DataStream-Output-Encryption-Key",
        "DataStream-Input-Encryption-Key",
    )
    return output_key


class MirrorEncryptor:
    """Stateful AES-128-CTR encryptor with continuous keystream.

    The reference sender's reverse-engineered MFiSAP path uses a single AES-CTR cipher
    state across the entire mirror session: the same cipher object that
    encrypts the M3 handshake-sig is then advanced through every mirror
    frame's payload. This class wraps a cryptography.io encryptor and
    exposes only `encrypt(bytes) -> bytes`, which keeps the keystream
    moving across calls.
    """

    def __init__(self, encryptor: Any, key: bytes = b"", iv: bytes = b"") -> None:
        """Wrap *encryptor*, remembering the *key* and *iv* it was built from."""
        self._encryptor = encryptor
        self._key = key
        self._iv = iv
        self._offset = 0

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
        """16-byte AES IV/nonce (the one supplied to from_key_iv)."""
        return self._iv

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt (or decrypt — CTR is symmetric) `data` with the running keystream."""
        self._offset = (self._offset + len(data)) % 16
        return self._encryptor.update(data)

    def start_fresh_block(self) -> None:
        """Advance the keystream to the next AES block boundary.

        The receiver restarts each packet on a block boundary (UxPlay's
        ``aes_ctr_start_fresh_block``), so a sender must discard the remainder
        of the current block between packets or the keystreams diverge.
        """
        if self._offset:
            self._encryptor.update(b"\x00" * (16 - self._offset))
            self._offset = 0


def pack_mirror_frame(
    encryptor: MirrorEncryptor,
    header: MirrorHeader,
    payload: bytes,
) -> bytes:
    """Return `header.pack() || encryptor.encrypt(payload)`.

    The 128-byte mirror header is sent in cleartext; only the payload is
    AES-CTR-encrypted.
    """
    if header.payload_size != len(payload):
        raise ValueError(
            f"header.payload_size ({header.payload_size}) "
            f"!= len(payload) ({len(payload)})"
        )
    return header.pack() + encryptor.encrypt(payload)


def derive_stream_keys(aes_key: bytes, stream_connection_id: int) -> tuple:
    """Derive the per-stream mirror video AES key and IV.

    This is the screen-mirroring derivation. Static analysis of Apple's own
    ``AirPlaySupport`` (Phase 29) confirms the routine
    ``APSEncryptionUtilsDeriveAESKeySHA512ForScreen`` computes exactly this:
    ``key = SHA512("AirPlayStreamKey" + str(id) || secret)[:16]`` and
    ``iv  = SHA512("AirPlayStreamIV"  + str(id) || secret)[:16]`` (salt/label
    bytes first, then the 16-byte secret, two independent digests). The earlier
    belief that this was a disused "legacy" path was wrong -- the formula was
    always correct; only the input ``secret`` (here ``aes_key``) was unresolved.

    ``secret`` is a 16-byte FairPlay/CoreUtils session key, NOT a "master key"
    used directly. On the tvOS 26 path an ``encryptionSeed`` may also feed the
    derivation; that axis is explored via the id argument / salt separately.

    ``stream_connection_id`` is formatted **unsigned** (``%llu``). Real senders
    put a signed int64 in the SETUP plist which is frequently negative;
    formatting it as signed derives the wrong key.
    """
    if len(aes_key) != 16:
        raise ValueError(f"aes_key must be 16 bytes, got {len(aes_key)}")
    unsigned_id = stream_connection_id & 0xFFFFFFFFFFFFFFFF

    def _digest(label: str) -> bytes:
        hasher = hashlib.sha512()
        hasher.update(f"{label}{unsigned_id}".encode("utf-8"))
        hasher.update(aes_key)
        return hasher.digest()[:16]

    return _digest("AirPlayStreamKey"), _digest("AirPlayStreamIV")


def build_codec_metadata(width: int, height: int) -> bytes:
    """Build the 112-byte metadata tail of a codec (SPS/PPS) packet header.

    The receiver reads little-endian floats out of this tail
    (UxPlay ``raop_rtp_mirror_thread``)::

        offset 16/20  source width / height
        offset 40/44  width_source / height_source (a duplicate pair)
        offset 48/52  two further width/height values
        offset 56/60  the width / height actually used
        offset 64+    zero

    Offsets here are relative to the start of the 128-byte header, so the tail
    written by this function starts at header offset 16.
    """
    tail = bytearray(HEADER_LEN - HEADER_PREFIX_LEN)

    def put(header_offset: int, value: float) -> None:
        pos = header_offset - HEADER_PREFIX_LEN
        struct.pack_into("<f", tail, pos, float(value))

    for offset_w, offset_h in ((16, 20), (40, 44), (48, 52), (56, 60)):
        put(offset_w, width)
        put(offset_h, height)
    return bytes(tail)


def build_avcc(sps: bytes, pps: bytes) -> bytes:
    """Pack SPS/PPS into an AVCDecoderConfigurationRecord ("avcC").

    Codec packets (type ``PACKET_TYPE_CODEC``) do not carry raw NALs: the
    receiver parses an avcC record, reading the SPS length at offset 6 and the
    PPS length at ``sps_size + 9``.

    ``sps`` and ``pps`` are raw NAL units without start codes.
    """
    if len(sps) < 4:
        raise ValueError(f"SPS too short: {len(sps)} bytes")
    return b"".join(
        [
            b"\x01",  # configurationVersion
            sps[1:4],  # profile, compatibility, level from the SPS
            b"\xff",  # 0b111111 + lengthSizeMinusOne = 3
            b"\xe1",  # 0b111 + numOfSequenceParameterSets = 1
            struct.pack(">H", len(sps)),
            sps,
            b"\x01",  # numOfPictureParameterSets
            struct.pack(">H", len(pps)),
            pps,
        ]
    )


def derive_tcp_stream_key_iv(
    raw16: bytes, pair32: bytes, stream_connection_id: int, flag: bool = True
) -> tuple:
    """Return (key, iv) for a TCP-dialect media stream (video or audio).

    Verified byte-for-byte against the reference sender's ``DeriveKeyAndIV``
    (2026-08-24):

        secret16 = sha512(raw16 ‖ pair32)[:16]          (flag=True path)
        key      = sha512("AirPlayStreamKey"
                          + decimal(streamConnectionID) ‖ secret16)[:16]
        iv       = sha512("AirPlayStreamIV"
                          + decimal(streamConnectionID) ‖ secret16)[:16]

    Both use AES-128-CTR (128-bit BE counter starting at ``iv``, continuous
    keystream). ``stream_connection_id`` is the 64-bit id sent in that stream's
    SETUP — the VIDEO id for the type-110 stream, the AUDIO id for type-96.
    """
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    return stream_key_iv_from_secret(
        stream_secret16(raw16, pair32, flag), stream_connection_id
    )


def stream_secret16(raw16: bytes, pair32: bytes, flag: bool = True) -> bytes:
    """Return the 16 bytes both stream keys are labelled from.

    Split out because ``session.py`` logs this value next to the key it
    produced, and had been recomputing the expression to do it -- two copies
    of a derivation that must agree, with nothing checking that they did.
    Swapping the halves in the copy changed nothing observable, which is how
    it was found.

    ``flag`` is the session's 0xb0 bit: set, the pair-verify shared secret is
    folded in; clear, ``raw16`` is the secret as it stands.
    """
    return hashlib.sha512(raw16 + bytes(pair32)).digest()[:16] if flag else raw16


def stream_key_iv_from_secret(
    secret: bytes, stream_connection_id: int
) -> tuple[bytes, bytes]:
    """Label the secret with the stream id and hash it down to (key, iv).

    The tail of :func:`derive_tcp_stream_key_iv`, split out because
    ``session.py``'s ``MIRROR_KEYBUF_WINDOW`` sweep needs the same two labels
    over a secret it slices out of the SAP context -- a window that is not
    16 bytes, so it cannot go through the function above.

    ``"AirPlayStreamKey"`` and ``"AirPlayStreamIV"`` are cryptographic domain
    separators; a copy of them that drifted from this one would derive keys
    that no receiver agrees with, and would do it silently. They are spelled
    once, here.
    """
    sid = stream_connection_id & 0xFFFFFFFFFFFFFFFF
    key = hashlib.sha512(f"AirPlayStreamKey{sid}".encode() + secret).digest()[:16]
    iv = hashlib.sha512(f"AirPlayStreamIV{sid}".encode() + secret).digest()[:16]
    return key, iv
