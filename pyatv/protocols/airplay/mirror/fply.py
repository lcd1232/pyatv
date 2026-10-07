"""FPLY v3 handshake for AirPlay screen mirroring.

Implements the FairPlay handshake a mirror sender runs against current Apple
TVs: M1 is POSTed to ``/fp-setup``, the receiver answers with M2, M3 is POSTed
back and answered with M4, after which the sender wraps its media key into an
``ekey``.

This module holds the wire format and the state machine.  The cryptography
behind M3 and the ekey lives in
:mod:`pyatv.protocols.airplay.mirror.fairplay_sap`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import hashlib
import logging
import os
import struct
from typing import Any, Protocol

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import fairplay_sap

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

_FPLY_MAGIC = b"FPLY"
_FPLY_VERSION = 0x03

_MSGTYPE_M1 = 0x01
_MSGTYPE_M3 = 0x03

# M1[12]: device sub-type
_M1_DEVICE_SUBTYPE = 0x02

# M3[8:12], big-endian: body length after the 12-byte header (152 bytes)
_M3_PAYLOAD_LEN_FIELD = 0x98

# M3[0:144] is constant on purpose.  The 128 bytes at M3[16:144] are the
# sender's half of the FairPlay session; the only randomness that would reach
# them is the sender's RNG, and this block is what a sender whose RNG returns
# zero produces.  The receiver accepts it.  Real senders send a different
# block here (see test_fply_groundtruth.py) but the same aux header.
#
# The part that varies per session is the 20-byte device tag at M3[144:164],
# a function of M2 through the SAP secret (see :mod:`.fairplay_sap`).
M3_AUX_HEADER = bytes.fromhex("8f1a9c")
M3_CIPHER_BLOCK = bytes.fromhex(
    "eb7e9ea373b1c4479177bcf09470646c08a54c58c818fcf348ee4ff805bf751e"
    "87fbfbd9c05590451abbc093b56dd5e8a0fc7a6d33a86220dc85a8495cca6ff2"
    "11d1cbe465afd6ebb414d2b394e6f7f9616ce5a5be04338fab16e3ae3cea317a"
    "5196f5a108ce317417392db1069719b4113c94bc78269e26feea289674327389"
)

# ---------------------------------------------------------------------------
# M1 construction
# ---------------------------------------------------------------------------


def build_m1(mode_byte: int = 0) -> bytes:
    """Return the 16-byte M1 message for mode *mode_byte* (0–3).

    The layout is fixed apart from the mode byte.  Test vector::

        build_m1(0) == bytes.fromhex("46504c590301010000000004020000bb")
    """
    mode_byte &= 0x03
    msg = bytearray(16)
    msg[0:4] = _FPLY_MAGIC
    msg[4] = _FPLY_VERSION
    # Bytes 5-7: 01, message type, 00
    msg[5] = 0x01
    msg[6] = _MSGTYPE_M1
    msg[7] = 0x00
    # Bytes 8-11: body length, big-endian
    struct.pack_into(">I", msg, 8, 0x00000004)
    msg[12] = _M1_DEVICE_SUBTYPE
    msg[13] = 0x00
    msg[14] = mode_byte
    msg[15] = 0xBB
    return bytes(msg)


# ---------------------------------------------------------------------------
# M2 parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class M2Parsed:
    """Parsed M2 message from the server.

    M2 wire layout (142 bytes):

      M2[0:4]    = b"FPLY" magic
      M2[4]      = version (0x03)
      M2[5:8]    = 01 02 00  (fixed framing)
      M2[8:12]   = body length BE (0x00000082 = 130)
      M2[12]     = device subtype echo (0x02)
      M2[13]     = mode echo
      M2[14:142] = 128-byte cipher input
    """

    mode: int  # M2[13] (0–3)
    payload: bytes  # M2[14:142] — 128-byte cipher input
    raw: bytes  # Full 142-byte M2


def parse_m2(m2: bytes) -> M2Parsed:
    """Validate and parse a 142-byte M2 reply from the server.

    Raises :class:`ValueError` if the FPLY magic or message type is wrong,
    or if the message is truncated.
    """
    if len(m2) < 16:
        raise ValueError(f"M2 too short: {len(m2)} bytes (need >= 16)")
    if m2[0:4] != _FPLY_MAGIC:
        raise ValueError(f"M2 magic mismatch: got {m2[0:4].hex()!r}, expected 'FPLY'")
    if m2[4] != _FPLY_VERSION:
        _LOGGER.warning(
            "M2 version byte 0x%02x != expected 0x%02x; continuing",
            m2[4],
            _FPLY_VERSION,
        )
    if len(m2) < 142:
        raise ValueError(f"M2 truncated: {len(m2)} bytes (expected 142)")
    mode = m2[13] & 0x03
    # The cipher input starts after the subtype and mode bytes.
    payload = bytes(m2[14:142])
    return M2Parsed(mode=mode, payload=payload, raw=bytes(m2))


def _rotl32(value: int, amount: int) -> int:
    """Rotate left a 32-bit value."""
    value &= 0xFFFFFFFF
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# MD5 variant with a message shuffle
# ---------------------------------------------------------------------------

# Textbook MD5 K constants (per RFC 1321, floor(2^32 * |sin(i+1)|))
_MD5_K_TEXTBOOK: tuple[int, ...] = (
    0xD76AA478,
    0xE8C7B756,
    0x242070DB,
    0xC1BDCEEE,
    0xF57C0FAF,
    0x4787C62A,
    0xA8304613,
    0xFD469501,
    0x698098D8,
    0x8B44F7AF,
    0xFFFF5BB1,
    0x895CD7BE,
    0x6B901122,
    0xFD987193,
    0xA679438E,
    0x49B40821,
    0xF61E2562,
    0xC040B340,
    0x265E5A51,
    0xE9B6C7AA,
    0xD62F105D,
    0x02441453,
    0xD8A1E681,
    0xE7D3FBC8,
    0x21E1CDE6,
    0xC33707D6,
    0xF4D50D87,
    0x455A14ED,
    0xA9E3E905,
    0xFCEFA3F8,
    0x676F02D9,
    0x8D2A4C8A,
    0xFFFA3942,
    0x8771F681,
    0x6D9D6122,
    0xFDE5380C,
    0xA4BEEA44,
    0x4BDECFA9,
    0xF6BB4B60,
    0xBEBFBC70,
    0x289B7EC6,
    0xEAA127FA,
    0xD4EF3085,
    0x04881D05,
    0xD9D4D039,
    0xE6DB99E5,
    0x1FA27CF8,
    0xC4AC5665,
    0xF4292244,
    0x432AFF97,
    0xAB9423A7,
    0xFC93A039,
    0x655B59C3,
    0x8F0CCC92,
    0xFFEFF47D,
    0x85845DD1,
    0x6FA87E4F,
    0xFE2CE6E0,
    0xA3014314,
    0x4E0811A1,
    0xF7537E82,
    0xBD3AF235,
    0x2AD7D2BB,
    0xEB86D391,
)
_MD5_S_TEXTBOOK: tuple[int, ...] = (
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
)


def _md5_F(x: int, y: int, z: int) -> int:  # pylint: disable=invalid-name
    return ((x & y) | ((~x & 0xFFFFFFFF) & z)) & 0xFFFFFFFF


def _md5_G(x: int, y: int, z: int) -> int:  # pylint: disable=invalid-name
    return ((x & z) | (y & ((~z) & 0xFFFFFFFF))) & 0xFFFFFFFF


def _md5_H(x: int, y: int, z: int) -> int:  # pylint: disable=invalid-name
    return (x ^ y ^ z) & 0xFFFFFFFF


def _md5_I(x: int, y: int, z: int) -> int:  # pylint: disable=invalid-name
    return (y ^ (x | ((~z) & 0xFFFFFFFF))) & 0xFFFFFFFF


def m2_stepper_compress(  # pylint: disable=too-many-locals
    iv: bytes, message: bytes
) -> bytes:
    """Run one MD5 compression whose message words are shuffled half-way.

    Rounds 1 and 2 (steps 0-31) are textbook MD5.  Before round 3, five
    message words are swapped, at indices taken from the state (A, B, C, D)
    at that point; rounds 3 and 4 then run on the shuffled message, followed
    by the usual final add of *iv*.

    Args:
        iv: 16 bytes, the input state as 4 little-endian uint32s.
        message: 64 bytes, the message as 16 little-endian uint32s.

    Returns:
        16 bytes, the output state.
    """
    if len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")
    if len(message) != 64:
        raise ValueError(f"message must be 64 bytes, got {len(message)}")

    # RFC 1321's own names for the state words, message and tables.
    # pylint: disable=invalid-name
    A, B, C, D = struct.unpack("<4I", iv)
    A0, B0, C0, D0 = A, B, C, D
    M = list(struct.unpack("<16I", message))

    M32 = 0xFFFFFFFF
    K = _MD5_K_TEXTBOOK
    S = _MD5_S_TEXTBOOK

    # Textbook MD5 rounds 1 (F) and 2 (G), steps 0..31
    for i in range(32):
        if i < 16:
            f, g = _md5_F(B, C, D), i
        else:
            f, g = _md5_G(B, C, D), (5 * i + 1) % 16
        T = (A + f + M[g] + K[i]) & M32
        A, B, C, D = D, (B + _rotl32(T, S[i])) & M32, B, C

    # State-driven 5-swap permutation on M[]
    swaps = (
        (A & 0xF, B & 0xF),
        (C & 0xF, D & 0xF),
        ((B >> 4) & 0xF, (A >> 4) & 0xF),
        ((A >> 8) & 0xF, (B >> 8) & 0xF),
        ((B >> 12) & 0xF, (A >> 12) & 0xF),
    )
    for ia, ib in swaps:
        M[ia], M[ib] = M[ib], M[ia]

    # Textbook MD5 rounds 3 (H) and 4 (I), steps 32..63, on the shuffled M[]
    for i in range(32, 64):
        if i < 48:
            f, g = _md5_H(B, C, D), (3 * i + 5) % 16
        else:
            f, g = _md5_I(B, C, D), (7 * i) % 16
        T = (A + f + M[g] + K[i]) & M32
        A, B, C, D = D, (B + _rotl32(T, S[i])) & M32, B, C

    # Textbook MD5 final add
    return struct.pack(
        "<4I", (A0 + A) & M32, (B0 + B) & M32, (C0 + C) & M32, (D0 + D) & M32
    )


def m2_stepper2_compress(iv: bytes, message: bytes) -> bytes:
    """Run the SAPHash block compression over *message*.

    Delegates to :func:`.fairplay_sap.region_a.hash_block`.

    *iv* is the 16-byte chaining value; it is only length-checked, because
    the compression reads *message* alone and callers always pass
    ``message[0:16] == iv``.  *message* is 64 bytes.  Returns 16 bytes.
    """
    if len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")
    if len(message) != 64:
        raise ValueError(f"message must be 64 bytes, got {len(message)}")
    # pylint: disable=import-outside-toplevel
    from .fairplay_sap import region_a

    return region_a.hash_block(message)


# ---------------------------------------------------------------------------
# M3 construction
# ---------------------------------------------------------------------------


def build_m3(
    mode: int,
    cipher_payload: bytes = M3_CIPHER_BLOCK,
    device_tag: bytes = b"\x00" * 20,
    aux_header: bytes = M3_AUX_HEADER,
) -> bytes:
    """Assemble the 164-byte M3 message.

    M3 layout:

      M3[0:4]      = b"FPLY"
      M3[4]        = 0x03 (version)
      M3[5:8]      = 01 03 00
      M3[8:12]     = 00 00 00 98  (body length BE = 152)
      M3[12]       = mode echo (1 byte)
      M3[13:16]    = 3 aux header bytes (8f 1a 9c)
      M3[16:144]   = the 128-byte session block (:data:`M3_CIPHER_BLOCK`)
      M3[144:164]  = the 20-byte device tag, from
                     :func:`.fairplay_sap.device_tag`

    *cipher_payload* must be 128 bytes; it defaults to the constant block.
    *device_tag*    is the 20-byte field at M3[144:164].
    *aux_header*    is the 3-byte field at M3[13:16].

    A zero *device_tag* — the default — is rejected by the receiver; use
    :meth:`FPLYHandshake.consume_m2_build_m3`, which computes it.
    """
    if len(cipher_payload) != 128:
        raise ValueError(f"cipher_payload must be 128 bytes, got {len(cipher_payload)}")
    if len(device_tag) != 20:
        raise ValueError(f"device_tag must be 20 bytes, got {len(device_tag)}")
    if len(aux_header) != 3:
        raise ValueError(f"aux_header must be 3 bytes, got {len(aux_header)}")
    mode &= 0x03

    msg = bytearray(164)
    msg[0:4] = _FPLY_MAGIC
    msg[4] = _FPLY_VERSION
    msg[5] = 0x01
    msg[6] = _MSGTYPE_M3
    msg[7] = 0x00
    struct.pack_into(">I", msg, 8, _M3_PAYLOAD_LEN_FIELD)
    msg[12] = mode
    msg[13:16] = aux_header
    msg[16:144] = cipher_payload
    msg[144:164] = device_tag
    return bytes(msg)


# ---------------------------------------------------------------------------
# Legacy stream key derivation
# ---------------------------------------------------------------------------


def derive_stream_key(
    round0_block: bytes,
    m3_payload: bytes,
    label: bytes,
    stream_id: int,
) -> bytes:
    """Derive a 16-byte value as SHA-512 over M3 material, truncated.

    Returns the first 16 bytes of
    SHA-512(round0_block || m3_payload || label || stream_id as BE uint64),
    where *round0_block* is M3[16:32], *m3_payload* is M3[16:144] and
    *label* is a 16-byte ASCII label such as ``b"AirPlayStreamKey"``.

    This is not the key the mirror stream is encrypted with; that one is
    derived from the raw16 wrapped in the ekey and the pair-verify shared
    secret by ``framing.derive_tcp_stream_key_iv``.
    """
    if len(round0_block) != 16:
        raise ValueError(f"round0_block must be 16 bytes, got {len(round0_block)}")
    if len(m3_payload) != 128:
        raise ValueError(f"m3_payload must be 128 bytes, got {len(m3_payload)}")
    if len(label) != 16:
        raise ValueError(f"label must be 16 bytes, got {len(label)}")

    h = hashlib.sha512()
    h.update(round0_block)
    h.update(m3_payload)
    h.update(label)
    h.update(stream_id.to_bytes(8, "big"))
    return h.digest()[:16]


# ---------------------------------------------------------------------------
# Handshake state machine
# ---------------------------------------------------------------------------


class _State(Enum):
    INIT = auto()
    AWAITING_M2 = auto()
    DONE = auto()


class FPLYHandshake:
    """FPLY v3 handshake state machine (M1 → M2 ← M3 →).

    Mirrors the interface shape of
    :class:`~pyatv.protocols.airplay.mirror.fairplay.MFiSAPHandshake` so
    callers can swap between the two implementations.
    """

    # Labels for derive_stream_key
    LABEL_STREAM_KEY: bytes = b"AirPlayStreamKey"
    LABEL_STREAM_IV: bytes = b"AirPlayStreamIV "

    def __init__(self, mode_byte: int = 1) -> None:
        """Start an FPLY v3 handshake in mode *mode_byte* (0-3)."""
        # Mode 1 is the mode this implementation has been tested with.
        self._mode_byte = mode_byte & 0x03
        self._state = _State.INIT
        self._m3_payload: bytes | None = None
        self._sap36: bytes = b""
        self._sap_context: bytes = b""
        self._stream_aes_key: bytes | None = None
        self._stream_aes_iv: bytes | None = None
        # The media secret we choose and package into the ekey.
        self.chosen_raw16: bytes = b""
        # The audio SETUP needs an ekey too; it wraps the same raw16 as the
        # video one, so the same blob is used.
        self.audio_ekey: bytes = b""
        self.ekey: bytes = b""
        # The M4 body, when a runner collected it for us.
        self.m4: bytes = b""

    def consume_m2_build_m3(self, m2: bytes) -> bytes:
        """Parse M2, derive the SAP secret, return the 164-byte M3 body.

        The device tag at M3[144:164] is the session-varying part and comes
        from :func:`.fairplay_sap.device_tag`; the 144 bytes in front of it
        are constant (see :data:`M3_CIPHER_BLOCK`).  The 36-byte SAP secret
        this derives is kept for :meth:`finish_ekey`.
        """
        if self._state is not _State.AWAITING_M2:
            raise RuntimeError(f"consume_m2_build_m3 called in state {self._state}")

        parsed = parse_m2(m2)
        _LOGGER.debug(
            "M2 parsed: mode=%d, payload=%d bytes", parsed.mode, len(parsed.payload)
        )
        if parsed.mode != 0x01:
            _LOGGER.warning(
                "M2 mode is 0x%02x; only mode 0x01 was verified against a "
                "receiver — echoing it into M3 and continuing",
                parsed.mode,
            )

        self._sap36 = fairplay_sap.sap_secret(parsed.raw)
        tag = fairplay_sap.device_tag(self._sap36)
        m3 = build_m3(parsed.mode, M3_CIPHER_BLOCK, tag, M3_AUX_HEADER)
        _LOGGER.debug("M3 built: device_tag=%s", tag.hex())

        self._m3_payload = M3_CIPHER_BLOCK
        self._sap_context = fairplay_sap.context_after_m3(self._sap36)
        # Not used by the media path (see derive_stream_key).  Since
        # M3[16:144] is constant, these are the same in every session.
        self._stream_aes_key = derive_stream_key(
            M3_CIPHER_BLOCK[:16], M3_CIPHER_BLOCK, self.LABEL_STREAM_KEY, 0
        )
        self._stream_aes_iv = derive_stream_key(
            M3_CIPHER_BLOCK[:16], M3_CIPHER_BLOCK, self.LABEL_STREAM_IV, 0
        )

        self._state = _State.DONE
        return m3

    def build_m3_stateful(self, m2: bytes) -> bytes:
        """Alias of :meth:`consume_m2_build_m3`."""
        return self.consume_m2_build_m3(m2)

    def finish_ekey(self, m4: bytes, raw16: bytes | None = None) -> bytes:
        """Process M4, choose a raw16, and package it into the ekey blob.

        Returns the ekey.  Also sets :attr:`chosen_raw16`, :attr:`ekey` and
        :attr:`sap_context`.  The receiver unwraps the ekey back to *raw16*
        and derives the video key from it, so any 16-byte *raw16* works as
        long as we encrypt with the same one.  A random one is chosen unless
        *raw16* is given.

        *m4* carries nothing we need — it echoes M3's device tag back for
        verification — so it is only checked, not consumed.
        """
        if not self._sap36:
            raise RuntimeError("consume_m2_build_m3 must be called first")
        if m4 and len(m4) >= 32:
            echoed = bytes(m4[-20:])
            ours = fairplay_sap.device_tag(self._sap36)
            if echoed != ours:
                _LOGGER.warning(
                    "M4 echoes device_tag %s, we sent %s",
                    echoed.hex(),
                    ours.hex(),
                )
        raw16 = raw16 or os.urandom(16)
        if len(raw16) != 16:
            raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")

        self.chosen_raw16 = raw16
        self.ekey = fairplay_sap.ekey(self._sap36, raw16)
        return self.ekey

    def build_m1(self) -> bytes:
        """Return the 16-byte M1 body to POST to ``/fp-setup``."""
        if self._state is not _State.INIT:
            raise RuntimeError(f"build_m1 called in state {self._state}")
        self._state = _State.AWAITING_M2
        return build_m1(self._mode_byte)

    @property
    def sap_secret(self) -> bytes:
        """The 36-byte FairPlay SAP secret derived from M2."""
        if not self._sap36:
            raise RuntimeError("handshake not complete")
        return self._sap36

    @property
    def sap_context(self) -> bytes:
        """The 276-byte FairPlay context after M3 (ctx[8:44] = the SAP secret)."""
        return self._sap_context

    @property
    def stream_aes_key(self) -> bytes:
        """16-byte key from :func:`derive_stream_key` (after M3 is built)."""
        if self._stream_aes_key is None:
            raise RuntimeError("handshake not complete")
        return self._stream_aes_key

    @property
    def stream_aes_iv(self) -> bytes:
        """16-byte IV from :func:`derive_stream_key` (after M3 is built).

        Not the IV the mirror stream uses; see :func:`derive_stream_key`.
        """
        if self._stream_aes_iv is None:
            raise RuntimeError("handshake not complete")
        return self._stream_aes_iv

    @property
    def m3_payload(self) -> bytes:
        """The 128-byte session block that was placed in M3[16:144]."""
        if self._m3_payload is None:
            raise RuntimeError("handshake not complete")
        return self._m3_payload


# ---------------------------------------------------------------------------
# HTTP helper — async handshake runner
# ---------------------------------------------------------------------------


class HttpConnection(Protocol):
    """Minimal protocol for the HTTP connection used by the handshake runner."""

    async def send_and_receive(
        self,
        method: str,
        uri: str,
        **kwargs: Any,
    ) -> Any:
        """Send an HTTP request and return the response."""


USER_AGENT = "AirPlay/550.10"


async def run_fply_handshake(
    connection: HttpConnection,
    mode_byte: int = 3,
) -> FPLYHandshake:
    """Execute the FPLY v3 handshake over an existing HTTP connection.

    Posts M1 to ``/fp-setup``, receives M2, posts M3 to ``/fp-setup``,
    and expects HTTP 200 for both.  The response to M3 is M4; it is stored on
    the handshake and a media key is wrapped into :attr:`FPLYHandshake.ekey`
    (and :attr:`FPLYHandshake.audio_ekey`) before returning.

    ``mode_byte`` 3 is what macOS senders use; with it M1 is byte-identical
    to theirs.

    Both requests carry ``X-Apple-HKP: 3`` and ``X-Apple-ET: 32`` (FairPlay
    encryption type).
    """
    sm = FPLYHandshake(mode_byte=mode_byte)

    m1 = sm.build_m1()
    _LOGGER.debug("FPLY: sending M1 (%d bytes) to /fp-setup", len(m1))
    resp1 = await connection.send_and_receive(
        "POST",
        "/fp-setup",
        user_agent=USER_AGENT,
        content_type="application/octet-stream",
        headers={"X-Apple-HKP": "3", "X-Apple-ET": "32"},
        body=m1,
    )
    if resp1.code != 200:
        raise exceptions.ProtocolError(f"/fp-setup (M1) returned HTTP {resp1.code}")

    m2_bytes = (
        resp1.body
        if isinstance(resp1.body, (bytes, bytearray))
        else bytes(resp1.body, "latin-1")
    )
    _LOGGER.debug("FPLY: received M2 (%d bytes)", len(m2_bytes))

    m3 = sm.consume_m2_build_m3(m2_bytes)
    _LOGGER.debug("FPLY: sending M3 (%d bytes) to /fp-setup", len(m3))

    resp2 = await connection.send_and_receive(
        "POST",
        "/fp-setup",
        user_agent=USER_AGENT,
        content_type="application/octet-stream",
        headers={"X-Apple-HKP": "3", "X-Apple-ET": "32"},
        body=m3,
    )
    if resp2.code != 200:
        raise exceptions.ProtocolError(f"/fp-setup (M3) returned HTTP {resp2.code}")

    m4_body = resp2.body
    if isinstance(m4_body, (bytes, bytearray)):
        sm.m4 = m4_body
    else:
        # A str body is latin-1 text the HTTP layer already decoded.
        sm.m4 = m4_body.encode("latin-1") if m4_body else b""
    _LOGGER.debug("FPLY handshake complete: M4 is %d bytes", len(sm.m4))
    # A mirror session needs `ekey` for its video SETUP and `audio_ekey` for
    # the audio SETUP, which must precede RECORD (otherwise the receiver
    # answers 455 Method Not Valid In This State).  Both wrap the same raw16.
    sm.finish_ekey(sm.m4)
    sm.audio_ekey = sm.ekey
    _LOGGER.debug("FPLY: ekey wrapped (%d bytes)", len(sm.ekey))
    return sm
