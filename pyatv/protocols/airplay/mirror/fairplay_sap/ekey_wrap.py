"""The 72-byte FairPlay ekey that carries a media secret to the receiver.

    ekey(sap36, raw16)
        = HEADER || mac(sap36, raw16) || wrap(sap36[0:16], raw16)
            36    +        20         +           16              = 72

``sap36`` is the 36-byte SAP secret of the handshake and ``raw16`` the
16-byte media secret being sent.  The two halves of the SAP secret are
independent: ``sap36[0:16]`` keys the wrap and only affects
``ekey[0x38:0x48]``; ``sap36[16:36]`` keys the MAC and only affects
``ekey[0x24:0x38]``.

The MAC is stock HMAC-SHA-1:

    ekey[0x24:0x38] = HMAC-SHA1(sap36[16:36] ^ 0x0d, HEADER || raw16)

keyed by the secret's tail under FPLY's usual 0x0d mask (the same mask
``fply_md5.SECRET_MASK`` applies).  The message is the ekey's constant
header followed by the *plaintext* ``raw16``, not the wrapped value that
goes on the wire.

The wrap is AES-128 with Apple's own tables: AES's key schedule and round
constants, ShiftRows, the MixColumns matrix over the Rijndael field and
ten rounds, but none of AES's S-boxes:

    state = raw16 ^ PLAINTEXT_XOR ^ K[0]
    for r in 0..8:
        state[p] = ROUND[r][p][ state[SHIFT_ROWS[p]] ]      substitute
        state[4c:4c+4] = MixColumns(COLUMN[state[4c:4c+4]]) ^ COLUMN_XOR
        state ^= K[r + 1]
    state[p] = LAST[p][ state[SHIFT_ROWS[p]] ] ^ K[10][p] ^ OUTPUT_XOR[p]

with ``K = key_schedule(sap36[0:16] ^ KEY_XOR)``, which uses a different
SubWord table for each of its ten round keys.  All sixty-three tables
(ten for the key schedule, four per full round, sixteen for the last
round, one before the column step) have the form ``T(x) = R[x ^ d] ^ e``
for one of three base tables; ``fply_wrap_tables`` stores the three bases
and a (class, in-xor, out-xor) triple per use.

The column step is MixColumns preceded by one more substitution
(``COLUMN``) plus a per-lane constant.  Every column step XORs in all four
lane constants, so only their XOR, ``COLUMN_XOR``, reaches the output.
This network has its own tables and shares none with ``fply_tables``.
"""

import hashlib
import hmac

from .fply_wrap_tables import (
    COLUMN,
    COLUMN_XOR,
    KEY_SBOXES,
    KEY_XOR,
    LAST,
    OUTPUT_XOR,
    PLAINTEXT_XOR,
    RCON,
    ROUNDS,
    SUBSTITUTIONS,
)

__all__ = [
    "HEADER",
    "ekey",
    "mac",
    "assemble",
    "split",
    "mac_key",
    "wrap",
    "key_schedule",
    "SHIFT_ROWS",
    "MAC_KEY_MASK",
    "MAC_AT",
    "WRAP_AT",
    "LIVE_CONTEXT",
    "DEAD_CONTEXT",
    "VECTORS",
]

# The ekey's constant 36 bytes: "FPLY" 01 02 01, a zero, the remaining
# length 0x3c big-endian, a 16-byte constant, then the wrapped-key
# length 0x10.  Identical on every handshake.
HEADER = bytes.fromhex(
    "46504c59010201000000003c00000000" + "99ef4c8b1d98dadd67c71a3c76a68da600000010"
)

# where the two session-dependent fields sit in the 72-byte ekey
MAC_AT = slice(0x24, 0x38)  # the 20-byte HMAC-SHA1
WRAP_AT = slice(0x38, 0x48)  # the 16-byte wrapped secret

# FPLY's usual byte mask, the one `fply_md5.SECRET_MASK` also applies
MAC_KEY_MASK = 0x0D

# The bytes of the 276-byte FairPlay context the ekey depends on: two
# integrity gates (any change yields an empty ekey) and the encrypted SAP
# secret.  DEAD_CONTEXT is never read.
LIVE_CONTEXT = (
    (0, 16, "gate"),
    (16, 48, "the encrypted SAP secret"),
    (256, 273, "gate"),
)
DEAD_CONTEXT = ((48, 256), (273, 276))


def mac_key(sap36: bytes) -> bytes:
    """The HMAC key: the SAP secret's 20-byte tail under the 0x0d mask."""
    if len(sap36) != 36:
        raise ValueError(f"sap36 must be 36 bytes, got {len(sap36)}")
    return bytes(byte ^ MAC_KEY_MASK for byte in sap36[16:36])


def mac(sap36: bytes, raw16: bytes) -> bytes:
    """Return ``ekey[0x24:0x38]``, the 20-byte HMAC-SHA-1 tag.

    Keyed by ``sap36[16:36] ^ 0x0d``, over the ekey's header followed by
    the *plaintext* secret -- not the ekey as it goes on the wire.
    """
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    return hmac.new(mac_key(sap36), HEADER + bytes(raw16), hashlib.sha1).digest()


# ---------------------------------------------------------------------------
# The wrap: AES-128 with Apple's tables
# ---------------------------------------------------------------------------

# AES's row permutation: byte 4c+r is fed from 4*((c + r) % 4)+r.  The
# tenth round uses it too, as AES does.
SHIFT_ROWS = [4 * ((c + r) % 4) + r for c in range(4) for r in range(4)]


def _expand(use):
    """One use of a substitution class, as a plain 256-byte table."""
    table, in_xor, out_xor = use
    return bytes(SUBSTITUTIONS[table][x ^ in_xor] ^ out_xor for x in range(256))


_ROUND_TABLES = [[_expand(use) for use in row] for row in ROUNDS]
_LAST_TABLES = [_expand(use) for use in LAST]
_KEY_TABLES = [_expand(use) for use in KEY_SBOXES]
_COLUMN_TABLE = _expand(COLUMN)
# x -> 2x in GF(2^8) mod the Rijndael polynomial, precomputed
_XTIME = bytes(((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1 for x in range(256))


def key_schedule(key16: bytes) -> list:
    """The eleven round keys -- AES's schedule with ten SubWord tables.

    ``w[i] = w[i-4] ^ w[i-1]``, except that every fourth word first
    goes through RotWord, then that round's own S-box, then AES's own
    round constant.  Which is AES exactly, apart from there being ten
    S-boxes where AES has one.
    """
    if len(key16) != 16:
        raise ValueError(f"key16 must be 16 bytes, got {len(key16)}")
    words = [list(key16[4 * i : 4 * i + 4]) for i in range(4)]
    for index in range(4, 44):
        word = list(words[index - 1])
        if index % 4 == 0:
            sbox = _KEY_TABLES[index // 4 - 1]
            word = [sbox[byte] for byte in word[1:] + word[:1]]
            word[0] ^= RCON[index // 4 - 1]
        words.append([a ^ b for a, b in zip(words[index - 4], word)])
    return [
        bytes(byte for word in words[4 * r : 4 * r + 4] for byte in word)
        for r in range(11)
    ]


def _mix_columns(state):
    """AES MixColumns over one more substitution, plus a constant."""
    for column in range(4):
        at = 4 * column
        q = [_COLUMN_TABLE[byte] for byte in state[at : at + 4]]
        for row in range(4):
            state[at + row] = (
                _XTIME[q[row]]
                ^ _XTIME[q[(row + 1) % 4]]
                ^ q[(row + 1) % 4]
                ^ q[(row + 2) % 4]
                ^ q[(row + 3) % 4]
                ^ COLUMN_XOR[row]
            )


def wrap(key16: bytes, raw16: bytes) -> bytes:
    """Return ``ekey[0x38:0x48]``, the wrapped secret.

    Ten rounds keyed by ``sap36[0:16]``; see the module docstring for the
    meaning of each constant.
    """
    if len(key16) != 16:
        raise ValueError(f"key16 must be 16 bytes, got {len(key16)}")
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    keys = key_schedule(bytes(a ^ b for a, b in zip(key16, KEY_XOR)))
    state = bytearray(a ^ b ^ c for a, b, c in zip(raw16, PLAINTEXT_XOR, keys[0]))
    for index, tables in enumerate(_ROUND_TABLES):
        state = bytearray(tables[p][state[SHIFT_ROWS[p]]] for p in range(16))
        _mix_columns(state)
        state = bytearray(a ^ b for a, b in zip(state, keys[index + 1]))
    return bytes(
        _LAST_TABLES[p][state[SHIFT_ROWS[p]]] ^ keys[10][p] ^ OUTPUT_XOR[p]
        for p in range(16)
    )


def ekey(sap36: bytes, raw16: bytes) -> bytes:
    """Return the 72-byte ekey that wraps *raw16* under the SAP secret."""
    return assemble(sap36, raw16, wrap(sap36[:16], raw16))


def assemble(sap36: bytes, raw16: bytes, wrapped16: bytes) -> bytes:
    """The 72-byte ekey, given its wrapped key from anywhere."""
    if len(wrapped16) != 16:
        raise ValueError(f"wrapped16 must be 16 bytes, got {len(wrapped16)}")
    return HEADER + mac(sap36, raw16) + bytes(wrapped16)


def split(blob: bytes) -> tuple:
    """``(header, mac, wrapped)`` for a 72-byte ekey."""
    if len(blob) != 72:
        raise ValueError(f"ekey must be 72 bytes, got {len(blob)}")
    return blob[:0x24], blob[MAC_AT], blob[WRAP_AT]


# (seed, sap36, raw16, ekey) known-answer vectors; `seed` only labels the
# handshake, and `sap36` is the SAP secret derived from its M2.
VECTORS = (
    (
        1001,
        "ae5be6678a6299aeb69466f6cf05e2eacaa08e7523ebe004eef65bb8cac1ee4d4f234edb",
        "657e13ec31113c7e8d3e06b78ac8d8b3",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000108dc89d389acad02decab206ad37c459bb2f1fb163e5745ce9603adbc"
        "41a73a2aef6f99de",
    ),
    (
        4242,
        "5a01e21c10f331c8a9b048034f8b46706191d7436082717471f2eb531b307acda61e10fc",
        "84a2db3ca97517dd27d544b0efd9d591",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000103ec7fd9073a8f26ec0541bc811da9e33b5861a1cc4af28014511ff16"
        "7ff26c8215e5d66d",
    ),
    (
        7,
        "31b51ed24fa228ba5d6550479dfc6d2d68220d173ad7f0d33f5fb9c7c948a2108f5d8e81",
        "b5769fa0f1483f95a90d9df2f130d60f",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "0000001041c28f61682ec7f1a490986b0e87d19282955a5b2eac417bd2308144"
        "553d3a4b9ff77399",
    ),
    (
        13,
        "e4b1e34a7b963be77bfaef8b1594556b155fd7fcf4eeb80088ab503bfd678d06ad506b5f",
        "4bd7b103ca9e33fe783e9d4625069ad5",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010ba30205fc2d6cb0e3433e87bcd0e087258df013934ff2ef7baaf2e22"
        "aa11792d5c377a4f",
    ),
    (
        99,
        "2c8869e79ae2f78165aed22404fc4c86c06091b9738427e935878035472b268a123516f9",
        "414c5b63bbc08adc05b9afaecd5a6c36",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010d48c1fc8533c2854aaac1524135070ded806fcc1632bebc35563583f"
        "e5ce2669e672564f",
    ),
    (
        555,
        "82286edb1700bb41c5517f4abaa7d372d3640946f775c92d0b933ee935a11c0f6ee3314a",
        "4cb97c534eabe0987f1c8298c2801dcd",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000104c581182585f90affecd715d3fef7a9f4907cbd1f7743b8ebf3be767"
        "92a6064850d4ecc5",
    ),
    (
        2024,
        "73aaa5bb9b0d53363ff366ec702f4708f4f3978cb70ab1a1531f43c18ccb8573d9d8b843",
        "066a3abb775f3dc611ece9ffa47ffadd",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010a84839741ea82583c92aca836697d7b34bf3931c7b7a5df2cd482983"
        "8022cbd044922d43",
    ),
    (
        12345,
        "2e62cf7e090d45e7d7240384bf02958df204b931a7425a3da5097cc2523ff2aa4be59f19",
        "922688fa428d42bc1fa8806998fbc595",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010819cba16229269ed446261f933d752fdcf44d3a23965b0856de375a2"
        "1c688e712ca2b7ce",
    ),
)
