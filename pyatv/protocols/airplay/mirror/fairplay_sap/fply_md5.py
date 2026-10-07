"""FPLY's hashing: MD5 with one modification.

The 144-byte key schedule of the device_tag cipher (see ``fply_pure``) is
nine MD5 compressions of the 20-byte SAP secret tail, differing only in a
round counter:

    secret(20)  ->  A(144)  ->  device_tag

Everything is MD5 by the book except that after step 31 the compression
shuffles its own message block, swapping word i with a word chosen from
the state, for i in 0..7:

    j = ([A, B, C, D][i & 3] >> (4 * (i >> 2))) & 15
    m[i], m[j] = m[j], m[i]

(airplay2-receiver's fairplay3.py has a swap of the same family, but there
both indices come from the state.)  The same compression, with a different
chaining value and salt, also joins the cipher's two passes; see ``link``.
"""

import struct

from .md5_constants import MD5_SHIFTS, MD5_T

__all__ = [
    "compress",
    "message_block",
    "round_keys",
    "link",
    "device_tag",
    "KEY_BASE",
    "SALT",
    "SECRET_MASK",
    "LENGTH_WORD",
    "ROUNDS",
    "LINK_IV",
    "LINK_SALT",
    "FINAL_XOR",
]

_M32 = 0xFFFFFFFF

# the chaining value the second block starts from -- the state after a
# constant first block, which is why it is a constant here
KEY_BASE = (0x1D4A4587, 0x92F39FCC, 0x1D87D836, 0xCDC86697)
# the 16 bytes that follow the secret in the message; the top byte of the
# first word is the round counter
SALT = (0x0057D8EE, 0xCBDEFBCF, 0x591C27A2, 0xCFBEB089)
# the secret is XORed with this before it is hashed
SECRET_MASK = 0x0D
# MD5's length field: 0x320 bits = 100 bytes, the whole two-block message
LENGTH_WORD = 0x20030000
ROUNDS = 9


def _rotate(value, count):
    return ((value << count) | ((value & _M32) >> (32 - count))) & _M32


def compress(state, block):
    """One MD5 compression, with FPLY's step-31 message shuffle."""
    a, b, c, d = state
    m = list(block)
    for i in range(64):
        if i < 16:
            f, g = (b & c) | (~b & d), i
        elif i < 32:
            f, g = (b & d) | (c & ~d), (5 * i + 1) % 16
        elif i < 48:
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, g = c ^ (b | (~d & _M32)), (7 * i) % 16
        mixed = _rotate((a + (f & _M32) + m[g] + MD5_T[i]) & _M32, MD5_SHIFTS[i])
        a, b, c, d = d, (mixed + b) & _M32, b, c
        if i == 31:
            words = (a, b, c, d)
            for k in range(8):
                j = (words[k & 3] >> (4 * (k >> 2))) & 15
                m[k], m[j] = m[j], m[k]
    return tuple((x + y) & _M32 for x, y in zip(state, (a, b, c, d)))


def message_block(secret, counter):
    """Return the padded 64-byte block for one round, as sixteen words.

    The secret goes in first as big-endian words, XORed with 0x0d; then
    the salt with the round counter in its top byte; then MD5's padding
    bit at byte 36 and the length of the whole 100-byte message.
    """
    if len(secret) != 20:
        raise ValueError(f"secret must be 20 bytes, got {len(secret)}")
    masked = bytes(byte ^ SECRET_MASK for byte in secret)
    words = list(struct.unpack(">5I", masked))
    words.append((counter << 24) | SALT[0])
    words.extend(SALT[1:])
    words.append(0x80000000)
    words.extend([0, 0, 0, 0])
    words.append(LENGTH_WORD)
    words.append(0)
    return words


def round_keys(secret):
    """Return the ten 16-byte round keys the cipher consumes, in its own order.

    Nine hashes, one per round, then the tenth key -- which is zero, its
    substitutions being a bare table lookup.  The cipher reads the
    schedule backwards, so round 0 takes the LAST hash.
    """
    schedule = [
        b"".join(
            word.to_bytes(4, "big")
            for word in compress(KEY_BASE, message_block(secret, r))
        )
        for r in range(ROUNDS)
    ]
    return schedule[::-1] + [bytes(16)]


# The two passes of the tag cipher are joined by one more compression of
# the same kind: the forward pass's 16-byte output, salted and padded,
# hashed from its own constant chaining value.  Without something here
# the backward pass would simply undo the forward one and the tag would
# be the constant block.
LINK_IV = (0xB9F3DCDC, 0xFBDC740B, 0x60F77F86, 0x51907216)
LINK_SALT = (0xAFC22BA0, 0x49EFFCFB, 0xFE67AC5E, 0xBEF6FBCB)
LINK_LENGTH_WORD = 0x00010000  # 0x100 bits = the 32-byte message


def link(ciphertext):
    """Return the backward pass's plaintext, from the forward pass's output."""
    if len(ciphertext) != 16:
        raise ValueError(f"expected 16 bytes, got {len(ciphertext)}")
    words = list(struct.unpack(">4I", ciphertext)) + list(LINK_SALT)
    words += [0x80000000, 0, 0, 0, 0, 0, LINK_LENGTH_WORD, 0]
    return b"".join(word.to_bytes(4, "big") for word in compress(LINK_IV, words))


# The backward pass ends with one more addition the substitution steps do
# not carry: a fixed constant XORed over all sixteen bytes.  (The tenth
# round key is zero; this is applied separately.)
FINAL_XOR = bytes.fromhex("67bc54c08e32851b50d2125f68b740a5")


def device_tag(initial, output):
    """Return the 20-byte tag, from the backward pass's plaintext and result.

    Four bytes of the result, then one more compression over the two of
    them together -- the same LINK_IV and the same 32-byte padding as the
    link between the passes.
    """
    words = list(struct.unpack(">4I", initial)) + list(struct.unpack(">4I", output))
    words += [0x80000000, 0, 0, 0, 0, 0, LINK_LENGTH_WORD, 0]
    digest = b"".join(word.to_bytes(4, "big") for word in compress(LINK_IV, words))
    return output[:4] + digest
