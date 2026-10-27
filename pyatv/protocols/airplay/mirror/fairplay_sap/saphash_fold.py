"""SAPHash's fold: the 16-byte delta block and the modified MD5.

Each 64-byte block of a SAPHash call updates the running four-word keyOut
twice -- the order of the two differs between calls, see
:func:`.region_a.run`:

    keyOut[w] += delta[w]                  # four 32-bit adds
    keyOut     = compress(keyOut, block)   # modified MD5

:func:`delta` is the tail of ``SAPHash.hash`` in airplay2-receiver's
``fairplay3.py``: fill 16 bytes with 0xe1, add eleven bytes gathered from
buffer3, XOR in buffer0, buffer2 and buffer1, then sixteen passes of a
sixteen-byte scramble.  The gather table is not the published ``i0_index``
([18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30]) and the difference is not a
constant offset.  Word 33 is the four bytes just past the 132-byte buffer3,
which is why :func:`delta` wants 136.

:func:`compress` is MD5 with a message shuffle after round 31, and the two
SAPHash calls of a handshake shuffle differently: the first with
:func:`shuffle_pairs`, the second with :func:`shuffle`.  In both, each swap
takes both of its indices from the state, unlike the device-tag MD5 in
``fply_md5`` whose left index is a plain counter.
"""

from .md5_constants import MD5_SHIFTS, MD5_T

__all__ = [
    "compress",
    "delta",
    "scramble",
    "shuffle",
    "shuffle_pairs",
    "GATHER",
    "HARD_BYTE",
    "FILL",
    "PASSES",
    "TAPS",
    "ROTATES",
    "SWAP_PAIRS",
]

_M32 = 0xFFFFFFFF

# every byte of the delta block starts here
FILL = 0xE1
# ...except byte 3, which is stored outright: 0xe1 + 0x5c, the same
# hard-coded byte as in the published implementation.
HARD_BYTE = 0x3D
# the eleven buffer3 WORDS the block adds in, one per output byte; the
# `None` is the byte that is stored rather than gathered
GATHER = (22, 26, 27, None, 5, 23, 33, 32, 10, 25, 31)
# the sixteen-byte scramble that finishes a delta block: sixteen passes
# of sixteen steps, each step folding three earlier bytes into one
PASSES = 16
TAPS = (7, 0, 37, 177)
ROTATES = (1, 0, 6, 5)


def _rol8(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _rotate32(value, count):
    return ((value << count) | ((value & _M32) >> (32 - count))) & _M32


def scramble(key, passes=PASSES):
    """Apply the delta block's finisher: `passes` sweeps over sixteen bytes.

    Each step rewrites one byte from itself and three earlier bytes.  The
    taps are unsigned 32-bit subtractions as in the 210-byte scramble, but
    since 16 divides 2**32 the wrap makes no difference and they are plain
    (i - 7), (i - 37), (i - 177) modulo 16.
    """
    key = bytearray(key)
    for _pass in range(passes):
        for i in range(16):
            key[i] = (
                _rol8(key[(i - TAPS[0]) % 16], ROTATES[0])
                ^ key[i]
                ^ _rol8(key[(i - TAPS[2]) % 16], ROTATES[2])
                ^ _rol8(key[(i - TAPS[3]) % 16], ROTATES[3])
            )
    return bytes(key)


def delta(buffer0, buffer1, buffer2, buffer3):
    """Return the 16-byte block a fold adds into keyOut.

    `buffer3` must be at least 136 bytes: the gather reads word 33.
    """
    if len(buffer3) < 4 * max(w for w in GATHER if w is not None) + 4:
        raise ValueError("buffer3 must reach word 33")
    key = bytearray([FILL] * 16)
    for i, word in enumerate(GATHER):
        if word is None:
            key[i] = HARD_BYTE
        else:
            key[i] = (key[i] + buffer3[4 * word]) & 0xFF
    for source in (buffer0, buffer2, buffer1):
        for i, byte in enumerate(source):
            key[i % 16] ^= byte
    return scramble(key)


def shuffle(block, state):
    """Apply the second SAPHash call's step-31 message shuffle.

    Eight nibbles of the state -- the low two of each of A, B, C and D,
    in the order A B C D A B C D -- name eight message words, and the
    block is rotated along that path: seven swaps, each between
    consecutive names.  When the eight are distinct the net effect is
    one 8-cycle, m'[p[k]] = m[p[k+1]].
    """
    path = [(state[k & 3] >> (4 * (k >> 2))) & 15 for k in range(8)]
    for k in range(7):
        left, right = path[k], path[k + 1]
        block[left], block[right] = block[right], block[left]


# The first call's shuffle swaps five pairs of message words, each end
# named by one nibble of the state -- (word, nibble) of (a, b, c, d) as
# round 31 left it.  The order matters.
SWAP_PAIRS = (
    ((0, 0), (1, 0)),  # a's low nibble with b's
    ((2, 0), (3, 0)),  # then c's low nibble with d's
    ((0, 1), (1, 1)),  # then a against b, nibble by nibble
    ((0, 2), (1, 2)),
    ((0, 3), (1, 3)),
)


def shuffle_pairs(block, state):
    """Apply the first SAPHash call's step-31 message shuffle.

    Five swaps between message words the state names (`SWAP_PAIRS`): a
    against b at each of the four nibble positions, with c's low nibble
    against d's done second.  The order only shows when two of the ten
    nibbles collide, but that happens on most states, so it is part of
    the rule.
    """
    for left, right in SWAP_PAIRS:
        i = (state[left[0]] >> (4 * left[1])) & 15
        j = (state[right[0]] >> (4 * right[1])) & 15
        block[i], block[j] = block[j], block[i]


def compress(state, block, step31=shuffle):
    """Run one modified-MD5 compression over *state* and sixteen words.

    Returns the pair (the message as the shuffle left it, the four-word
    result).

    *step31* is the shuffle to run after round 31: `shuffle` for the
    second SAPHash call, `shuffle_pairs` for the first.
    """
    a, b, c, d = state
    message = list(block)
    for i in range(64):
        if i < 16:
            mix, index = (b & c) | (~b & d), i
        elif i < 32:
            mix, index = (b & d) | (c & ~d), (5 * i + 1) % 16
        elif i < 48:
            mix, index = b ^ c ^ d, (3 * i + 5) % 16
        else:
            mix, index = c ^ (b | (~d & _M32)), (7 * i) % 16
        turned = _rotate32(
            (a + (mix & _M32) + message[index] + MD5_T[i]) & _M32, MD5_SHIFTS[i]
        )
        a, b, c, d = d, (turned + b) & _M32, b, c
        if i == 31:
            step31(message, (a, b, c, d))
    return message, [(x + y) & _M32 for x, y in zip(state, (a, b, c, d))]
