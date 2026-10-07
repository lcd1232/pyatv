"""SAPHash's fold, as the algorithm instead of as its trace.

`fold_read` used to say this window one Python statement per executed
instruction: 18,063 lines for one fold and 17,888 for the other, 2.8 MB
of file for a 16-byte answer.  Straight-line output proved the recovery
was exact; it was never the thing to ship.  This module is the same
window ROLLED, and every constant in it was measured rather than
guessed.

WHAT THE FOLD ACTUALLY IS.  Two pieces, run back to back:

  1. a DELTA BLOCK -- 548 byte-writes into the 16 bytes at
     `saphash.KEYOUT_AT - 0x1b4`, which the slice hides behind about
     17,000 named values of mixed boolean arithmetic.  548 is not a
     round number by accident: it is 16 + 11 + 20 + 35 + 210 + 256, and
     those are the six loops of `SAPHash.hash`'s tail in
     airplay2-receiver's published `fairplay3.py` -- fill with 0xe1,
     add eleven bytes of buffer3, XOR in buffer0, buffer2 and buffer1,
     then sixteen passes of a sixteen-byte scramble.  `delta` is those
     six loops, twenty lines, and it reproduces the block exactly.

  2. a MODIFIED MD5 -- `compress`, keyed by the running keyOut and fed
     the 64-byte staging block.  This is the same compression
     `fply_md5` already uses for the device_tag, with the same step-31
     message shuffle in spirit but NOT with the same rule: there the
     left index of each swap is a plain counter, here BOTH indices come
     from the state.

     And not one rule but TWO.  A handshake folds twice, and the two
     SAPHash calls run their own copies of the code: the second walks a
     chain of seven swaps along a path of eight state nibbles
     (`shuffle`), the first swaps five pairs of words that ten state
     nibbles name (`shuffle_pairs`).  Everything else about the two
     compressions -- state, message, all sixty-four rounds -- is the
     same, which is why one of them was mistaken for the other for as
     long as only two handshakes were on the bench.

  So one fold is

      keyOut[w] += delta[w]                      # four 32-bit adds
      keyOut     = compress(keyOut, staging)     # four more

  which is `saphash`'s "three stages of plain 128-bit adds" seen
  properly: the second and third stage are one MD5 compression, and its
  addend looked input-dependent only because MD5's own chaining value
  IS the keyOut it is adding to.

WHAT IS MEASURED HERE.  `GATHER`, the eleven buffer3 word indices, was
solved by intersecting the candidates over both handshakes and both
folds -- every entry pins to exactly one word.  Entry 3 is not a gather
at all: the slice stores 0x3d there outright, which is 0xe1 + 0x5c and
is the same hard-coded byte the published implementation has.  The
scramble taps and rotations, and `shuffle`, were fitted against the
port itself and then checked on 400 randomised states.

`shuffle_pairs` was measured rather than fitted.  The generated port of
the first fold is a pure function of memory, so the state it hands the
shuffle can be CHOSEN -- rounds 0..31 invert -- and the message it
shuffles is left in memory at 0x6fffc378 where it can be read straight
off.  Driving one nibble at a time says which nine of the state's
thirty-two nibbles the shuffle reads.  Giving those nine distinct
values, all of them inside the ten message words the padding does not
zero, then makes the whole permutation readable at once, and it comes
back as five disjoint transpositions.  60 random states pin the order
they are made in, which shows only where two nibbles collide.

The tenth nibble -- a's lowest, the left end of the first swap -- the
port cannot answer for.  It is 8 on both of the handshakes the port was
lifted from, so the lift folded that read to the literal 8, and a rule
that hard-codes 8 reproduces those two exactly and nothing else.  That
one was settled against six FURTHER handshakes, where it is 3, 5, 6, 7,
8 and 15.  Both shuffles are checked on all eight by
`test_saphash_fold`.

The published `i0_index` is [18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30]
and this one is [22, 26, 27, -, 5, 23, 33, 32, 10, 25, 31].  They are
not the same table and the difference is not a constant offset, so the
published one is a near miss rather than a different indexing of the
same thing.  Note 33: buffer3 is 132 bytes in `garble`'s layout and
word 33 is the four bytes just past it, which is why `delta` wants 136.
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
# ...except byte 3, which the slice stores outright.  0xe1 + 0x5c.
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

    Each step rewrites one byte from four -- itself and three taps back,
    the taps taken as unsigned 32-bit subtractions before the modulo,
    exactly as in the 210-byte scramble.  Sixteen is divisible by
    2**32's factors, so the unsigned wrap makes no difference here and
    the taps are plain (i - 7), (i - 37), (i - 177) modulo 16.
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
    """Apply the SECOND SAPHash call's step-31 message shuffle.

    Eight nibbles of the state -- the low two of each of A, B, C and D,
    in the order A B C D A B C D -- name eight message words, and the
    block is rotated along that path: seven swaps, each between
    consecutive names.  When the eight are distinct the net effect is
    one 8-cycle, m'[p[k]] = m[p[k+1]], which is how it was recognised.

    `fply_md5.compress` swaps `m[k]` with the k-th nibble instead, with
    a plain counter on the left.  That rule is wrong for this window --
    it disagrees on the first randomised state -- so the two are kept
    apart rather than merged.
    """
    path = [(state[k & 3] >> (4 * (k >> 2))) & 15 for k in range(8)]
    for k in range(7):
        left, right = path[k], path[k + 1]
        block[left], block[right] = block[right], block[left]


# the FIRST call's shuffle swaps five pairs of message words, each end
# named by one nibble of the state -- (word, nibble) of (a, b, c, d) as
# round 31 left it.  Measured, in this order, on eight handshakes.
SWAP_PAIRS = (
    ((0, 0), (1, 0)),  # a's low nibble with b's
    ((2, 0), (3, 0)),  # then c's low nibble with d's
    ((0, 1), (1, 1)),  # then a against b, nibble by nibble
    ((0, 2), (1, 2)),
    ((0, 3), (1, 3)),
)


def shuffle_pairs(block, state):
    """Apply the FIRST SAPHash call's step-31 message shuffle.

    Five swaps between message words the state names, NOT the chain
    `shuffle` walks -- the two SAPHash calls run their own copies of the
    code and their shuffles are different rules.  Eight of the state's
    nibbles pair off, a against b at each of the four nibble positions,
    and c's low nibble against d's is done second.

    The order only shows when two of the ten nibbles collide -- which is
    why it took a fit over 60 states rather than one reading -- but that
    is not a rare accident: on 90% of states some reordering of
    `SWAP_PAIRS` gives a different answer, so the order is as much of the
    rule as the pairs are.
    """
    for left, right in SWAP_PAIRS:
        i = (state[left[0]] >> (4 * left[1])) & 15
        j = (state[right[0]] >> (4 * right[1])) & 15
        block[i], block[j] = block[j], block[i]


def compress(state, block, step31=shuffle):
    """Run one modified-MD5 compression over *state* and sixteen words.

    Returns the pair (the message as the shuffle left it, the four-word
    result).  The message is returned as well because the slice keeps it in
    memory, and a port of the fold has to leave those words behind
    exactly as the compression did.

    *step31* is the shuffle to run after round 31: `shuffle` for the
    second SAPHash call, `shuffle_pairs` for the first.  Everything
    else about the two is the same compression.
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
