"""SAPHash's garble step.

`garble` runs at the end of every SAPHash round.  It finishes the round's
scramble of the 210-byte ring b1, then mixes b1 through three fixed tables
to produce 34 output bytes in b3, stirring b0, b1 and b2 as it goes.

It is written for the one way it is ever called: b0, b2 and b4 arrive
holding FairPlay's tables (`saphash.CONSTANT_20`, `CONSTANT_35` and
`CONSTANT_21`; `region_a.hash_block` hands over fresh copies every time),
so the only real input is b1.  Everything the tables alone decide is
written as the value it always has, with one exception: a store that
stirs a cell into something new is written as an update of that cell --
`b2[13] ^= b4_w0`, not `b2[13] = b4_w0 ^ 0x3f` -- because the byte it
would fold in is the cell's own.  Called with anything else in b0, b2 or
b4 this computes something else.

    b0   20 bytes   table, stirred
    b1  210 bytes   the scramble ring, stirred
    b2   35 bytes   table, stirred
    b3  133 bytes   output: the low byte of each of 34 32-bit words
    b4   21 bytes   table, read only

b0, b1, b2 and b4 are indexed modulo their own length, which is how garble
picks a table cell from a computed byte, and every store keeps only the
low byte; `_Ring` does both and `_Words` does the second, so the
arithmetic below says only what it computes.  A word that is used again
as an index is kept to a byte where it is computed -- with `& 0xff`,
unless its operands already make it one; a store needs no mask, and nor
does a word whose only readers mask it again.

Names.  `wordK` is output word K.  `b0_181` is the cell `b0[b1[181]]`, read
where it stands because a later store to b0 could change that cell before
the value is used; the b2 names are the same.  `b4_w5` is `b4[word5]` --
b4 never changes, so the b4 names, and `b2_w1`, are just reads used more
than once.  `b0_mixed` is the one named cell whose index is computed from
several values.  A number on any other name says which output word it
feeds, directly or through other temporaries -- the first, when it feeds
several; a name with no number feeds only stores back into b0, b1 and b2.
No temporary is bound twice.  A store that a later one overwrites is not
dead: any read at a computed index in between can land on that cell.

Numbers.  Cell indices and arithmetic are decimal; bit patterns, and the
bytes stored as constants, are hex.

Only words 5, 10, 22, 23, 25, 26, 27, 31, 32 and 33 reach FairPlay's key
(`saphash_fold.GATHER`); the fold then xors in the whole of b0, b1 and b2.
The other words, and the stores no word reads back, matter only that way.

The published playfair `hand_garble.c` (copied into shairplay, RPiPlay,
UxPlay and others) computes the same b0, b1 and b2.  Its output words are
numbered differently from 13 onward, and the ones that do not feed
playfair's key were never checked there.
"""


class _Ring:
    """A byte buffer indexed modulo its length, storing the low byte."""

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def __getitem__(self, index):
        return self.data[index % self.size]

    def __setitem__(self, index, value):
        self.data[index % self.size] = value & 0xFF


class _Words:
    """b3 as 32-bit words; garble writes only the low byte of each."""

    def __init__(self, data):
        self.data = data

    def __setitem__(self, index, value):
        self.data[4 * index] = value & 0xFF


def _rotl8(value, count):
    """Rotate a byte left -- SAPHash's own primitive."""
    value &= 0xFF
    return (value << count | value >> (8 - count)) & 0xFF


def _rotl8_or_zero(value, count):
    """Rotate a byte left by `count & 7` -- but a count of 0 gives 0.

    The original spells this as two shifts xored together, and at a count
    of 0 the two copies coincide and cancel.  The hole is reached at every
    call site, so it is part of the function, not a quirk to smooth over.
    """
    count &= 7
    return _rotl8(value, count) if count else 0


def _rotr8_or_zero(value, count):
    """Rotate a byte right by `count & 7` -- with the same hole at 0."""
    return _rotl8_or_zero(value, -count)


def _window_or_zero(value, count):
    """Return the byte repeated in a 16-bit word, shifted right by `8 - count`.

    0 when `count & 7` is 0.  This is `_rotl8_or_zero` without the final
    byte mask: its callers use the result as an index into a 21-byte ring,
    so the bits above 7 change which cell it picks.
    """
    count &= 7
    return (value & 0xFF) * 0x101 >> (8 - count) if count else 0


def _majority(a, b, c):
    """Bitwise majority: each output bit is the one two of the three share."""
    return a & b | a & c | b & c


def _choose(mask, off, on):
    """Take each bit from *on* where *mask* is set, from *off* where not."""
    return off & ~mask | on & mask


def _tap(cursor, back):
    """Return the scramble tap *back* bytes behind *cursor* on the 210-byte ring.

    The subtraction is unsigned 32-bit and happens before the modulo:
    cursor 0, back 155 is 101, because 0xffffff65 % 210 is 101, where
    Python's own `%` would give 55.  A real call starts at cursor 789 and
    never gets near that; the cursor is a parameter so other starting
    points behave as the original does.
    """
    return (cursor - back & 0xFFFFFFFF) % 210


def _finish_scramble(b1, cursor):
    """Run the last 51 of the round's 840 scramble passes over the b1 ring.

    Each pass is `saphash.scramble`'s step.  The cursor arrives at 789 in
    every recorded call and the loop stops at 840, `saphash.STEPS`.
    """
    for head in range(cursor, cursor + 51):
        at = _tap(head, 0)
        y = b1[_tap(head, 57)]
        z = b1[_tap(head, 13)]
        x = b1[_tap(head, 155)]
        b1[at] = _rotl8(y, 5) + (_rotl8(z, 3) ^ b1[at]) - _rotl8(x, 7)


def garble(b0, b1, b2, b3, b4, cursor=789):
    """Fill the 34 output words of b3, stirring b0, b1 and b2, in place.

    *cursor* is where the round's scramble has got to; every real call
    passes 789.
    """
    # One straight-line pass, as the original is: splitting it would only
    # hide the order of the stores, which is the point.
    # pylint: disable=too-many-locals,too-many-statements
    b0, b1, b2, b4 = _Ring(b0), _Ring(b1), _Ring(b2), _Ring(b4)
    out = _Words(b3)
    _finish_scramble(b1, cursor)

    # There are no sections: b0 and b2 are read at computed indices
    # throughout, so almost every statement is pinned between stores that
    # could alias it.  word0, word5, word20, word10 and word1 are the
    # values read most widely in what follows.
    picked = _choose(0xA3, b1[64], b1[99] // 3)
    b2[12] += picked & b4[_window_or_zero(b4[b1[206]], 4)]
    b1[4] = (b1[99] // 5) ** 2 * 2
    b2[34] = 0xB8
    b1[153] ^= b1[190] * b2[b1[203]] ** 2
    b0[3] = 0x03 if b4[b1[205]] & 0x20 else 0x13
    b0[16] = 0x93
    b0[13] = 0x62
    b1[33] -= b4[b1[36]] & 0xF6
    b0_181 = b0[b1[181]]
    b2_67 = b2[b1[67]]
    b2[12] = 0x07
    b1[2] -= 64
    b0[19] = b4[b1[58]]
    word0 = 92 - b2[b1[32]] & 0xFF
    out[0] = word0

    word1 = b2[b1[15]] + 158 & 0xFF
    out[1] = word1

    b1[34] += b4[word1] // 5
    b0[19] += ~(b0[word1] >> 1) & 0xE6
    b1[15] ^= (_rotr8_or_zero(b1[72], b4[b1[190]]) - b4[b1[126]] * 3) * 3
    b0[15] ^= b2[b1[181]] ** 3
    b2[4] ^= b1[202] // 3
    b2[1] += _majority(92 - b0[word0], ~b1[105], 0xC6) ** 3
    b4_92 = b4[b1[92]]
    b0[19] ^= (0xE0 | b4_92 & 0x1B) * b2[b1[41]] // 3
    b1[140] += _rotr8_or_zero(0x5C, b1[5])
    b2[12] += _majority(~(b1[4] ^ b2[b1[12]]), b1[182], 0xC0)
    b1[36] += 125
    inner = _majority(b0[15], b1[138], 0x4A)
    b1[124] = _rotl8(_majority(b0[b1[43]], inner, 0x5F), 4)
    word2 = ~(b4[b1[68]] * 2 & b0[word1]) & 0x4C
    out[2] = word2

    half3 = (b1[177] + b4[b1[79]]) >> 1
    word3 = 222 - _majority(b1[148] * 3 // 5, half3, b2[1]) & 0xFF
    out[3] = word3

    b2[16] += (b0[word1] | b2[word0] & 0x97 | 8) - (_rotl8(b1[33], 2) | 0x80)
    b0[14] ^= b2[word3]
    fifth = _choose(0x7C, b0[b1[208]], b0[b1[164]]) // 5
    b1[19] += _majority(fifth, _rotl8_or_zero(b4[b0[b1[201]]], b2[b1[112]] * 2), 0x25)
    b2[8] = (0, 0x46, 0xC8, 0x46)[b4[b1[45]] & 3]
    b1[190] = 0x38
    b2[8] ^= word0
    b1[53] = 255 - (b0[b1[83]] | 0xCC) // 5
    b0[13] += b0[b1[41]]
    b0[10] = _majority(b2[word0], b1[2], word3) // 15
    word4 = _majority(b2[word2], 0x38 | b4[b1[2]] & 4, 0x2A) ** 2 + 114 & 0xFF
    out[4] = word4

    word5 = 206 - word4  # word4 takes seven values, at most 182
    out[5] = word5
    word6 = b1[151]
    out[6] = word6

    b4_w0 = b4[word0]
    b2[13] ^= b4_w0
    word7 = _majority(b2[b1[179]] - 38, word3, 0xB1) ** 2 + 70
    out[7] = word7

    word8 = word7 + 22 & 0xFF
    out[8] = word8

    mix11 = _majority((word0 & 0x4A) + word5, b4_w0 ^ 0xFF, 0x79) ^ 0xA6
    b1[47] ^= b2[b1[89]] + _majority(mix11, word0, 4)
    # b0[3] is still 0x03 or 0x13 here, so only bits 0, 1 and 4 of `on` count
    word9 = _choose(b0[3], b2_67, 0x11 | b0_181 >> 6) - 15 & 0xFF
    out[9] = word9

    b1[123] ^= 0xDD
    b2_w1 = b2[word1]
    word10 = b4_w0 // 3 - _majority(word0 & 0xAA | 0x54, word6, 0x36) - b2_w1 & 0xFF
    out[10] = word10

    word11 = ((word0 & 0xCA) >> 1) ^ 0xED ^ mix11
    out[11] = word11

    low12 = b2_w1 & 0x1B
    out[12] = low12 ^ 0x7F
    out[13] = low12 * 2
    out[14] = 0x1B  # b4[18], straight from the table

    vote15 = _majority(word6, word10, 0xB1)
    blend15 = b4_w0 & 0x4D | 0xB0
    out[15] = (blend15 | vote15) & 0xF7
    # Words 16 to 18 are three views of the table cell b2[19] = 0xb1: the
    # byte itself, under 0xfc xored with 0x71, and doubled under 0xe0.
    out[16] = 0xB1
    out[17] = 0xC1
    out[18] = 0x60
    out[19] = word0 % 21  # the b4 cell b4_w0 was read from

    word20 = word1 + _choose(0x1B, _majority(blend15, vote15, 0xC7), b2_w1) & 0xFF
    out[20] = word20

    b2[33] ^= b1[26]
    b1[106] ^= word5 ^ 0x85
    b2[30] = (word20 // 3 - (word0 & 0xE4 | 0x13)) ^ b0[b1[122]]
    b1[22] = 0x44 | b2[b1[90]] & 0x1B
    b2[18] += _choose(0xB8, b2[word11], b4[word9]) ** 3 >> 1
    b2[5] -= b4_92
    arm = _choose(0x18, b1[41], b2[b1[183]])
    b2[18] ^= _choose(word5, arm, b2[word5]) * _choose(word11, b1[17], b0[b1[59]])
    spin = _rotr8_or_zero(b1[11], b2[b1[28]])
    alt = _choose(b0[14], b0[b1[93]], 0x96)
    turned = _rotl8_or_zero(b2[word0], spin)
    b2[22] += _majority(turned, _choose(0x1C, alt, b1[7]), b2[33])
    vote = _majority(word0, word5, 0xD6)
    b0[15] -= _majority(word8, vote, b4[b0[b1[39]] ^ 0xD9])
    word21 = (b0[b1[99]] ** 4 & 0xFF) | b2[word20]
    out[21] = word21

    shared22 = b2[word21] & b0[b1[209]]
    either22 = _choose(b0[10], _rotl8_or_zero(b4[b1[127]], b2[word21]), shared22)
    word22 = _choose(0xB8, either22, b4[b2[word9]] * 2)
    out[22] = word22

    # Cells the stores below can overwrite before their values are used,
    # and the index of one of them.
    forced24 = 0x52 | word20 & 0x2D
    diff24 = word0 // 3 - (b1[22] | word20) & 0xFF
    nested24 = _majority(forced24, _majority(b0[word20], b2[b1[57]], 0x5F), 0x20)
    b0_mixed = b0[diff24 ^ word8 ^ nested24]
    b0_50 = b0[b1[50]]
    b2_138 = b2[b1[138]]
    b0_151 = b0[b1[151]]
    b2_14 = b2[b1[14]]
    b0_145 = b0[b1[145]]

    b4_w20 = b4[word20]
    b2[2] += _choose(0x96, b4_w20, b1[25]) & (0x40 | b0[word5] * 2 & 0x9F)
    b2[14] -= _choose(0x22, (b2[b1[100]] ^ word22) & b2[word5], b1[97])
    b0[17] = 0x73
    stir = _majority(word22, b0[word5], b4[b1[17]])
    b1[23] ^= _majority(stir, b1[50] // 3, 0xF6) * 2
    b0[13] = _choose(0x17, _majority(b0[word10], b1[10], 0x52) >> 1, b0[b1[39]])
    b2[33] -= b1[113] & 9
    b2[28] -= _choose(0x20, word5, b1[110] >> 1)
    b4_202 = b4[b1[202]]
    fifth24 = (
        _choose(0x11, b4[b1[39]], b1[33]) + _choose(b2[16], b2_138, b0_mixed)
    ) // 5
    vote24 = _majority(b0[b1[4]], fifth24, 0x93)
    total24 = _rotl8_or_zero(b0_151 | b4_202, b0_50) + vote24 + word2 & 0xFF
    b4_w5 = b4[word5]
    cube = _majority(b4[total24], word10, 0xAA) ** 3
    b0[15] = cube & _majority(b4_w5 + 208, ~b1[184], 0xBD)
    b2[22] += b1[183]
    word23 = word0 ^ b4[b1[1]] * 3
    out[23] = word23

    product24 = (
        _majority(b2[total24], b4[b1[178]], 0xD1) * b0[b1[13]] * (b4[b1[26]] >> 1)
    )
    word24 = word9 + product24 * 198 & 0xFF
    out[24] = word24

    word25 = _choose(0xA, b2[word20], b2[word5])
    out[25] = word25

    b2[18] -= _choose(b0[15], (b0[word21] | 0x51) ** 3, word24 // 15)
    word26 = total24 + b4[b0[total24]] // 3 - b0[b1[160]] & 0xFF
    out[26] = word26

    sel = _choose(0xC6, word22 ^ b0_145, b2_14**2)
    odd = _majority(word3 - sel + 77, b4[b1[69]], b1[172]) & 0xFA | 1
    b0[16] -= _majority(word22, odd, 0xC6)
    window_byte = _majority(b4[b1[155]], b1[105], 0x8D)
    b0[3] -= b4[_window_or_zero(window_byte, _majority(b0[b1[29]], b4[b1[168]], 6))]
    b1[5] = _rotr8_or_zero(0x38, b0[b1[61]] // 5) ^ ((255 - b2[word25]) // 5)
    b1[198] += b1[3]
    b1[164] += (b2[word20] | 0xA2) ** 2 // 5
    cube27 = b4_w20**3
    turned27 = _rotr8_or_zero(0x8B, word24)
    word27 = _majority(b0[word5], turned27, 0xC) | _choose(0x5F, b0[word10], cube27)
    out[27] = word27

    b2[12] += _majority(word27, b1[103] | 0x1C, 0x30) // 3
    out[28] = b1[143]

    # word30 comes first: word 29 is picked from it
    word30 = _choose(b2[8], word10, b1[35])
    pick29 = _choose(word20, word25 // 3, word30)
    out[29] = pick29 & 0x09 | 0x12
    out[30] = word30
    flags = 0x56 | b1[172] >> 1 & 0x20
    b1[143] -= _majority(pick29, flags, 0x1B)
    b2[29] = 0xA2
    b4_w26 = b4[word26]
    square = b1[43] ** 2
    nudge = _majority(
        _choose(0xA0, b0[b1[125]], b4_w26) >> 1, b2[b1[149]] ^ square, 0x73
    )
    b0[15] += nudge
    word31 = word20 - b0[word10] & 0xFF
    out[31] = word31

    b1[95] = b4_w5
    b0[7] -= _rotr8_or_zero(b2[word24], b2[b1[17]] ** 3) ** 2
    b2[8] -= b1[184] - b4_202**3
    b0[16] = b2[b1[102]] * 2 & 0x84
    word32 = (b4[word10] >> 1) ^ word21
    out[32] = word32

    b0[7] += _choose(0xB1, b4[b1[80]] * 2, b4[b4_w26]) - b0[b1[191]]
    b0[6] = b0[b1[119]]
    second_square = b0[word31] ** 2
    masked = 2 | b1[118] & 0xD1
    # b1[15] was rewritten after word1 read it, so this may be another cell.
    pair_sum = b2[b1[71]] + b2[b1[15]]
    b0[12] = (b0[word25] ^ pair_sum) & _majority(second_square, masked, 0x1B)
    b4_w32 = b4[word32]
    fifth33 = _choose(0xA9, _majority(b1[32], b2[word26], 0x17), b4[b1[57]] * 231) // 5
    taken33 = _choose(0xBE, b4[fifth33], _choose(0x1C, b0[b1[82]], b4_w32))
    vote33 = _majority(b0[word10] ** 3, b1[82], 0x5C)
    out[33] = fifth33 ^ _majority(vote33, taken33, 0xC0)

    rolled = _rotl8_or_zero(word23, b4_w32)
    b2[25] ^= b0[word31] * b1[5] * 2 - (rolled & (word5 - 146))
