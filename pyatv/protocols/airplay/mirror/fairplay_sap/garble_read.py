r"""Garble, rolled back into its loops, in the order the writes happen.

Do not edit: regenerate with
    uv run --with capstone python -m devirt.garble_render \
        > devirt/garble_read.py
    uv run --with capstone python -m devirt.reroll devirt/garble_read.py
    uv run --with numpy --with capstone python -m devirt.mba_reduce \
        devirt/garble_read.py garble --write --freshproofs
    uv run python -m devirt.mba_divide \
        devirt/garble_read.py garble --write
    uv run python -m devirt.mba_divide \
        devirt/garble_read.py garble --write
    uv run python -m devirt.mba_cse \
        devirt/garble_read.py garble --write --fixpoint

A FIFTH STEP WRITES THE DIVISIONS BACK.  A compiler turns `x // 3` into a
multiply by a magic constant and a shift, and `garble_render` undoes that
where it can see both instructions.  0 got past it.

Two of them because the magic is the SIGNED form -- `0x55555556 >> 0x20`
for three, `0x66666667 >> 0x21` for five -- where the renderer knows the
unsigned one.  The third because the multiply and the shift are no longer
adjacent: `reroll` gave the product a name, so one instruction pair became
`p = X * 0x55555556` on one line and `p >> 0x20` two lines below.  Nothing
that runs before naming can see that shape, which is why this runs after.

It is worth 0 operators, which is not the point.  The point is that
`(n & 0xef ^ 0x10 | b1[0x67] & 0x20 ^ 0x10) * 0x55555556` followed by two
shifts of the result is a division written to look like anything else, and
now it says `// 3`.

A FIFTH STEP WRITES THE DIVISIONS BACK.  A compiler turns `x // 3` into a
multiply by a magic constant and a shift, and `garble_render` undoes that
where it can see both instructions.  3 got past it.

Two of them because the magic is the SIGNED form -- `0x55555556 >> 0x20`
for three, `0x66666667 >> 0x21` for five -- where the renderer knows the
unsigned one.  The third because the multiply and the shift are no longer
adjacent: `reroll` gave the product a name, so one instruction pair became
`p = X * 0x55555556` on one line and `p >> 0x20` two lines below.  Nothing
that runs before naming can see that shape, which is why this runs after.

It is worth 6 operators, which is not the point.  The point is that
`(n & 0xef ^ 0x10 | b1[0x67] & 0x20 ^ 0x10) * 0x55555556` followed by two
shifts of the result is a division written to look like anything else, and
now it says `// 3`.

The renderer prints one statement per executed instruction; the second
step rolls the repetition back up.  What it finds here is exactly the
sweep this docstring already describes -- 51 passes over
`b1[cursor % 210:]` -- split as 1 + 12 + 1 + 37, because the addressing
changes where the cursor wraps.  155 stores still execute; 108 lines
write them.

The third step takes the obfuscation off.  What the virtual machine ran
was mixed boolean arithmetic: a simple byte function inflated into a
complicated-looking one over the same bytes, and rendering it faithfully
preserved the inflation.  `mba_reduce` comes at it four ways.  Where
the inputs are few enough it tabulates the expression over the whole
domain of its inputs and puts back the smallest expression with the
same table -- for one and two byte inputs that is a proof, not a
sample.  Where they are not -- three byte inputs is already 16.7
million points and four is four billion -- three other backends try:
`mba_linear` *fits* a model to the expression from a few hundred
evaluations, which is what SiMBA and GAMBA are built on, widened here
so that shifts and rotations are in the class too; `mba_narrow` throws
away the input bits the expression never reads and tabulates what is
left; and `mba_table` looks the expression up in a committed table of
rewrite identities.  All three produce a guess, so every one of them is
checked before it is kept: over the whole grid where that is
affordable, over a large fixed sample where it is not, and the record
says which.  On top of all four, eight things a table cannot see come
off: masks a width analysis shows are no-ops, doubled masks, byte
rotations spelled out as shifts, the tap arithmetic, arithmetic shifts
of values that cannot be negative, the 16 bitwise majorities,
which go back under the name `_maj`, and -- read the other way round --
the masks nothing outside them ever looks through, which no forward
analysis can see because they really do change the value they wrap.
That last takes 299 statements down by 737 masks, and it is
value-preserving: each statement starts at "every bit is wanted", so a
mask only goes from under a mask that stayed, and the byte the line
stores is the byte it stored.  The eighth is the one no tabulation
could reach: 31 times the two sides of an `|` shared an `&`
operand -- most often the same mask, reduced twice by different
backends and so never in one table together -- and the shared operand
comes out in front of both.  It runs after everything else, on the
finished file, because it is the one rule that can cost more than it
saves: applied from the first pass it leaves the passes behind it a
different expression to tabulate, and they then fit 16 fewer of the
substitutions below.  717 substitutions are on record
over 811 assignments -- 513 tabulated, 159 fitted,
37 table identities and 8 narrowed -- with 982
peephole rewrites on top of them, and the expression text came down from
76,543 characters to 43,600.  What did not reduce is left exactly as
the machine had it; `garble_read_proofs.json` records every substitution with the domain
it was checked over and how far the check went, and `test_mba_synth.py`
replays them.

13 LINES SAID WHAT THE LINE ABOVE THEM ALREADY SAID -- the same
expression, over bytes nothing had touched since, into the same name --
and are gone.  They survived every earlier pass because the sweep that
drops statements looks for a DEAD one, and these are read; nothing was
looking for a redundant one.  `mba_reduce.sweep_redundant` is, and it
asks for more than matching text: no name the expression reads, and no
BUFFER it reads, may have been written in between, because b0, b2 and
b4 are indexed by data bytes and a store anywhere in one of them can
change what a load answers.

WHAT IT TURNS OUT TO BE.  With the costume off, the window is
`saphash.scramble`, unrolled -- the same three taps, the same three
rotations, in the same places:

    saphash.scramble           garble, here
    x = b[u32(i - 155) % 210]  d = b1[_tap(cursor, 0x9b)]
    y = b[u32(i -  57) % 210]  a = b1[_tap(cursor, 0x39)]
    z = b[u32(i -  13) % 210]  c = b1[_tap(cursor, 0xd)]
    rol8(x, 7)                 _rol8(d, 7)
    rol8(y, 5)                 _rol8(a, 5)
    rol8(z, 3)                 _rol8(c, 3)

The four lines carrying those rotations ran to 152, 164, 152 and 164
characters of arithmetic before the reduction, saying exactly this.

`garble_gen` emits the same window as 5,168 lines of machine
translation.  This is the same computation, recovered the same way and
checked against the same trace.  19 bytes are read before the line that
uses them, because a later store overwrites them first.

TWO KINDS OF NAME come from the renderer and they mean different
things.  `held0` to `held18` are bytes READ EARLY, because a later
store overwrites them before the line that uses them runs.  `kept0` to
`kept84` are values the window WORKS OUT MORE THAN ONCE: it reads
`b3[4 * 0]` at sixty-three places and `b3[4 * 10]` at fifty-two, and
each of those is now written once and read by name after.

A name may only stand for two places while the byte underneath it holds
still between them, and here it often does not -- the window writes b3
as it runs, so `b2[b3[4 * 1] % 0x23]` before that store and after it are
two values wearing one spelling.  `garble_render.windows` works out the
span of lines each expression is good for, one cell for a constant
address and the whole buffer for an index the data computes; `runs`
cuts a name that would outlive its span into the pieces it does cover;
and `proved` then runs the whole window over the traced buffers and
sixteen random ones and checks that every group really is one value
before a name is bound.

NOTHING IS NAMED THAT `mba_reduce` COULD HAVE SHORTENED INSTEAD, and
what that rules out is narrower than it sounds.  Reduction reads a line
as a function of its SYMBOLS -- the memory reads and the names -- and
tabulates it over the cross product of their domains, so a name costs
it a rewrite in one way only: by breaking a correlation, leaving two
symbols that are really one byte twice for the grid to range over
independently.  A memory read is already a symbol, so a name in its
place moves nothing.  Three inputs or more is past where tabulating
reaches -- 16.7 million points -- so there is nothing there to lose.
Below three, `garble_render.Emitter._reducible` looks for the
correlation itself, line by line, and names what has none.  Fencing it
that way rather than on the input count alone is worth 5 substitutions
and 232 characters; naming everything that repeats instead costs 66 of
them and 2,950 characters.

THE FOURTH STEP NAMES WHAT IS LEFT OVER.  Reduction works on one
expression at a time and `reroll`'s naming works on one statement at a
time, so neither can see that two different statements build the same
subexpression.  110 of them do, and computing each of them again
instead of naming it costs 464 operators.  Hoisting the 126 that clear
the floor described below takes garble from 5,514 operators to 4,946.

Running it LAST is what makes it free.  The paragraph above fences the
renderer's naming so that a name never costs `mba_reduce` a rewrite --
a name it cannot see through is a symbol whose correlation to another
symbol is lost.  A name bound after reduction has finished cannot lose
a rewrite that has already happened, so this pass needs no fence, and
in exchange the pipeline may not be reordered: `mba_cse` reads the
names it binds as opaque symbols, and putting it before `mba_reduce`
would hide exactly what that pass came to tabulate.

WHAT IS SAFE TO HOIST is the question `sweep_redundant` answers, asked
of a fragment instead of a whole statement: a repeat may be named only
if nothing between its first and last use writes anything it reads --
buffers included, since b0, b2 and b4 are indexed by data bytes.
Occurrences are grouped per straight-line block, so nothing is lifted
out of the loop it belongs to.  The floor of 2 operators is a trade of
one line for the operators it removes; at 2 it runs 4.2 operators
removed per line added, and the whole curve is in the commit that added
this pass.

The five buffers lie in one heap block, in this order and at these
offsets from its base:

    b4  0x1a0   21 bytes        b2  0x2a0   35
    b0  0x1b8   20              b3  0x2f4  136
    b1  0x1cc  210

*cursor* is a 32-bit counter in the gap after b2, at 0x2cc.  The window
opens with a loop that rewrites `b1[cursor % 210 : 210]`, and every call
a handshake makes reads 789 there -- 159 modulo 210, which is why the
loop runs 51 times.  It is read from memory rather than assumed, so it
is an argument here too.

b3 IS AN ARRAY OF WORDS, which is why its indices are spelled `4 * n`.
Profiling the live function over 400 random blocks: every b3 access,
read and write, is at an offset divisible by four, and the three bytes
above each low one are never non-zero.  So it is 34 32-bit slots each
carrying a byte -- an `int tmp[34]` of chars -- and this window writes
words 0 to 33 and reads 0 to 32.  That makes the last store, to byte
132, the last word of a 136-byte array rather than one byte past a
132-byte one; earlier versions of this file called it an overrun, and
it is not.  `saphash_fold` reads the same array the same way.
"""

# flake8: noqa: E501 - one write per line, and some writes are long
# pylint: disable=line-too-long,too-many-locals,too-many-statements
# One write per line; black would explode each into several.
# fmt: off


def _asr(value, count, bits):
    """ARM `asr`: shift right, sign-extending from the top bit."""
    value &= (1 << bits) - 1
    if value >> (bits - 1):
        value -= 1 << bits
    return (value >> count) & ((1 << bits) - 1)


def _rol8(value, count):
    """Rotate a byte left -- SAPHash's own primitive.

    `saphash.scramble` is written in this and nothing else:
        b[i] = rol8(y, 5) + (rol8(z, 3) ^ w) - rol8(x, 7)
    The window below is that step, unrolled and obfuscated; the
    rotations were spelled out as shifts and masks, and are put back
    under their real name here.
    """
    value &= 0xff
    return (value << count | value >> 8 - count) & 0xff


def _tap(cursor, back, span=0xd2):
    """Return the scramble tap *back* bytes behind *cursor*.

    The subtraction is an UNSIGNED 32-bit one and it happens before the
    modulo, which is the subtlety the whole scramble turns on: for
    cursor 0 and back 155 the tap is not 55, which is what Python's `%`
    would give, but 101, because 0xffffff65 % 210 is 101.  The wrap is
    kept here rather than simplified away -- that is the point of
    naming it.  `saphash.TAPS` is (155, 57, 13), and those are the three
    numbers this is called with.
    """
    return (cursor - back & 0xffffffff) % span


def _maj(a, b, c):
    """Bitwise majority: each output bit is the one two of the three agree on.

    NOT the median of three values.  `_maj(1, 2, 3)` is 3, while the
    median is 2: it works a bit at a time, and 1, 2, 3 are 01, 10, 11,
    so the low column holds 1, 0, 1 and the high column 0, 1, 1.

    The obfuscator writes this `a ^ (a ^ b) & (a ^ c)`, which is the
    same function for every input -- checked over the whole byte domain
    in `test_mba_synth.py` -- and spelled that way it hides both that it
    is a majority and that it is symmetric in a, b and c.
    """
    return a & b | a & c | b & c


def garble(b0, b1, b2, b3, b4, cursor=789):
    """Rewrite 130 bytes across the five buffers, in place."""
    a = b1[_tap(cursor, 0x39)]
    c = b1[_tap(cursor, 0xd)]
    d = b1[_tap(cursor, 0x9b)]
    e = b1[cursor % 0xd2] & 0x7f ^ _rol8(c, 3) & 0x7f
    f = b1[cursor % 0xd2] ^ _rol8(c, 3)
    g = _rol8(d, 7) ^ 0x34
    h = (g ^ 0xcb) + (f + _rol8(a, 5) ^ 0x6f) & 0xff
    b1[cursor % 0xd2] = h + (0xde & 2 * e + (0xfe & _rol8(a, 6))) - 0x6e & 0xff
    for _step in range(12):
        a = b1[_tap(cursor, 0x38 - _step)]
        c = b1[_tap(cursor, 0xc - _step)]
        d = b1[_tap(cursor, 0x9a - _step)]
        e = _rol8(d, 7) ^ 0x34
        reused108 = -1 - _step
        f = b1[_tap(cursor, reused108)] & 0x7f ^ _rol8(c, 3) & 0x7f
        g = b1[_tap(cursor, reused108)] ^ _rol8(c, 3)
        h = (e ^ 0xcb) + (g + _rol8(a, 5) ^ 0x6f) & 0xff
        b1[_tap(cursor, -1 - _step)] = h + (0xde & 2 * f + (0xfe & _rol8(a, 6))) - 0x6e & 0xff
    a = b1[_tap(cursor, 0x2c)]
    c = -(b1[cursor % 0xd2] >> 5)
    d = b1[_tap(cursor, -0xd)]
    e = b1[_tap(cursor, 0x8e)]
    reused61 = b1[cursor % 0xd2] << 3
    f = d & 0x7f ^ c + 0x3f ^ (reused61 & 0x78 ^ 0x72) ^ 0x4d
    g = d ^ c + 0x3f ^ (reused61 & 0xf8 ^ 0xf2) ^ 0xcd
    h = _rol8(e, 7) ^ 0x34
    j = (h ^ 0xcb) + (g + _rol8(a, 5) ^ 0x6f) & 0xff
    b1[_tap(cursor, -0xd)] = j + (0xde & 2 * f + (0xfe & _rol8(a, 6))) - 0x6e & 0xff
    for _step in range(37):
        a = b1[_tap(cursor, 0x2b - _step)]
        c = b1[_tap(cursor, -1 - _step)]
        d = b1[_tap(cursor, 0x8d - _step)]
        e = _rol8(d, 7) ^ 0x34
        reused109 = -0xe - _step
        f = b1[_tap(cursor, reused109)] & 0x7f ^ _rol8(c, 3) & 0x7f
        g = b1[_tap(cursor, reused109)] ^ _rol8(c, 3)
        h = (e ^ 0xcb) + (g + _rol8(a, 5) ^ 0x6f) & 0xff
        b1[_tap(cursor, -0xe - _step)] = h + (0xde & 2 * f + (0xfe & _rol8(a, 6))) - 0x6e & 0xff
    a = (0x5c | b1[0x63] // 3) ^ 0x27
    c = (b1[0x40] ^ b2[0x12] & (b1[0x40] ^ b2[b1[0xb2] % 0x23])) & 0x5c
    d = a ^ 0x7b ^ c
    e = b4[b1[0xce] % 0x15] << 4 ^ 0x4cd3429f
    f = e ^ (b4[b1[0xce] % 0x15] >> 4 ^ 0x62f093e8) ^ 0x2e23d177
    b2[0xc] = b2[0xc] + (d & b4[f % 0x15]) & 0xff
    reused47 = b1[0x63] // 5 * (b1[0x63] // 5)
    b1[4] = ((reused47 & 0x7d) * 2 - (reused47 & 0xd) * 4 & 0xfe) + 0x1a & 0xfa ^ 0x1a
    a = 0xea >> (7 & b4[0x13] // 3) & 0x3f
    c = ((0xea << (-(b4[0x13] // 3) & 7) & 0x3e) + 0x20 & 0x3e ^ (a ^ 0x3b)) & 0x25
    b2[0x22] = c ^ 1 ^ (b4[8] & 0xda ^ b2[0x22])
    a = b2[b1[0xcb] % 0x23] & 0x7f
    c = 0xc8 - 2 * (0xc8 & b1[0xbe] * a ** 2) + b1[0xbe] * b2[b1[0xcb] % 0x23] ** 2 & 0xff
    b1[0x99] = b1[0x99] ^ c ^ 0xc8
    reused96 = b4[b1[0xcd] % 0x15] >> 1
    a = reused96 & 0x1c
    reused38 = b2[b1[0x16] % 0x23] & b0[0xc]
    c = reused38 & 3
    d = b2[b1[0x16] % 0x23] & 0x1f
    e = reused38 & 0x3f
    f = (((b0[0xc] | d) & 0x1c | e) ^ 0x2a) + ((b0[0xc] << 1 & 0x14 ^ 4 | d << 1 & 0x14 ^ 4) ^ 4) - 0x2a & 0x23
    reused16 = b0[6] // 3 * (b0[6] // 3)
    g = ((reused16 & 0x1d) * (b0[6] // 3) & 0x1f) * 2
    h = (reused16 & 0x3d) * (b0[6] // 3) & 0x3f
    j = reused96 & 0x5c
    k = reused16
    reused18 = (k & 0x7d) * (b0[6] // 3)
    m = reused18 - g + 0x1f & 0x7f ^ 0x1f | -j + (f + (a + a)) & 0x7f
    n = e & 0x23
    p = -n + (c << 1) & 0x3f | a
    q = (n ^ 0x5b) + c * 2 - 0x5b & 0x7f | j
    r = (q ^ 0x6f) + (p * 2 & 0x5e) - 0x6f & 0x7f & (reused18 - (reused18 * 2 & 0x6a) + 0x75 & 0x7f ^ 0x75)
    s = reused38
    v = (k & 0xfd) * (b0[6] // 3) & 0xff
    w = ((v - g + 0x1f & 0xff ^ 0x1f | j + (f + f - (s & -0x5d)) & 0xff) ^ 0x7d) + (m * 2 & 0xfa)
    x = 2 * (p ^ 0xf) - 0x1e + (c << 2 ^ b4[b1[0xcd] % 0x15] << 1 & 0x30) & h << 1 & 0x6e
    y = (m ^ 0x7d) + ((h * 0xfe + (g + g) | f * 0xfe + (a + a + (c << 2))) & 0x7a) - 0x7d & 0x52
    z = (((s & 0xa3 ^ 3) - 3 + (c << 1) | j) ^ 0x6f) + (q * 2 & 0xde) - 0x6f & 0xff
    n21 = b0[3] + (((r & 0x77) * 2 + (z & v ^ 0xf7) + 9 | w - 0x7d & 0xd2) ^ 0xa9) & 0xff
    b0[3] = n21 - (((r ^ 0x77) + 9 + x & 0x7f | y) * 2 & 0xac) + 0x57 & 0xff
    a = b4[8] & 0x1a ^ 4
    c = b4[8] << 1 & 0x14
    d = (8 - a + c) * a & 0x14
    e = (b4[8] & 0x3a ^ 0x3f) + (8 ^ a + a) + 0x38 - 0x33 & 0x3e
    f = b0[0x10] + ((((b4[8] << 1 & 0x74 ^ 8) * (e >> 1) & 0x34) + 0x17 << 2) - (d << 3) ^ 0x4f) & 0xff
    b0[0x10] = (0xde | d * 8) + 0xf + f & 0xff
    b0[0xd] = b0[0xd] - 0x75 & 0xff
    a = b2[0x1a] // 3 & b2[0x18] & (b1[0xb] & ~b0[0xf] | b0[0xf] & 0x38) | b4[b1[0x24] % 0x15] & ~b2[0x18]
    b1[0x21] = b1[0x21] - a & 0xff
    held1 = b0[b1[0xb5] % 0x14]
    held0 = b2[b1[0x43] % 0x23]
    b2[0xc] = (b4[8] // 3 & ~b0[0x10] | b0[0x10] & b2[0x16]) // 5
    a = (b0[0xc] | b2[0x1c]) & 0x10 | b0[0xc] & b2[0x1c] & 0xf
    c = (b0[0xc] | b2[0x1c]) & 0x50 | b0[0xc] & b2[0x1c] & 0x2f
    d = (b0[0xc] & 0xaf ^ 0x50) & b2[0x1c] | b0[0xc] & 0x50
    e = (d * d ^ 0xb8) + b1[2] & 0xff
    b1[2] = e + (((c * c & 0x7d) - ((a * a & 0x1d) * 2 & 0x18) + 0x4c & 0x7f) * 2 & 0x8a ^ 0x77) + 0x49 & 0xff
    b0[0x13] = b4[b1[0x3a] % 0x15]
    b3[4 * 0] = 0x5c - b2[b1[0x20] % 0x23] & 0xff
    kept0 = b2[b1[0xf] % 0x23]
    a = ~b4[0x10] & 0x1c
    c = b4[0x10] & b2[0x1a] & 0xf
    d = b4[0x10] & b2[0x1a] & 0x1f
    reused1 = ((c - ((b4[0x10] & b2[0x1a]) * 2 & 4) + 0xa ^ 0xa | ~b4[0x10] & 0xc) & 0xa) + ((d | a) >> 1 ^ 0xd) - 1 - 0xc & 0xf
    e = reused1
    reused39 = (c | ~b4[0x10]) & 0xc | c & 2
    reused4 = reused39 + ((0xf ^ a >> 1) & (d >> 1 ^ 0xf)) - 1 - 0xe & 0xf
    f = reused4
    reused2 = reused39 + (((d ^ 7) - 7 + (c << 1 & 0xe) | a) >> 1 ^ 7) + 0xc - 3
    g = f * (e * reused2) & 0xf
    h = g * 2 & 0x12
    j = b4[0x10] & b2[0x1a] | 0x5c & ~b4[0x10]
    k = ~b4[0x10] & 0x5c
    m = b4[0x10] & b2[0x1a] & 0x7f
    n = a
    reused14 = (b4[0x10] & b2[0x1a]) + ((d ^ 0xa) - d - 0xa) + 0xa ^ 0xa
    p = ((reused14 | n) & 0x3a) + (j >> 1 ^ 0x1d)
    q = (0xf ^ b4[0x10] & 0x5c) + 0x2d + (0x20 & k + k) & 0x7f | b4[0x10] & b2[0x1a]
    r = ((((0xc - k ^ 0xc) + (0x20 & n + n) | m) & 0x5e) + (q >> 1 ^ 0x6f) - 1 & 0x7f) - 0x6e
    s = r * ((0x5c - p ^ 0x3f) * (((m | k) & 0x6e) + (j >> 1 ^ 0x77) + 0x6c - 0x63)) - h & 0x7f
    u = (kept0 + ((q >> 1) * ((0x9c - p ^ 0x7f) * (j >> 1)) - h + 9 ^ 0x46) & 0xff) + ((s + 9 & 0x7f) * 2 & 0x9e ^ 0x12)
    kept1 = u + 0x57 & 0xff
    b3[4 * 1] = kept1
    e = j
    f = ((reused14 | a) & 0x3a) + (e >> 1 ^ 0x1d) - 1 & 0xff
    g = reused1
    h = reused4
    j = h * (g * reused2) & 0xf
    k = (0xff & f - 0x1c) * (e >> 1)
    m = b4[0x10] & b2[0x1a] & 0xa3 | (b2[0x1a] | ~b4[0x10]) & 0x5c
    n = ((m >> 1) * k - (j * 2 & 0x12) & 0xffffffff) + 9
    p = kept0 + (n ^ 0x46) + (n << 1 & 0xffffff9f ^ 0x12) + 0x57 & 0xff
    q = (kept1 // 0x15 * 0xffffffeb + p & 0xffffffff ^ 0x33333333) + ((kept1 // 0x15 * 0xb + p & 0x1f) * 2 & 0x26)
    r = b4[q + 0xcd & 0xff]
    b1[0x22] = b1[0x22] + r // 5 & 0xff
    kept2 = b3[4 * 0]
    kept3 = b3[4 * 1]
    a = ((b2[0x12] | kept2 & b4[8]) & ~b2[5] & (b4[8] | kept2) | b2[5] & b0[0xc]) & 0x19
    reused63 = ~b0[kept3 % 0x14]
    c = reused63 & 0xc
    reused64 = b0[kept3 % 0x14] >> 1
    d = (a | (reused64 & 0x26 ^ 0x38) + c - 0x1e & 0x26) * 2 & 0x6a
    e = reused63 & 0x8c
    f = b0[0x13] + ((a | (reused64 & 0x66 ^ 0xb8) + e - 0x5e & 0xe6) ^ 0x35) + d & 0xff
    b0[0x13] = f - 0x35 & 0xff
    a = b1[0x48] << (7 & -b4[b1[0xbe] % 0x15])
    c = _asr(b1[0x48], b4[b1[0xbe] % 0x15] & 7, 0x20)
    d = (c ^ a) & 0x3f
    e = (c ^ a) & 0x7f
    f = c ^ a & 0xff
    g = (b4[b1[0x7e] % 0x15] * -0x12 + 0x42 + d * 6 & 0x3e) + 0x3e & 0x20
    h = (3 * ~b4[b1[0x7e] % 0x15] - 0x32 + e & 0x7f) * 2
    b1[0xf] = b1[0xf] ^ 2 ^ f + h - b4[b1[0x7e] % 0x15] * 3 - g - 6 & 0xff ^ 0x92
    a = b2[b1[0xb5] % 0x23] & 0xf
    b0[0xf] = b0[0xf] ^ 0x46 ^ (b2[b1[0xb5] % 0x23] * b2[b1[0xb5] % 0x23] & 0xfd) * b2[b1[0xb5] % 0x23] - ((a * a & 0xd) * a * 2 & 0xa) + 5 & 0xff ^ 0x43
    b2[4] = b1[0xca] // 3 ^ b2[4]
    a = b0[kept2 % 0x14] & ~b1[0x69] & 1
    c = ~b1[0x69] & b0[2] & 1
    d = b0[kept2 % 0x14] & b0[2] & 1
    e = c << 1 | (d << 1 | a << 1)
    reused65 = 0x1c - b0[kept2 % 0x14]
    f = 0x1f & reused65
    g = f & ~b1[0x69]
    h = 0x3f & reused65
    j = h & ~b1[0x69]
    reused66 = 0x5c - b0[kept2 % 0x14]
    k = 0x7f & reused66
    m = k & ~b1[0x69]
    n = (b1[0x69] ^ (b1[0x69] | b0[2])) & 0x7f
    reused67 = n | k & b0[2]
    p = reused67 | m - g * 2 + 0x5f & 0x7f ^ 0x5f
    reused68 = j * 2 & 0x4c
    q = reused67 | m - reused68 + 0x26 & 0x7f ^ 0x26
    r = reused66 & 0xff
    s = b0[2] & (f | ~b1[0x69]) & 0x1f | g - ((4 - b0[kept2 % 0x14] & ~b1[0x69] & 7) * 2 & 0xc) + 6 & 0x1f ^ 6
    u = p - (((b0[2] & (h | ~b1[0x69]) | -j + (g << 1)) & 0x3f) * 2 & 0x52) + 0x69 & 0x7f ^ 0x69
    v = ((q - (s * 2 & 0x3a) + 0x5d ^ 0x5d) * (k & b0[2] | n | m) * u - e + 1 & 0x7f) * 2 & 0xe6 ^ 2
    reused49 = b0[2] & (r | ~b1[0x69])
    reused69 = r & ~b1[0x69]
    w = (reused49 | reused69 - (m & 0x5f) * 2 - 0x21 ^ 0xdf) - (p * 2 & 0xd2) + 0x69 & 0xff ^ 0x69
    x = (reused49 | reused69 - reused68 + 0xa6 ^ 0xa6) - (q * 2 & 0xba) + 0x5d & 0xff ^ 0x5d
    b2[1] = b2[1] + (x * (r ^ (~r ^ b1[0x69]) & (r ^ b0[2])) * w - e + 0x81 ^ 0xf2) + v - 0x73 & 0xff
    kept4 = b4[b1[0x5c] % 0x15]
    a = (kept4 & b4[0x12] | ~b4[0x12] & 0xfb) * b2[b1[0x29] % 0x23]
    c = (a + 0x10b41fff - (0x21683ffe & a << 1) & 0xffffffff ^ 0x10b41fff) // 3
    b0[0x13] = b0[0x13] ^ (c << 1 & 0xfc ^ 0xfe) + c & 0xff ^ 0xfe
    a = 0x5c << (7 & -b1[5])
    c = 0x5c >> (b1[5] & 7)
    b1[0x8c] = (c ^ 0x12 ^ ((a & 0xfc) - (a << 1 & 0xc8) & 0xfc) + 0x67 ^ 0x75) + b1[0x8c] & 0xff
    reused70 = b1[4] ^ b2[b1[0xc] % 0x23]
    a = reused70 ^ 0xff
    c = a & b1[0xb6] | b4[0xf] & (0x41 ^ 0xbf + 2 * (0xc1 & ~b1[0xb6] & reused70) + (a | b1[0xb6]))
    b2[0xc] = b2[0xc] + c & 0xff
    b1[0x24] = b1[0x24] + 0x7d & 0xff
    a = b2[b1[0xbe] % 0x23] << 1 & ~b0[0] & 6
    c = (b2[0x16] | b1[0x8a]) & b0[0xf]
    d = b0[0xf] & (b2[0x16] | b1[0x8a]) & 0x3f
    reused71 = c | b2[0x16] & b1[0x8a]
    e = (reused71 + 0x80 & 0xff | (0x80 & ~c & b2[0x16] & b1[0x8a]) * 4) - 0x80 & 0xffffffff
    f = e - ((d | b2[0x16] & b1[0x8a] & 0x3f) * 2 & 0x40) + 0x20 & 0xffffffff ^ 0x20 | b0[b1[0x2b] % 0x14]
    g = f & b0[1] | b0[b1[0x2b] % 0x14] & (c | b1[0x8a] & b2[0x16])
    reused72 = a | b0[0] & 4
    h = _asr(g, reused72, 0x20)
    j = (b2[0x16] & b1[0x8a] | b0[b1[0x2b] % 0x14] | b2[0x16] & b0[0xf] | b1[0x8a] & b0[0xf]) * 2 & 0xff
    k = b0[b1[0x2b] % 0x14] & reused71 | b0[1] & j - (b0[b1[0x2b] % 0x14] | c | b2[0x16] & b1[0x8a])
    m = k << ((8 - reused72 ^ 5) + 3 & 7)
    b1[0x7c] = m & 0xff ^ h
    kept5 = b0[kept3 % 0x14]
    reused48 = b4[b1[0x44] % 0x15] << 1
    a = reused48 & 0x1c
    c = (b0[1] & 6 ^ 4) - 2
    d = reused48 & 0xe ^ 3
    e = a
    reused73 = 0x10 & d + d
    f = 0x1c & 4 - e ^ 4 ^ reused73
    reused51 = reused48 & 0x5c
    g = reused51 ^ 0x40
    h = reused51
    j = (((kept5 & b0[1] & 0x7f | (c & 0x7e) + 0x43 & 0x47 ^ 0x43) & ~(b4[0xd] & 0x7f) | b4[0xd] & 0x5c) & (0x5c & g - 0x1f)) * 2 & 0xa8
    k = (0x1c & -a) + (b4[b1[0x44] % 0x15] << 2 & 0x18) & 0x1f
    m = 0x5c & h + 8 ^ 8 ^ reused73 | ((kept5 & b0[1] | ~b0[1] & 0x86) & ~b4[0xd] | b4[0xd] & 0x5c)
    n = ((0x1c & e + 4 ^ 4) + 6 * (d & 4) & 0x1f | -(~(b4[0xd] | kept5 & b0[1]) & 0x19) - (b4[0xd] & 3) + 0x1f) * 2 & 0x30
    p = ~(b0[1] | b4[0xd]) & 0x86 | ~b4[0xd] & (kept5 & b0[1]) | b4[0xd] & 0x5c
    q = (-(~(f | (b0[1] | b4[0xd])) & 0xf9) - (~f & ~kept5 & b0[1] & ~b4[0xd]) - (b4[0xd] & 0xe3) - n - 9 & 0x3f ^ 0x38) & (b4[0xd] & 0x3f)
    r = ((kept5 & b0[1] & 0x3f | (c & 0x3e) + 3 & 7 ^ 3) & ~(b4[0xd] & 0x3f) | b4[0xd] & 0x1c) & a
    s = (q | r - ((((kept5 & b0[1] & 0x1f | (c & 0x1e) + 3 & 7 ^ 3) & ~(b4[0xd] & 0x1f) | b4[0xd] & 0x1c) & k) * 2 & 0x28) + 0x15 & 0x3f ^ 0x15) * 2 & 0x60
    u = ((~b4[0xd] & 0xa0) * 6 + (~b4[0xd] & ~f & (~kept5 | ~b0[1]) & 0xb8) * 2 + m + 8 & 0xff ^ 0x38) & b4[0xd]
    b3[4 * 2] = (u | (j ^ 0x6a) - 0x14 - 1 + (p & g - 0x1f & 0x5c) ^ 0x55) - s + 0x30 & 0xff ^ 0x6c
    a = b1[0x94] * 3 // 5
    c = (b1[0xb1] ^ 0x100000000) + b4[b1[0x4f] % 0x15]
    e = b4[b1[0x4f] % 0x15] & 0xf
    f = (c & 0x1ff) >> 1
    g = b4[b1[0x4f] % 0x15] & 0x3f
    h = c
    j = 0
    k = b4[b1[0x4f] % 0x15] & 0x1f
    m = (h & 0x1ff) >> 1
    n = m - (b1[0xb1] + (-k + (e << 1)) & 0x12) + 0x19 & 0x1f ^ 0x19
    p = (a + a | n << 1) & 0x30
    q = b4[b1[0x4f] % 0x15] & 0x7f
    r = m - (b1[0xb1] + (-g + (k << 1)) & 0x32) + 0x19 & 0x3f ^ 0x19
    s = (m - (b1[0xb1] + q * 2 - b4[b1[0x4f] % 0x15] + j & 0xb2) & 0xff) + 0xd9
    u = f - (-8 & b1[0xb1] + b4[b1[0x4f] % 0x15]) & 0xff
    v = f - (b1[0xb1] + g & 0x38) + 0x3c & 0x3f ^ 0x3c
    w = f - (b1[0xb1] + q & 0x78) + 0x7c & 0x7f ^ 0x7c
    x = f - (b1[0xb1] + e & 8) + 0xc & 0xf ^ 0xc
    y = (~(v & a) & 0x2a | v & a & 0x15) + (x << 1 & a + a & 0x14) & 0x3f
    z = ((0xf8 & 0x1c - p) + (a | (~s & 0xd9 | s & 0x26)) & 0xff ^ 0x18) & b2[1]
    n21 = w << 1 & 0xd4 & 2 * (a & 0x6a)
    n22 = 0xcb - b4[8] + ((z | ((3 - u ^ 3) & a ^ 0x6a) + n21 - 0x6a) ^ 0xc0) & 0xff
    b3[4 * 3] = n22 - ((((p ^ 0xd8) + (a | r) ^ 0x18) & b2[1] | y - 0x2a) & 0x3f) * 2 - 0xb & 0xff
    reused74 = 7 & -b2[0x16]
    a = _asr(b1[0x21], reused74, 0x20)
    c = b1[0x21] << (b2[0x16] & 7)
    d = 0x1f & b4[0x11] & (0x1a & b0[0xc] | 5 & b0[6])
    e = _asr(b1[0x21], reused74, 0x20)
    f = b0[0xc] & 0x1a | b0[6] & 0x25
    g = b2[kept2 % 0x23] << 1 & 0xc
    h = 0 - (b2[kept2 % 0x23] & 0x1a)
    j = b0[0xc] & 0x5a | b0[6] & 0x25
    k = b0[0xc] & 0x5a | b0[6] & 0xa5
    reused75 = b2[kept2 % 0x23] & 5
    m = ((((h & 0x7e) + 0x7a & 0x7a | reused75 | 8) ^ 0x72) - g + 0x46 ^ 0x46 | kept5 & 0x7f) * 2 & 0x9c
    n = (((b2[kept2 % 0x23] & 7 ^ 6) + 2 + g | kept5) & 0xf) * 2
    p = (((((h & 0x3e) + 0x3a & 0x3a | reused75 | 8) ^ 0x32) - g + 6 ^ 6 | kept5 & 0x3f) ^ 0xe) + (n & 0x1c)
    reused76 = b4[0x11] | c ^ e
    q = j & reused76
    reused19 = ~c & a & b4[0x11]
    reused20 = c & ~a & b4[0x11]
    r = ((q | reused20 | reused19) & 0x7ff2) * 2 & 0xff
    s = (((((h & 0xfe) + 0x7a & 0x7a | b2[kept2 % 0x23] & 0x85 | 8) ^ 0x72) - g + 0x46 ^ 0x46 | kept5) ^ 0x4e) + m
    u = k & reused76
    v = ((s ^ u) & 0x7f00) + s + ((u | reused20 | reused19) ^ 0x8d) & 0x1ff
    w = d | b0[0xc] & 0x1a & (c ^ e)
    x = 2 * (0x12 & (w | reused20 | reused19))
    y = b4[0x11] & (c ^ a) & 0x3f
    z = f & (c ^ e)
    n21 = (p + ((z | (f & b4[0x11] ^ 0x2f) + (d * 2 & 0x1e) - 0x2f | y) ^ 0xd) - x + 0x25 & 0x3f) * 2 & 0x6e
    b2[0x10] = b2[0x10] + (v - r + 0x25 ^ 0x37) + n21 - 0x37 & 0xff
    kept6 = b3[4 * 3]
    b0[0xe] = b2[kept6 % 0x23] ^ b0[0xe]
    a = (b0[b1[0xd0] % 0x14] & 0x83 | b0[b1[0xa4] % 0x14] & 0x7c) // 5
    c = b2[b1[0x70] % 0x23] << 1 & 6
    d = b4[b0[b1[0xc9] % 0x14] % 0x15]
    reused77 = 6 & -c
    e = _asr(d, reused77, 0x20)
    f = 2 * (7 & (a | e ^ d << c))
    g = (d << c & 0x3f) * 2 & 0x68
    reused53 = b2[b1[0x70] % 0x23] << 2 & 4
    h = _asr(d, c ^ reused53, 0x20)
    j = d << (reused77 ^ reused53)
    reused9 = ((d << c) - g + 0x34 ^ (e ^ 0x33) ^ 7 | a) - f + 7
    k = (reused9 & 0xff ^ 7) & b4[1]
    reused78 = a & (j ^ h)
    m = b1[0x13] + ((reused78 | k) ^ 0x5f)
    n = reused9 & 0x7f ^ 7
    p = (reused78 | n & b4[1]) * 2
    b1[0x13] = m + (p & 0xbe) - 0x5f & 0xff
    reused30 = 5 & b4[b1[0x2d] % 0x15] * b4[b1[0x2d] % 0x15]
    a = 0x8c << ((reused30 ^ 3) + 5 & 7)
    c = 0x8c >> reused30
    b2[8] = c ^ 0xce ^ (a & 0xcc) - (a << 1 & 0x88) + 0xd4 & 0xdc ^ 0x1a
    b1[0xbe] = b0[0xc]
    b2[8] = b2[8] ^ kept2
    reused79 = b0[b1[0x53] % 0x14] | b0[6]
    b1[0x35] = reused79 // 5 - (reused79 * 0xcccccccd >> 0x21 & 4) + 0x42 ^ 0xbd
    b0[0xd] = b0[b1[0x29] % 0x14] + b0[0xd] & 0xff
    b0[0xa] = (b2[kept2 % 0x23] & b1[2] | (b2[kept2 % 0x23] | b1[2]) & kept6) // 0xf
    kept7 = b4[b1[2] % 0x15]
    reused5 = kept7 ^ ~b2[0x1b] & (kept7 ^ b0[0xc])
    kept8 = reused5 & 0x7f
    kept9 = reused5 & 0x3f
    kept10 = b3[4 * 2]
    kept11 = b2[kept10 % 0x23]
    kept12 = (reused5 | kept11) & 0xa
    kept13 = (kept9 | kept11) & 0x2a
    a = kept9
    kept14 = (a | kept11) & 0x2a
    a = (b0[0xc] ^ b2[0x1b] & (b0[0xc] ^ kept7)) & 0x7f
    kept15 = ((kept8 - (kept9 * 2 & 0x68) + 0x74 ^ 0x74) & kept11 | kept14) * (kept13 | a & kept11) & 0x7f
    a = kept7 & b2[0x1b] & 0x1f
    reused40 = b0[0xc] & ~b2[0x1b]
    c = reused40 & 0x1f
    d = (reused5 & 0xf4) * 6 + ((a | c) & 0x1b) + ((a | c) & 4) * 3 & kept11 & 0x1f | kept12
    e = (kept15 - ((d * (kept12 | (c - (reused40 * 2 & 0xa) + 5 ^ 5 | a) & kept11) & 0x1f) * 2 & 0x28) & 0x7f) + 0x54
    f = ((~kept8 & 0xf4) * 2 + reused5 - 0x74 & 0xff ^ 0x74) & kept11 | kept14
    kept16 = (e + e & 0xe4 ^ 0xa0) + (f * (kept13 | (reused40 | kept7 & b2[0x1b]) & kept11) - (kept15 * 2 & 0xa8) + 0x54 ^ 0x26) & 0xff
    b3[4 * 4] = kept16
    b3[4 * 5] = 0xce - kept16 & 0xff
    b3[4 * 6] = b1[0x97]
    kept17 = b4[kept2 % 0x15]
    b2[0xd] = kept17 ^ b2[0xd]
    kept18 = b2[b1[0xb3] % 0x23]
    a = kept18 - 0x26 & 0x7f
    kept19 = _maj(a, b2[0x13], kept6) * _maj(a, b2[0x13], kept6) & 0x7f
    reused80 = kept18 - 0x26 & 0xff
    a = reused80 & b2[0x13]
    c = reused80 & kept6
    d = 0x3f & 5 - kept18 ^ 0x1f
    e = kept6 & b2[0x13] & 0x3f
    f = (kept19 - (((d & b2[0x13] | e | d & kept6) * (d & kept6 | e | d & b2[0x13]) & 0x3f) * 2 & 0x66) + 0x73 & 0x7f) * 2
    kept20 = (f & 0x8c ^ 0x84) + ((a | kept6 & b2[0x13] | c) * (c | kept6 & b2[0x13] | a) - (kept19 * 2 & 0xe6) + 0x73 ^ 0x35) & 0xff
    b3[4 * 7] = kept20
    b3[4 * 8] = kept20 + 0x16 & 0xff
    kept21 = b3[4 * 5]
    reused50 = (b2[0x16] & kept2) + kept21
    reused54 = reused50 - 1
    kept22 = reused54 & 7
    kept23 = (~kept17 | kept21 ^ kept2 & b2[0x16]) & 1
    kept24 = reused50 - 9 & 0x7f
    kept25 = kept23 << 1
    a = b2[0x16] & kept2 & 0x7f
    c = kept21 + (b2[0x16] & kept2) & 0x3f | ~(kept17 & 0x3f)
    kept26 = ((kept21 + a | ~kept17) & 0x79 ^ 0x3f) + ((c & 0x3f) * 2 & 0x72)
    a = b2[0x16] & kept2 & 0xf
    c = (a + kept21 & ~kept17) + (((6 - kept22 | kept17) & 7) * 2 | 3) + 0xf & 0xf ^ 0xe
    kept27 = (c | ((kept21 + a | ~kept17) & 9 ^ 0xf) + kept25 - 0xf & 0xf) * 2 & 0x16
    a = reused50 & 0xff & ~kept17
    kept28 = (a + (((0x76 - kept24 | kept17) & 0x7f) * 2 | 3) + 0x7f ^ 0x7e | kept26 - 0x3f) - kept27 + 0xb & 0xff ^ 0xad
    a = b2[0x16] & kept2 & 0x3f
    c = (kept24 - 0x77 & ~kept17) + ((a << 1 ^ 0x7e) + kept21 * 0xfe | kept17 << 1 & 0x7e | 3) & 0x7f
    kept29 = (-c ^ 1 | kept26 - 0x3f) - kept27 + 0xb & 0x7f ^ 0x2d
    a = reused54 & 3
    c = (-~kept22 & ~kept17) + (((2 - a | kept17) & 3) * 2 | 3) + 7 & 7 ^ 6 | -kept23 - kept25 * 3 & 7
    d = c - (a - 3 & 3 & ~(kept17 & 3) | kept23 ^ kept23 << 1 ^ kept25) * 2 + 3 & 7 ^ 5
    e = b2[b1[0x59] % 0x23] * 2 + ((kept2 | d) & 0x84) * 2 + (kept2 & d & 2) * 4 + (kept29 & kept2 & 0x79) * 2 + (kept29 & kept2 & 2) * 0x7e & 0xca
    f = b2[b1[0x59] % 0x23] + ((kept28 & kept2 ^ (kept2 | d)) & 4) + (kept28 & kept2) - e + 0x65 & 0xff
    b1[0x2f] = f ^ b1[0x2f] ^ 0x65
    reused81 = held1 & 0xb3 ^ 0x44
    a = _asr(reused81, 7 & 6 - b0[0xc], 0x20)
    c = reused81 << (b0[0xc] + 2 & 7)
    d = b0[3] & (c ^ a) | ~b0[3] & held0
    b3[4 * 9] = (b4[8] - 0x14 ^ 0x7f) + d & 0xff
    b1[0x7b] = b1[0x7b] ^ 0xdd
    kept30 = b3[4 * 6]
    kept31 = b2[kept3 % 0x23]
    a = (kept2 | b2[0xa]) & 0x5c | kept2 & b2[0xa] & 0x23
    c = (kept2 | 0x5c) & b2[0xa] | kept2 & 0x5c
    d = (kept31 + 0xf ^ 0x7f) + kept17 // 3 + (_maj(b2[0x11], c, kept30) ^ 0x80) & 0xff
    b3[4 * 0xa] = d - _maj(a, b2[0x11], kept30) * 2 + 0x10 & 0xff
    a = (kept2 >> 1 & 0x65 ^ 0x2f) + (kept2 & 0x4a)
    c = (kept2 >> 1 & 1 ^ 0x10 ^ a - 0x2f & 0x65) << 1
    d = (0x100000000 - c - 0x13 + (a - 0xa) & 0xffffffff ^ 0xffffff00) + 0x7c ^ 0x100
    b3[4 * 0xb] = ((kept29 ^ 0x5e) - kept29 + kept28 ^ d) & 0xff ^ 0xdd
    kept32 = kept31 & b4[0x12]
    b3[4 * 12] = kept32 ^ 0x7f
    b3[4 * 13] = kept32 * 2 & 0xfe
    b3[4 * 14] = b4[0x12]
    kept33 = b3[4 * 10]
    b3[4 * 0xf] = ((kept17 | b2[0x13]) & 0xfc | kept17 & b2[0x13] & 3 | kept33 & kept30 | (kept33 | kept30) & b2[0x13]) & b4[0x14] ^ 0x30
    b3[4 * 16] = b2[0x13]
    b3[4 * 18] = b2[0x13] * 2 & 0xe0
    b3[4 * 17] = b2[0x13] & 0xfc ^ 0x71
    b3[4 * 19] = kept2 % 0x15
    a = (_maj(b2[0x13], kept30, kept33) & 0xfe) * 2 & 7
    c = b4[(b3[4 * 0x13] ^ 0x7e) + (b3[4 * 0x13] * 2 & 0x3c) + 0x82 & 0xff]
    reused82 = b2[0x13] & (kept30 | kept33)
    d = reused82 & 0xf
    e = d | kept30 & kept33 & 0xf
    reused26 = c & b3[4 * 0x10]
    reused11 = reused26 | ~-b3[4 * 0x11] + b3[4 * 0x12]
    f = (reused11 & 0xf | kept17 & 0xc) & (0xa - a + e & 0xf ^ 0xa)
    g = reused26 & 0x1f
    h = ((d << 1 & 0xc) + (~reused82 ^ 9) + 0xa | kept30 & kept33) - (e * 2 & 0x14) & 0x1f
    reused12 = b3[4 * 0x11] + 0xf + b3[4 * 0x12]
    j = ((g | reused12 | kept17 & 0x1c) & (5 - h ^ 5)) - (f * 2 & 0x1c) + 0xe & 0x1f ^ 0xe
    k = ((reused26 ^ 0x2f) + (g * 2 & 0x1e) - 0x2f | reused12) & 0x3f | kept17 & 0x3c
    m = (k & ((~e & 0xea) * 2 + _maj(b2[0x13], kept30, kept33) - 0xa & 0x3f ^ 0xa)) - (f * 2 & 0x1c)
    reused83 = b3[4 * 0xf] ^ 0x30
    n = ((m + 0xe ^ 0xe | reused83) ^ 0x1d) + ((j | b3[4 * 0xf] & 0x1f ^ 0x10) * 2 & 0x3a) - 0x1d & 0x3f & ~(b3[4 * 0xe] & 0x3f)
    p = (~e & 0xca) * 2 + _maj(b2[0x13], kept30, kept33) - 0xa & 0x7f ^ 0xa
    q = ((reused26 | reused12) & 0x7f | kept17 & 0x7c) & p
    r = _maj(b2[0x13], kept30, kept33) - a + 2 & 7 ^ 2
    s = f - (((reused11 & 7 | kept17 & 4) & r) * 2 & 0xc) + 0xe & 0xf ^ 0xe | b3[4 * 0xf] & 0xf
    u = n - ((((j | b3[4 * 0xf] ^ 0x10) ^ 0x1d) + (s * 2 & 0x1a) - 0x1d & 0x1f & ~(b3[4 * 0xe] & 0x1f)) * 2 & 0x2a) + 0x35 & 0x3f ^ 0x35
    v = (~e & 0x8a) * 2 + _maj(b2[0x13], kept30, kept33) - 0xa & 0xff ^ 0xa
    w = ((reused26 | b3[4 * 0x11] + b3[4 * 0x12] - 0x71 | kept17 & 0xfc) & v) - (q * 2 & 0x9c) + 0x4e & 0xff ^ 0x4e | reused83
    x = ((w ^ 0x5d) + ((q - (f * 2 & 0x1c) + 0x4e & 0x7f ^ 0x4e | b3[4 * 0xf] & 0x7f ^ 0x30) * 2 & 0xba) - 0x5d & 0xff & ~b3[4 * 0xe]) - (n * 2 & 0x6a)
    y = kept3 + ((x + 0x35 ^ 0x35 | b3[4 * 0xc] + b3[4 * 0xd] - 0x7f) ^ 0x2f) & 0xff
    b3[4 * 0x14] = y + ((u | -~b3[4 * 0xc] + b3[4 * 0xd] & 0x3f) * 2 & 0x5e) - 0x2f & 0xff
    b2[0x21] = b2[0x21] ^ b1[0x1a]
    b1[0x6a] = b1[0x6a] ^ kept21 ^ 0x85
    kept34 = b3[4 * 20]
    a = b4[0xd] << 1 & 0x20
    reused84 = kept34 // 3 + 0x2f
    c = reused84 + ((((kept2 & 0x28 | 0x17) & b4[0xd] ^ a) + 0x10 ^ 0x10 | kept2 & 0x17) ^ 0xe) & 0x3f
    d = reused84 + ((((kept2 | 0x57) & b4[0xd]) - a + 0x10 ^ 0x10 | kept2 & 0x57) ^ 0x8e) & 0xff
    e = d - ((0x10 - a + (b4[0xd] & (0x57 | kept2 & 0x28)) & 0x7f ^ 0x10 | kept2 & 0x57) * 2 & 0xe2) + 0x43 & 0xff
    b2[0x1e] = e - ((c - ((kept2 << 1 | b4[0xd] << 1) & 0x22) + 3 & 0x3f) * 2 & 0x44) + 0x22 & 0xff ^ (b0[b1[0x7a] % 0x14] ^ 0x22)
    b1[0x16] = b2[b1[0x5a] % 0x23] & 0x1b ^ 0x44
    kept35 = b3[4 * 9]
    kept36 = b3[4 * 11]
    reused55 = b2[kept36 % 0x23] & ~b2[0x22]
    a = reused55 & 0xf
    reused85 = b4[kept35 % 0x15] & b2[0x22]
    c = reused85 & 0xf
    d = reused85 | reused55
    reused56 = d * d * d >> 1
    e = (reused56 - (((c | a) * (c | a) & 0xd) * (~-(c ^ 1) + (b4[kept35 % 0x15] << 1 & 2) * (b2[0x22] & 1) | a) & 0xc) & 0x7f) + 0x46
    b2[0x12] = b2[0x12] + (reused56 - ((d * d & 0xfd) * d & 0x8c) + 0xc6 ^ 0xb8) + (e + e & 0xfc ^ 0x8c) - 0x7e & 0xff
    b2[5] = b2[5] - kept4 & 0xff
    reused23 = b2[b1[0xb7] % 0x23] & b0[7]
    a = reused23 & 0x1f
    reused86 = b1[0x29] & ~b0[7]
    c = reused23 + ((a ^ 0xe) - a - 0xe) + 0x2e & 0x3f ^ 0x2e | reused86 & 0x3f
    reused87 = ~b0[7] & b1[0x29]
    d = 0x7f & (reused87 | reused23)
    e = (1 - d ^ 1) + (c << 1 & 0x7c) & 0x7f & (0x7f & 0xe - b3[4 * 4] ^ 0x3f)
    f = ((0x7e + 2 * d - 2 * (-2 | d) + (0x7e ^ (reused23 | reused87)) & b3[4 * 4] + 0x31 ^ 0x7f) + e * 2 & 0xff) - 0x7f
    g = ((e ^ 0x7f) + ((~c ^ 1) + ((a | reused86) & 0xfe) * 2 + 2 & b3[4 * 4] - 0xf & 0x3f) * 2 & 0x7f) - 0x7f
    h = ((g | b2[kept21 % 0x23] & kept21) * (b0[b1[0x3b] % 0x14] ^ ~kept36 & (b0[b1[0x3b] % 0x14] ^ b1[0x11])) & 0x7f) * 2 & 0xa4
    b2[0x12] = (f | b2[kept21 % 0x23] & kept21) * (b0[b1[0x3b] % 0x14] & kept36 | b1[0x11] & ~kept36) - h + 0x52 & 0xff ^ (b2[0x12] ^ 0x52)
    a = b1[0xb] << (7 & -b2[b1[0x1c] % 0x23])
    reused88 = b2[b1[0x1c] % 0x23] & 7
    c = _asr(b1[0xb], reused88, 0x20)
    d = ~(c ^ a) & 7
    e = _asr(b2[kept2 % 0x23], 7 & -~d, 0x20)
    f = _asr(b1[0xb], reused88, 0x20)
    g = a
    h = b2[kept2 % 0x23] << ((g ^ f) & 7)
    j = b1[7] & b2[0xb] & 0x7f
    reused3 = b0[b1[0x5d] % 0x14] & ~b0[0xe]
    k = reused3 & 0x7f
    m = reused3 & 0xf
    n = ((m | b0[0xe] & 6) - ((m & 9 ^ reused3 & 1) * 2 & 0xe) & 0xf & ~(b2[0xb] & 0xf)) * 2 & 0x1a
    p = reused3 + ((m ^ 5) - m - 5) + 0x25 & 0x3f ^ 0x25 | b0[0xe] & 0x16
    q = (p & 0x39 ^ reused3 & 0x21) * 2
    r = a
    s = (3 | ~((f & 3 ^ 1 ^ r & 3) * 2)) & 0xffffffff ^ 0xfffffff8
    u = _asr(b2[kept2 % 0x23], s + (f ^ 1 ^ r) & 7, 0x20)
    v = b2[kept2 % 0x23] << (7 & (c ^ a))
    w = (v ^ u) & 0x7f
    x = w & ((((k | b0[0xe] & 0x16) - q + 0x18 ^ 0x18) & ~b2[0xb]) - n + 0xd & 0x7f ^ 0xd | j)
    y = reused3
    z = (b0[0xe] & ~k & ~b2[0xb] & ~j & (~h | e) & (h | ~e) & 0x7f96 | (j | k & ~b2[0xb] | h ^ e)) & 0x7f
    n21 = (v ^ u) & 0x3f
    n22 = v & 0xff ^ u
    n23 = 2 * (-9 & x) + (0x77 ^ n22 & (b2[0xb] & b1[7] | 0xd ^ 0xd - n + (~b2[0xb] & (0x18 ^ 0x18 - q + (y | b0[0xe] & 0x96))))) & 0xff
    n24 = h & 0xff ^ e
    n25 = b2[0x16] + ((n23 - 0x77 | ((b0[0xe] & 0x96 | y) & ~b2[0xb] | b1[7] & b2[0xb] | n24) & b2[0x21]) ^ 0x77) & 0xff
    n26 = b1[7] & b2[0xb] & 0x3f
    n27 = (x ^ 0x77) + ((n21 & (((0xd8 - q + p ^ 0x18) & ~b2[0xb]) - n + 0xd & 0x3f ^ 0xd | n26)) * 2 & 0x6e) - 0x77 & 0x7f
    b2[0x16] = 0x79 + n25 + 2 * (8 | n27 | z & b2[0x21]) & 0xff
    a = (b0[b1[0x27] % 0x14] ^ 0xd9) % 0x15
    c = kept2 & kept21 & 0x7f
    reused89 = b2[6] & (kept2 | kept21)
    d = reused89 * 2 & 0x7f
    e = reused89 & 0x7f
    f = (kept2 | kept21) & b2[6] | kept2 & kept21
    g = b4[0xfe - (a ^ 0x7f) - 0x7f]
    h = 0xa1 + 2 * (0xdf & (c | (e ^ 0xdf) + 0xa1 + (d & 0x3f))) + (0x5f ^ f) & 0xff & b4[0xbe - (a ^ 0x5f) - 0x5f]
    j = ((f | g) ^ 0x6f) + 2 * (0xef & (c | g | 0xd0 ^ 0x50 - (d & 0x20) + e)) + 0x91 & 0xff & b3[4 * 8] | h
    b0[0xf] = b0[0xf] - j & 0xff
    held6 = b0[b1[0x63] % 0x14]
    held5 = b2[kept34 % 0x23]
    held2 = b0[kept34 % 0x14]
    held3 = b2[b1[0x39] % 0x23]
    a = (_maj(b0[1], held2, held3) & 0x3f | kept34 & 0x2d) ^ 0x1b
    c = kept34 << 1 & 2 ^ 0x20
    d = 2 * (0xa & b0[1] & (held2 | held3))
    e = (b1[0x16] | kept34) & 0x3f
    f = ((((held3 | held2) & b0[1] | held3 & held2 | kept34 & 0x2d) ^ 0x5b | 0x52) ^ 0x75) + (a << 1 & 0x58 ^ 0xb0) + 0x84 & 0xff & b2[0x1f]
    g = (c ^ 0x63) + (kept34 & 0x2d) ^ 0x11
    h = ((kept2 << 1) // 3 & 0x7a) + ((b1[0x16] | kept34) ^ 0x80) - ((b1[0x16] | kept34) * 2 & 0xfe) + (kept2 // 3 ^ 0x3d) + 0x43 & 0xff
    j = h - ((kept2 // 3 - e & 0x3f) * 2 & 0x6e) + 0x37 & 0xff
    reused90 = b0[1] & (held2 | held3)
    k = 2 * (0xc2 & (held2 & held3 | 0xca ^ 0xca - d + reused90)) & 0xff
    m = reused90 - d + 0xa & 0x3f ^ 0xa | held2 & held3 & 0x3f
    n = (_maj(b0[1], held2, held3) & 0xe2) * 0x1e + (2 ^ m + 2) & 0x3f
    p = n & ((kept34 & 0x2d ^ 0x12 ^ c) + 0x11 & 0x2f ^ 0x11)
    q = (_maj(b0[1], held2, held3) - k + 0x42 & 0xff ^ 0x42) & g | f
    r = _maj(b0[1], held2, held3) & 0xf | kept34 & 0xd
    s = (r - ((_maj(b0[1], held2, held3) | kept34 & 5) * 2 & 6) + 0xb & 0xf | 0x12) << 1 & 0x38 ^ 0x10
    u = q - ((p | (a & 0x2d ^ 0x27) + s + 4 & b2[0x1f] & 0x3f) * 2 & 0x6e) + 0x37 & 0xff
    held4 = b0[(j ^ b3[4 * 7] - (b3[4 * 8] * 2 & 0x8c) + 0x5c & 0xff ^ u ^ 0x46) % 0x14 + 0x100 ^ 0x100]
    a = 0x1f & held6 * held6
    reused111 = (a * a & 0x11) * 2
    reused112 = held6 * held6 & 0xfd
    reused110 = (reused112 * reused112 & 0xf1) - reused111 + 0x9f & 0xff ^ 0x9f | held5
    b3[4 * 0x15] = reused110
    c = (held6 * held6 * (held6 * held6) - reused111 + 0x9f ^ 0x9f | held5) & 0xff
    reused17 = reused110 // 0x23
    reused0 = (reused17 * 0xffffffdd & 0xffffffff) + c
    d = reused0
    held11 = b2[(d ^ 0x73) + (d << 1 & 0x66666666) + 0x8d & 0xff]
    kept37 = b4[b1[0x7f] % 0x15]
    d = reused17
    reused31 = (d * 0x1d + c & 0x3f) * 2
    reused91 = d * 0xffffffdd + c
    e = ((reused91 ^ 0x67) + (reused31 & 0x4e) & 0xffffffff) + 0x99
    held12 = b2[e & 0xff]
    reused24 = kept37 << (held12 & 7)
    reused25 = 7 & -held11
    kept38 = (reused24 & 1 ^ _asr(kept37, reused25, 0x20) & 1) & ~(b0[0xa] & 1)
    kept39 = kept38 << 1
    e = ((reused91 ^ 0x7a) + (reused31 & 0x74) & 0xffffffff) + 0x86
    held13 = b2[e & 0xff]
    held14 = b0[b1[0xd1] % 0x14]
    d = reused0
    held15 = b2[d + 0x11111200 & 0xff]
    a = ((reused24 ^ _asr(kept37, reused25, 0x20)) & ~b0[0xa]) - kept39 + 1 & 3 ^ 1
    kept40 = b0[0xa] & (b0[7] & (held14 | held15) | held13 & held14) & ~a & 3 | a
    a = ((reused24 ^ (_asr(kept37, reused25, 0x20) ^ 4) ^ 4) & ~b0[0xa]) - kept39 + 1 & 7 ^ 1
    kept41 = b0[0xa] & (b0[7] & (held14 | held15) | held13 & held14) & ~a & 7 | a
    a = _asr(kept37, reused25, 0x20)
    c = reused24
    d = 2 * (0x31 & ~b0[0xa] & (c ^ a))
    e = (~b0[0xa] & (c ^ a)) - d & 0x7f
    f = 2 * (0x1c & b0[0xa] & (b0[7] & (held14 | held15) | held13 & held14))
    g = (b0[0xa] & (b0[7] & (held14 | held15) | held13 & held14)) - f - 0x24 & 0x7f ^ 0x5c
    kept42 = (g | 0xe - e ^ 0xe) & 0x47
    kept43 = ((kept40 | 0x75) ^ kept41) * 2
    held16 = b2[kept35 % 0x23]
    kept44 = b4[held16 % 0x15]
    a = kept44 << 2 & 0x30
    c = (kept44 << 1 & 0xb8 ^ 0x5f) + a - 0x5f & 0xb8
    reused32 = (kept43 ^ 4) % 0x1f + kept42 ^ 0x15
    kept45 = reused32 | c
    held9 = b0[b1[0x32] % 0x14]
    held8 = b2[b1[0x8a] % 0x23]
    held7 = b0[b1[4] % 0x14]
    held10 = b0[b1[0x97] % 0x14]
    b3[4 * 22] = kept45
    kept46 = b4[b1[0xbe] % 0x15]
    kept47 = b4[kept34 % 0x15]
    held17 = b2[b1[0xe] % 0x23]
    reused92 = b0[kept21 % 0x14] << 1
    a = reused92 & b4[6] & 0xe
    c = b0[kept21 % 0x14] & 0x3f
    d = ((b0[kept21 % 0x14] << 2 & 4 ^ 0x5e) + (c << 1) + 0x65 & 0x7f ^ 0x43) & (b4[6] & 0x7f)
    e = (kept46 & 0x79 | 6) & ~b4[6] | d
    f = (kept47 & 0xe | b0[b1[0x19] % 0x14] & 1) & ~b0[0]
    g = kept47 << 1 & 0x54
    h = (((kept47 & 0x6e | b0[b1[0x19] % 0x14] & 0x11) - g + 0x2a ^ 0x2a) & ~b0[0]) - (f * 2 & 0x1c) + 0xe & 0x7f ^ 0xe
    j = h | b0[0] & b1[0x19] & 0x7f
    k = (((kept47 & 0x6e | b0[b1[0x19] % 0x14] & 0x91) - g + 0x2a ^ 0x2a) & ~b0[0]) - (f * 2 & 0x1c) + 0xe & 0xff ^ 0xe | b0[0] & b1[0x19]
    m = (((c << 2 & 0x84 ^ 0xde) + (reused92 & 0xfe) + 0x65 ^ 0x43) & b4[6] ^ 0x3f) + (d * 2 & 0x7c) - 0x3f & 0xff
    n = b2[2] + ((k - (j * 2 & 0x9c) + 0x4e ^ 0x4e) & (((kept46 | 6) & ~b4[6] | m) - (e * 2 & 0x90) + 0x48 ^ 0x48) ^ 0x67) & 0xff
    p = (kept47 & ~b0[0] & 0xfe) * 2 + (~f ^ 1) + 2 & 0xf
    q = ((a | kept46 & ~b4[6]) & 0xc8) * 0xe + (e & 0x77) + (e & 8) * 3 & 0x7f
    b2[2] = n + ((((~(p | b0[0] & b1[0x19]) & 0xce) * 2 + j + 0x32 & 0x7f ^ 0x4e) & q) * 2 & 0xce) - 0x67 & 0xff
    kept48 = b3[4 * 22]
    held18 = b0[b1[0x91] % 0x14]
    a = b2[0xe] + (((b2[b1[0x64] % 0x23] ^ kept48) & b2[kept21 % 0x23] & 0xdd | b1[0x61] & 0x22) ^ 0xfc) & 0xff
    b2[0xe] = a + (b1[0x61] & 0x82) * 0x7e - (b2[kept21 % 0x23] & (b2[b1[0x64] % 0x23] ^ kept48) & 0x81) * 2 + 4 & 0xff
    b0[0x11] = b0[0x11] + b4[8] & 0xff
    a = b0[kept21 % 0x14] & 0x1f
    c = b4[b1[0x11] % 0x15] & 0x1f
    d = kept48 & (c | a)
    e = b0[kept21 % 0x14] & 0x3f
    f = (_maj(b4[b1[0x11] % 0x15], e, kept48) | b1[0x32] // 3) & 0x3f & (b2[0xa] & 0x3f)
    g = _maj(b4[b1[0x11] % 0x15], e, kept48) & b1[0x32] // 3 & 0x3f | f
    h = b0[kept21 % 0x14] & 0x7f
    j = b4[b1[0x11] % 0x15] & 0x7f
    k = kept48 & (j | h)
    m = ((g ^ 0x3f) + (((d | a & c) & b1[0x32] // 3 | (d | c & a | b1[0x32] // 3) & b2[0xa]) & 0x1f) * 2 + 0x34 + 0xd & 0x3f) * 4 & 0xb8
    n = (((k | h & j) & b1[0x32] // 3 | ((k | j & h | b1[0x32] // 3) & b2[0xa]) - (f * 2 & 0x38) + 0x5c ^ 0x5c) ^ 0x7f) + g * 2 & 0x7f
    b1[0x17] = b1[0x17] ^ 0x23 ^ -~(0xde - m) + (n << 1) & 0xff ^ 0xfe
    b0[0xd] = (((b0[kept33 % 0x14] | b1[0xa]) & b4[0xe] | b0[kept33 % 0x14] & b1[0xa]) & b4[2] | b0[b1[0x27] % 0x14] * 2 & (b4[2] ^ 0xff)) >> 1
    a = 1 - (b4[8] >> 2 & 0x18 ^ 1)
    b2[0x21] = b2[0x21] + (((a & 0xf8) + 0x5d & 0x5d ^ 0x5c) & b1[0x71] ^ 0xda) - (b1[0x71] << 1 & 2) + 0x26 & 0xff
    a = b4[7] & b1[0x6e] & 1
    c = b4[7] & b1[0x6e] | (b4[7] | b1[0x6e]) & 0xde
    d = 0
    e = (b4[7] | b1[0x6e]) & 6 | a
    f = _asr((c + 0xba48cc4 - (c & 0xc5 ^ a) * 2 ^ 0xba48cc4) + d, 1, 0x20)
    g = (b4[7] | b1[0x6e]) & 0x5e | b4[7] & b1[0x6e] & 0x21
    h = (f - ((g + 0x44 - (g << 1 & 0xa ^ a << 1) ^ 0x44) + d & 0x46) + 0x63 & 0x7f ^ 0x63) & ~(b0[8] & 0x7f)
    j = ((h ^ 0x7d) + (((f - (((e ^ 4) - ((e & 5 ^ a) * 2 & 6) ^ 4) + d & 6) + 0x23 & 0x3f ^ 0x23) & ~(b0[8] & 0x3f)) * 2 & 0x7a) & 0x7f) - 0x7d
    k = ((f - ((c + 0xc4 - (c << 1 & 0x8a ^ a << 1) ^ 0xc4) + d & 0xc6) + 0xe3 & 0xff ^ 0xe3) & ~b0[8] ^ 0x7d) + (h * 2 & 0xfa)
    b2[0x1c] = b2[0x1c] + ((k - 0x7d | kept21 & b0[8]) ^ 0xa2) - (((j | kept21 & b0[8]) & 0x7f) * 2 & 0xba) + 0x5e & 0xff
    kept49 = b4[b1[0xca] % 0x15]
    kept50 = (held10 | kept49) << (held9 & 7)
    kept51 = kept50 & 0x7f
    kept52 = kept51 * 2 & 0xac
    kept53 = _asr(kept49 | held10, 7 & -held9, 0x20)
    kept54 = b4[b1[0x27] % 0x15]
    kept55 = (kept54 ^ b4[0xa] & (kept54 ^ b1[0x21])) + 0x47 & 0xff
    kept56 = held4 ^ ~b2[0x10] & (held4 ^ held8)
    kept57 = ((kept55 + 0xb9 & 0xff) + kept56) // 5
    kept58 = 2 * (kept57 & 0xb8)
    reused94 = 0xb8 - kept58 + kept57
    kept59 = reused94 ^ 0xb8
    kept60 = reused94 & 0xff ^ 0xb8
    kept61 = (7 - kept57 ^ 7) + kept58 & 0x7f
    kept62 = kept59 | held7
    kept63 = kept61 | held7 & 0x7f
    kept64 = kept62 & b0[0x10] | kept59 & held7
    kept65 = ((kept60 | held7) ^ 0x5e) + (kept63 * 2 & 0xbc) - 0x5e & 0xff & b0[0x10] | kept60 & held7
    a = (kept63 ^ 0x5e) + ((kept57 + kept57 | held7 << 1) & 0x3c) - 0x5e & 0x7f
    kept66 = a & b0[0x10] | kept61 & held7
    a = (0x7f - kept53 & 0xffffffff ^ 6 + (0x50 - kept52) + kept50 & 0xffffffff ^ 0x29) + kept64 * 2
    kept67 = (a + (kept64 ^ 0x7f) & 0xffffffff) - 0x7f
    kept68 = (kept67 ^ 0x7f) + kept10 + (kept67 << 1) + 0x81 & 0xff
    a = (kept53 ^ 0x7f ^ kept50 - kept52 + 0x56 ^ 0x29) + (kept65 * 2 & 0xfe) + (kept65 ^ 0x7f) - 0x7f & 0xff ^ 0x7f
    c = ((~kept53 ^ kept51 - ((kept50 & 0x1f) * 2 & 0x2c) + 0x56 ^ 0x29) + (kept66 * 2 & 0x7e) + (kept66 ^ 0x7f) & 0x7f) - 0x7f
    kept69 = a + kept10 + (c & 0x7f) * 2 & 0xff
    kept70 = kept69 + 0x81 & 0xff
    kept71 = b4[kept21 % 0x15]
    a = (kept70 // 0x15 * 0xffffffeb & 0xffffffff) + kept68
    reused7 = (kept70 // 0x15 * 0xb + kept68 & 0x1f) * 2
    c = b4[(a ^ 0x73) + (reused7 & 0x26) + 0x8d & 0xff]
    d = b4[(a ^ 0x7d) + (reused7 & 0x3a) + 0x83 & 0xff]
    e = b4[(a ^ 0x7f) + (a << 1) + 0x81 & 0xff]
    f = b4[(a ^ 0x3e) + (reused7 & 0x3c) + 0xc2 & 0xff]
    reused52 = b2[0x17] & (f | kept33)
    g = reused52 * 2 & 7
    h = e & kept33 & 0x3f
    reused27 = reused52 - g + 3 ^ 3
    j = ((reused27 | h) * (h | b2[0x17] & (c | kept33) & ~h) & 0x3f) * 2 & 0x62
    k = (0xff & kept71 + 0x50 ^ 0x80) & (b1[0xb8] ^ 0xff)
    m = 0 - (-((reused52 | kept33 & e) & 1) & 0xffffffff)
    reused33 = kept33 & (e | b2[0x17]) | c & b2[0x17]
    n = m * reused33 << 1 & 2
    p = reused33 & 0xf
    q = ((f | kept33) & b2[0x17] | e & kept33) * (e & kept33 | (c | kept33) & b2[0x17]) + 0xb1 - j & 0xff ^ 0xb1
    r = (reused27 | e & kept33) * p + 1 - n & 0xf ^ 1
    s = q * ((d | kept33) & b2[0x17] | c & kept33) - ((r * (b2[0x17] & (d | kept33) | kept33 & c) & 0xf) * 2 & 0x12) & 0xff
    b0[0xf] = (s + 9 & 0xff ^ 9) & (k | (kept71 + 0xd0 & 0xff | ~b1[0xb8]) & b4[0x10])
    b2[0x16] = b1[0xb7] + b2[0x16] & 0xff
    a = b4[b1[1] % 0x15] * 3 - 9 & 0xff
    b3[4 * 0x17] = (b4[b1[1] % 0x15] << 1 & 2 ^ 0xb) + ~-(a ^ 1) & 0xff ^ kept2
    a = (kept70 // 0x23 * 0xffffffdd & 0xffffffff) + kept68
    c = b2[(a ^ 0x7b) + (a << 1 & 0x77777777) + 0x85 & 0xff]
    d = b4[b1[0xb2] % 0x15] & 0x1f
    e = b2[(a ^ 0x69) + ((kept70 // 0x23 * 0x1d + kept68 & 0x3f) * 2 & 0x52) + 0x97 & 0xff]
    reused95 = (d | e) & 0x11
    f = (reused95 | b4[b1[0xb2] % 0x15] & c) * b0[b1[0xd] % 0x14] & 0x3f
    g = b4[b1[0x1a] % 0x15] >> 1
    h = b4[b1[0xb2] % 0x15] & 0x7f
    reused97 = f * 2 & 0x68
    j = (((e | h) & 0x51 | h & c & 0x2e) * b0[b1[0xd] % 0x14] + 0x34 - reused97 ^ 0x34) * g & 0x7f
    k = f - 0xc - (((reused95 | d & c & 0xe) * b0[b1[0xd] % 0x14] & 0x1f) * 2 & 0x28) & 0x3f ^ 0x34
    m = j + 0x6d - ((k * g & 0x3f) * 2 & 0x5a) & 0x7f ^ 0x6d
    n = (((e & 0xd1 | b4[b1[0xb2] % 0x15] & (c & 0x2e | 0xd1)) * b0[b1[0xd] % 0x14] + 0x34 - reused97 ^ 0x34) * g & 0xff) + 0x6d
    p = n - (j * 2 & 0xda) & 0xff ^ 0x6d
    q = kept35 + (((0 - (p * 0x8c & 0xd0) & 0xf0) + (p * 0xc6 & 0xfe) & 0xfe) + 0xe8 & 0xfe ^ 0x97) & 0xff
    b3[4 * 0x18] = q + ((((0 - (m * 0xc & 0x50) & 0x70) + (m * 0x46 & 0x7e) & 0x7e) + 0x68 & 0x7e) << 1 ^ 0xd0) - 0x7f & 0xff
    b3[4 * 25] = b2[kept34 % 0x23] & 0xf5 | b2[kept21 % 0x23] & 0xa
    kept72 = b3[4 * 21]
    kept73 = b3[4 * 24]
    a = (b0[kept72 % 0x14] << 1 & 0x18 ^ b0[kept72 % 0x14] << 2 & 0x18 ^ 1) * (b0[kept72 % 0x14] & 0xf | 0x11) & 0x1f
    c = b0[kept72 % 0x14] & 0x3f
    d = ((c | 0x11) * (c | 0x11) & 0x39) * (c | 0x11) & 0x3f
    e = b0[kept72 % 0x14] | 0x51
    f = ((0x10 - d ^ 0xe ^ 0x20 & a + a) & ~b0[0xf] ^ 0x1f) + (a + a & (~(b0[0xf] << 1) & 0x3e)) - 0x1f & 0x3f
    g = ((((c | 0x51) * (c | 0x51) & 0x79) * (c | 0x51) - (d << 1 & 0x62) + 0x31 & 0x7e ^ 0x31) & ~(b0[0xf] & 0x7f)) * 2 & 0xbe
    h = (-0x5f + g + (0x5f ^ ~b0[0xf] & (0x31 ^ -2 & 0x2f - 2 * d - 2 * (0x31 | ~d) + e * (e * e))) & 0xff | kept73 // 0xf & b0[0xf]) ^ 0xc9
    b2[0x12] = b2[0x12] + h - ((f | kept73 // 0xf & (b0[0xf] & 0x3f)) * 2 & 0x6c) + 0x37 & 0xff
    a = b4[b0[kept70 % 0x14] % 0x15]
    reused34 = 0x80 - a // 3 + b0[b1[0xa0] % 0x14]
    c = kept69 + reused34 & 0xff
    b3[4 * 0x1a] = c - (reused34 & 0x7f) * 2 + 1 & 0xff
    a = b4[b1[0x45] % 0x15] & 0x7f
    c = 0xf & held17 * held17
    d = ((kept40 | 5) ^ kept41) * 2
    e = (((~-kept41 ^ 1) + (d & 6) & 7 ^ held18 & 7) & (~b0[2] & 7)) * 2 & 0xa
    f = kept44 << 1 & 0xe ^ 0xf
    g = (((kept41 + (d ^ 5) + 6 ^ 5 | 8 & ~f) ^ held18) & ~b0[2] ^ 5) + e - 5 & 0xf
    h = (g << 1 | c + c & b0[2] << 1) & 0x1a
    j = 0x7f & held17 * held17
    k = kept44 << 1 & 0x1e ^ 0x1f
    m = kept44 << 1 & 0x3e ^ 0x1f
    reused35 = kept40 << 1 & 4 ^ kept41 << 1
    n = (kept41 + (reused35 ^ 0x3f) + 0x16 & 0x3f ^ 0x15 | (k + (k ^ 6) ^ 0x10) + (m & 0xb8) & 0x3f) ^ held18 & 0x3f
    p = n & ~b0[2]
    q = ((reused32 | 0xb8 & (m ^ 0x1c)) ^ held18 & 0x7f) & ~(b0[2] & 0x7f)
    r = 0xa - (q ^ 0xa) + (p << 1 & 0x6a) & 0x7f | j & b0[2] & 0x7d
    reused36 = kept6 + (r ^ 0x32) - h + 0x1b
    s = (((a | b1[0xac]) & reused36 | a & b1[0xac] ^ 1) & 0x7b | 1) & (kept48 & 0x7f)
    u = (kept41 + (reused35 ^ 0x1f) + 0x16 & 0x1f ^ 0x15 | 0xd8 & k - 0xe8 ^ 0x10 & f + f) ^ held18 & 0x1f
    v = u & ~b0[2]
    w = ((v ^ 5) - 5 + e | (held17 * held17 + 4 + 6 * (c & 4) ^ 4) & b0[2]) & 0x1f ^ 0x12
    reused41 = b4[b1[0x45] % 0x15] | b1[0xac]
    x = ~(h - 0x1c) + (kept6 + w) & reused41 & 0x1f
    y = b4[b1[0x45] % 0x15] & 0x3f
    z = (0xa - (p ^ 0xa) + (v << 1 & 0x2a) | ((c ^ 0x14) - c + 0x10 + held17 * held17 ^ 0x24) & b0[2]) & 0x3f
    n21 = (kept6 + (z ^ 0x32) - h + 0x1b & (y | b1[0xac]) ^ 0x2f) + (x * 2 & 0x1e) - 0x2f & 0x3f | y & b1[0xac]
    reused42 = b4[b1[0x45] % 0x15] & b1[0xac]
    n22 = (((x | reused42) & 0xf7) * 2 + (n21 ^ 0x37) & 0x3f) - 0x37
    n23 = (b0[0xa] & (b0[7] & (held14 | held15) | held13 & held14) | kept38 | kept39) & 1
    n24 = ~b0[2] & (n23 ^ held18) & 1
    n25 = n24 | held17 & b0[2] & 1
    n26 = ((reused41 & (~kept6 | n25) & (kept6 | ~n25) | reused42) & 1) << 1
    n27 = kept6 + (b0[2] & held17 & 0xfd) + n24 * 2 + n25 * 2 - (~b0[2] & (kept40 ^ held18)) + 1 & 3
    n28 = (~n27 ^ (n27 ^ b4[b1[0x45] % 0x15]) & (n27 ^ b1[0xac]) ^ n26) - 3 & 2
    n29 = reused36 & 0x7f & (a | b1[0xac] & 0x7f) | a & b1[0xac]
    n30 = reused42
    n31 = (q & 0xf5) * 2 + (~b0[2] & (kept45 ^ held18) ^ 0xf5) + 0xb & 0xff | (((held17 * held17 & 0xfd) - (j * 2 & 0x48) & 0xfd) + 0x24 & 0xfd ^ 0x24) & b0[2]
    n32 = kept6 + (~n31 ^ 0xcd) - (r << 1 & 0x9a) + 0x1b & 0xff
    n33 = reused41
    reused37 = (n28 + 0x79 ^ n22 & 0x2a) * 2
    n34 = ((((n32 & n33 | n30) ^ 0x77) + (n29 * 2 & 0xee) - 0x77 & 0xfa) + (reused37 & 0xfe ^ 0xd) + 0x2a & 0xff ^ 0x29 | kept48 | 1) & b0[2]
    n35 = (8 - (n29 ^ 8) + (n21 << 1 & 0x6e) & 0x7a) + (reused37 & 0x7e ^ 0xd) + 0x2a & 0x7f ^ 0x29 | kept48 & 0x7f | 1
    n36 = (((n22 & 0x3a) + ((n28 + 0x39 ^ n22 & 0x2a) * 2 & 0x3e ^ 0xd) + 0x2a ^ 0x29 | kept48 | 1) & b0[2]) * 2 & 0x20
    n37 = (0x50 - n36 + (n35 & b0[2]) & 0x7f ^ 0x50 | s) * 2 & 0xaa
    b0[0x10] = b0[0x10] + ((n34 | (((n30 | n33 & n32) & 0xfa | 1) & kept48 ^ 0x3c) + (s * 2 & 0x70) - 0x3c) ^ 0xaa) - n37 + 0x56 & 0xff
    a = b4[b1[0x9b] % 0x15] & b1[0x69]
    c = (b4[b1[0x9b] % 0x15] | b1[0x69]) & 0x8d
    reused10 = (b0[b1[0x1d] % 0x14] | b4[b1[0xa8] % 0x15]) & 6 | b0[b1[0x1d] % 0x14] & b4[b1[0xa8] % 0x15] & 1
    d = _asr(c | a, 4 - reused10 + 4 & 7, 0x20)
    e = (b0[b1[0x1d] % 0x14] << 1 & 6 ^ 2 | b4[b1[0xa8] % 0x15] << 1 & 6 ^ 2) ^ 2
    f = (a | c) << ((reused10 ^ 3) + e + 5 & 7)
    g = (f - (0x5f5e6b50 & f << 1) & 0xffffffff) + 0x2faf35a8
    b0[3] = b0[3] - b4[(g & 0xffffffff ^ d - (0xd7240bf6 & d << 1) + 0x6b9205fb ^ 0x443d3053) % 0x15] & 0xff
    kept74 = b3[4 * 25]
    a = (b2[kept74 % 0x23] ^ 0xff) // 5
    reused98 = b0[b1[0x3d] % 0x14] // 5
    c = b0[0xc] << (-reused98 & 7)
    d = _asr(b0[0xc], 7 & reused98, 0x20)
    e = d ^ 0x1d ^ c & 0xff
    b1[5] = e ^ 0x1d ^ a
    b1[0xc6] = b1[0xc6] + b1[3] & 0xff
    a = b2[kept34 % 0x23] | b4[8]
    reused62 = a * a // 5
    reused57 = reused62 * 2
    c = b1[0xa4] + (reused62 - (reused57 & 0x6a) + 0xb5 ^ 0xab) & 0xff
    b1[0xa4] = c + ((reused62 - (reused57 & 0xa) + 0x15 & 0x1f) * 2 & 0x3c ^ 0x28) - 0x1e & 0xff
    kept75 = b0[kept33 % 0x14]
    reused29 = kept47 * kept47 * kept47
    reused58 = reused29 & 0xf
    a = reused58
    reused59 = reused29 * 2
    c = reused29 - (reused59 & 0x18) & 0x3f
    d = ((c + 0xc ^ 0xc) & b0[1]) - (a << 1 & b0[1] << 1 & 0xe) + 7 & 0x3f ^ 7
    kept76 = (d << 1 | kept75 << 1 & ~(b0[1] << 1)) & 0x6c
    kept77 = b0[kept21 % 0x14]
    a = 0x8b << (7 & -kept73)
    c = 0x8b >> (kept73 & 7)
    d = a
    e = (kept47 * kept47 & 0xfd) * kept47 - (reused59 & 0x58) + 0x2c & 0xff ^ 0x2c
    reused99 = kept77 | c ^ a
    f = b4[0xc] & (reused99 & 0xff)
    g = kept77 & (c ^ d)
    kept78 = g | (e ^ ~b0[1] & (e ^ kept75)) - kept76 + 0x36 & 0xff ^ 0x36 | f
    b3[4 * 27] = kept78
    d = reused58
    e = reused29 & 0x7f
    f = a
    g = ((e & b0[1]) - (d << 1 & b0[1] << 1 & 0xe) & 0x7f) + 0x47
    h = b4[0xc] & (c ^ a) & 0x7f
    j = (b4[0xc] & reused99) * 2 & 4
    k = kept77 & (c ^ f) & 0x7f
    m = k | (g ^ 0x47 | kept75 & ~b0[1]) - kept76 + 0x36 & 0x7f ^ 0x36
    n = (kept78 ^ 0x3fedff7f) + (m | (h | kept77 & b4[0xc]) - j - 0x3e & 0x7f ^ 0x42) * 2 + 0xc0120081 & 0xffffffff & (b1[0x67] | 0x3c)
    p = (n & 0xef ^ 0x10 | b1[0x67] & 0x20 ^ 0x10) // 3
    q = b2[0xc] + (p - (p * 2 & 0xac) + 0xd6 ^ 0xed) & 0xff
    b2[0xc] = q + ((p - ((p & 0x1f) * 2 & 0x2c) + 0x16 & 0x3f) * 2 & 0x76 ^ 0x24) - 0x3b & 0xff
    b3[4 * 28] = b1[0x8f]
    kept79 = kept74 // 3
    kept80 = b1[0xac] & 0x41
    a = (kept34 & (~b2[8] | b1[0x23]) & (kept33 | b2[8]) | ~kept34 & kept79) & 0x7f
    reused43 = kept79 & ~kept34
    reused100 = kept33 & ~b2[8]
    d = (((reused100 | b1[0x23] & b2[8]) & kept34 | reused43) ^ 0x58) + (a * 2 & 0xb0) - 0x58 & 0xff
    e = d & 0xa9 ^ 9 | kept80 >> 1
    b3[4 * 0x1d] = (a << 1 & 0x12 ^ 0x4d) + e & 0xff & b4[0x12]
    b3[4 * 30] = reused100 | b2[8] & b1[0x23]
    a = reused43 & 0x1f
    reused101 = b3[4 * 0x1e] & kept34
    c = (a | reused101 & 0x1f) * 2 & 0x22
    d = (kept80 | 0xa8) >> 1 ^ 2
    e = (reused43 - (a * 2 & 0x1a) + 0x2d ^ 0x2d | reused101) - c + 0x11 & 0x3f ^ 0x11
    f = 0x14 - (0xa - (kept80 >> 1) & 0xffffffff)
    g = b3[4 * 0x1c] + ((d & ((kept79 ^ kept34 & (kept79 ^ b3[4 * 0x1e])) - c + 0x11 ^ 0x11) | b3[4 * 0x1d]) ^ 0xc0) & 0xff
    b1[0x8f] = g - ((0x62 - (f + 0x27) ^ 0x27) & e | b3[4 * 0x1d] & 0x3f) * 2 + 0x40 & 0xff
    b2[0x1d] = b4[8]
    kept81 = b3[4 * 26]
    kept82 = b4[kept81 % 0x15]
    a = (0x3f & b1[0x2b] * b1[0x2b]) * 2
    c = b0[b1[0x7d] % 0x14] << 1 & 6
    d = b0[b1[0x7d] % 0x14] & 0x5f
    e = (kept82 & 0xa0 | d) + 0x78a20103 - c
    f = 0
    g = ((e & 0x2fc | ~e & 0x103) >> 1) - (((kept82 & 0x20 | d) + 3 - c ^ 3) + f & 0x5c) & 0xff
    reused102 = b1[0x2b] * b1[0x2b] & 0xfd
    h = (g + 0xae & 0xff ^ 0xae | (reused102 - (a & 0x30) & 0xfd) + 0x1a & 0xff ^ b2[b1[0x95] % 0x23] ^ 0x1a) & b0[0x11]
    j = (d | kept82 & 0xa0) >> 1 & ((reused102 - (a & 0x38) & 0xfd) + 0x1e & 0xff ^ b2[b1[0x95] % 0x23] ^ 0x1e) | h
    b0[0xf] = b0[0xf] + j & 0xff
    b3[4 * 31] = kept34 - b0[kept33 % 0x14] & 0xff
    b1[0x5f] = kept71
    a = (5 & b2[b1[0x11] % 0x23] * b2[b1[0x11] % 0x23]) * b2[b1[0x11] % 0x23] & 7
    c = b2[kept73 % 0x23] << (7 & -a)
    d = _asr(b2[kept73 % 0x23], a, 0x20)
    e = b2[kept73 % 0x23] << ((a ^ a << 1 & 4) + (b2[b1[0x11] % 0x23] << 1 & 2 ^ b2[b1[0x11] % 0x23] << 2 & 4) & 7)
    f = _asr(b2[kept73 % 0x23], a, 0x20)
    g = (f ^ e) & 0x3f
    h = (g * (d ^ c) & 0x3f) * 2 & 0x56
    j = (d ^ c) & 0x7f
    k = (f ^ e) * j - h & 0x7f
    m = d ^ c & 0xff
    n = (f ^ e) * m - h & 0xff
    b0[7] = 0x6e + b0[7] + 2 * (0xd4 ^ 0xeb & 0x2b + k) + (0x3f ^ 0xab + n) & 0xff
    a = (kept49 * kept49 & 0xfd) * kept49 & 0xff
    reused44 = kept49 * kept49 * kept49
    c = reused44 & 0x1f
    d = reused44 - (reused44 * 2 & 0x30) & 0x7f
    e = b2[8] + ((2 ^ d + d) - 2 + (c << 2 & 0x64)) - b1[0xb8] * 2 & 0xff
    b2[8] = e + ((a ^ 0xa6) + b1[0xb8] + ((d + 0x58 & 0x7f) * 2 & 0xb2 ^ 0x4f) + 0x5b ^ 0x80) & 0xff ^ 0x80
    b0[0x10] = b2[b1[0x66] % 0x23] << 1 & 0x84
    b3[4 * 0x20] = b4[kept33 % 0x15] >> 1 ^ kept72
    reused103 = b4[b1[0x50] % 0x15] << 2
    a = reused103 & ~(b2[0x13] << 1) & 0x10
    c = b4[b1[0x50] % 0x15] & 0x1f
    d = b4[b1[0x50] % 0x15] & 0x3f
    e = ((c << 2 & 0x6c ^ c << 3 & 0x10 ^ 0x76) + (d << 1) & 0x7f ^ 0x76) & ~(b2[0x13] & 0x7f)
    reused45 = b4[kept82 % 0x15] & b2[0x13]
    f = ((e + 8 ^ 8) + a * 7 | reused45) & 0x7f
    g = (((d << 2 & 0xec ^ d << 3 & 0x10 ^ 0xf6) + (b4[b1[0x50] % 0x15] << 1 & 0xfe) ^ 0xf6) & ~b2[0x13]) - (e * 2 & 0x90) + 0x48 & 0xff ^ 0x48
    h = (((reused103 & 0x2c ^ 0x1e) + (c << 1) + 0x18 & 0x3e ^ 0x36) & ~b2[0x13]) - a + 8 & 0x3f ^ 8
    j = b0[7] + (f & 0x47) * 2 + (f & 0x38) * 0x1e + ((h | reused45) & 0xf8) * 4 - b0[b1[0xbf] % 0x14] * 2 & 0xff
    b0[7] = j + b0[b1[0xbf] % 0x14] + ((g | reused45) ^ 7) + (f & 0xf8) * 0x1e - 7 & 0xff
    b0[6] = b0[b1[0x77] % 0x14]
    kept83 = b3[4 * 31]
    a = b0[kept83 % 0x14] * b0[kept83 % 0x14] & 0xfd
    c = kept46 & ~b4[2] | b4[2] & b1[0x76]
    reused60 = b2[b1[0x47] % 0x23] + b2[b1[0xf] % 0x23]
    d = reused60 - ((reused60 & 0x1f) * 2 & 0x34) + 0x1a & 0xff
    e = c - ((kept46 ^ b4[2] & (kept46 ^ b1[0x76])) & 0xf7) * 2 + 0x77 & 0xff ^ 0x77
    b0[0xc] = (b0[kept74 % 0x14] ^ d ^ 0x1a) & ((e & ~b4[0x12] | ~c & b4[0x12]) & a & 0xfd | c & b4[0x12])
    kept84 = b4[b3[4 * 32] % 0x15]
    a = (~b4[9] & ((b2[kept81 % 0x23] ^ b1[0x20]) & 0x17 | b2[kept81 % 0x23] & b1[0x20]) | b4[b1[0x39] % 0x15] * 0xe7 & b4[9]) // 5
    c = b4[0xbe - (a % 0x15 ^ 0x5f) - 0x5f]
    reused15 = b0[9] & (~b2[0xf] | kept84) & (b0[b1[0x52] % 0x14] | b2[0xf])
    reused46 = ~b0[9] & c
    d = ((reused15 | reused46) & 0xfe) * 2 & 7
    e = kept84 & b2[0xf] & 0x1f
    reused93 = b0[kept33 % 0x14] * b0[kept33 % 0x14]
    reused8 = reused93 * b0[kept33 % 0x14]
    f = reused8 & 0xf
    g = reused8 & 0x1f
    h = (g | b1[0x52]) & 0x1c
    j = h | g & b1[0x52]
    reused105 = c & ~b0[9]
    k = reused105 & 0x3f
    reused22 = b0[b1[0x52] % 0x14] & ~b2[0xf]
    m = reused22 & 0x3f
    n = reused8 & 0x3f
    p = (b1[0x52] << 1 & 4) * ((b0[kept33 % 0x14] & 3) // 3)
    q = f << 1 & b1[0x52] << 1 & 0xc
    r = h
    s = b0[kept33 % 0x14] & 0x7f
    reused21 = (s * s & 0x7d) * s
    u = reused21 - (g * 2 & 0x18) + 0xc & 0x5c ^ 0xc | b1[0x52] & 0x5c
    reused28 = reused21 * 2 & 0x5c
    v = u | (reused21 - reused28 + 0x2e & 0x7f ^ 0x2e) & (b1[0x52] & 0x7f)
    w = reused22
    x = (reused93 & 0xfd) * b0[kept33 % 0x14] & 0xff
    y = reused21 - (n * 2 & 0x3c) + 0x5e & 0x7f ^ 0x40
    z = (j ^ 0x1c) + ((f << 1 | b1[0x52] << 1) & 0x18) & 0x1f
    reused106 = (f ^ 6) - f
    n21 = (r | ((reused106 + g ^ 6) & b1[0x52]) - q + 6 ^ 6) - p + 2 & 0x1f ^ 2
    reused104 = b1[0x52] << 1 & 0x20
    reused6 = y & 0x5c ^ y << 1 & 0x20 ^ 0x3c | b1[0x52] & 0x5c ^ reused104
    n22 = reused6 + 0xe * (r & 0x10) & 0xff
    reused107 = j * 2 & 0x38
    n23 = ((h | (n - (g * 2 & 0x1c) + 0x2e ^ 0x2e) & b1[0x52]) ^ 0x1c) + reused107 - 0x1c & 0x3f
    n24 = (b4[0xf] & (n21 | b0[9] | b4[a % 0x15]) & (n21 | e | b0[b1[0x52] % 0x14] | ~b0[9]) & (n21 | e | ~b2[0xf] | ~b0[9]) & 0x8e) * 2 & 0xff
    n25 = (0x1f & z + 4 & ((b0[9] & (e | reused22) | reused46) - d + 2 & 0x1f ^ 2)) * 2 & 0x2e
    n26 = ((u | (x - reused28 + 0xae ^ 0xae) & b1[0x52]) ^ 0x5c) + (v * 2 & 0xb8) - 0x5c & 0xff
    n27 = (g & 0x1c ^ g << 1 & 0x20 | b1[0x52] & 0x1c ^ reused104) ^ 0x20 & r + r
    n28 = ((n27 | ((reused106 + n ^ 6) & b1[0x52]) - q + 6 ^ 6) - p + 2 & 0x3f ^ 2) & (b4[0xf] & 0x3f)
    n29 = n24 + (-(n28 | b4[0xf] & ~b0[9] & b4[a % 0x15] | b4[0xf] & b0[9] & m | b4[0xf] & b0[9] & b2[0xf] & kept84) - 1 ^ 0x11) + 0x12 & 0x3f
    n30 = (n29 | (n23 & (((m | kept84 & b2[0xf]) & b0[9] | k) - d + 2 ^ 2)) - n25 + 0x17 & 0x3f ^ 0x17) * 2 & 0x62
    n31 = reused6 + 6 * (r & 0x10) & 0x7f
    n32 = (n31 | ((reused21 - (f * 2 & 0xc) + 0x46 ^ 0x46) & b1[0x52]) - q + 0x46 & 0x7f ^ 0x46) * 2 & 0x84
    n33 = ((n22 | x & b1[0x52]) - n32 + 0x42 & 0xff ^ 0x42) & b4[0xf]
    n34 = reused15 & 0x7f
    n35 = (n34 | (reused105 ^ 0x5f) + (k * 2 & 0x3e) - 0x5f) - d + 2 & 0x7f ^ 2
    n36 = (n26 & (((w | kept84 & b2[0xf]) & b0[9] | reused46) - d + 2 ^ 2)) - (((v ^ 0x5c) + reused107 - 0x5c & 0x7f & n35) * 2 & 0xae) & 0xff
    b3[4 * 0x21] = (n33 | ((kept84 & b2[0xf] | w) & b0[9] | b4[a % 0x15] & ~b0[9]) & b4[0xf] | n36 + 0x57 ^ 0x57) - n30 + 0x31 & 0xff ^ (a ^ 0x31)
    a = _asr(b3[4 * 0x17], 7 & -kept84, 0x20)
    c = b3[4 * 0x17] << (kept84 & 7)
    reused13 = b0[kept83 % 0x14] << 1
    d = (reused13 & 0xe) * b1[5] & 0xf
    e = (reused13 & 0x7e) * b1[5] & 0x7f
    f = c & 0xff ^ a
    g = (c ^ a) & 0x7f
    h = g << 1 & (kept21 << 1 & 0xfe) - 0x24 & 0xd6
    j = (e - (((reused13 & 0x3e) * b1[5] & 0x3f) * 2 & 0x58) + 0x6d & 0x7f) * 2 & 0xfc ^ 0xd8
    k = (c ^ a) & 0x1f
    m = (reused13 & 0x1e) * b1[5] - (d * 2 & 0x18) + 0xd & 0x1f ^ 0x13
    n = (c ^ a) & 0xf
    p = (d - (((reused13 & 6) * b1[5] & 7) * 2 & 8) + 0xd & 0xf) * 2 & 0x1c ^ 0x18
    q = (b0[kept83 % 0x14] * 2 & 0xfe) * b1[5] - (e * 2 & 0xd8) + 0xed & 0xff ^ 0x93
    r = q + ((f ^ 0xff | 0x9c - kept21 - 0xb) ^ 0x6b) + j - h - 0x12 & 0xff
    s = ((k ^ 0x1f | kept21 + 0xfe ^ 0xf) ^ 0xb) + m + p & 0x1f
    b2[0x19] = r - ((s - (n << 1 & (kept21 << 1) - 4 & 0x16) - 0x12 & 0x1f) * 2 & 0x36) + 0x1b & 0xff ^ (b2[0x19] ^ 0x1b)
