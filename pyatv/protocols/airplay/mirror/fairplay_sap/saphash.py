"""FPLY's other primitive: SAPHash's 210-byte scramble.

Region A's two big arithmetic bursts are neither the block cipher nor the
MD5 -- they are the scramble at the heart of SAPHash, the FairPlay v3
routine that airplay2-receiver's `fairplay3.py` also implements.

    for i in range(840):
        x = b[u32(i - 155) % 210]
        y = b[u32(i -  57) % 210]
        z = b[u32(i -  13) % 210]
        w = b[i % 210]
        b[i % 210] = rol8(y, 5) + (rol8(z, 3) ^ w) - rol8(x, 7)

The taps are the whole trick.  `i - 155` is taken as an UNSIGNED 32-bit
value before the modulo, so for i = 0 the tap is not 55 -- what Python's
`%` gives -- but 101, because 0xffffff65 % 210 == 101.  The slice
computes exactly that: 0xffffff65 sits in a register two ops before the
first read, at buffer offset 101.

Getting this wrong is not subtle in its effect but is very subtle to
spot: the loop still runs, still touches the right buffer, and produces
completely different bytes.  A first attempt here used Python's `%`,
failed to match, and nearly wrote SAPHash off as "structurally similar
but not the same".

THE ROUND STRUCTURE, from the trace.  Buffer1's byte writes fall into
eight runs of exactly 1050 with the index sweeping 0..209, each ending
within 40 ops of a garble marker.  1050 is 210 + 840: a 210-byte LOAD
followed by the 840-step scramble.  So one round is

    load 210 bytes from 0x1016f456c  ->  scramble 840  ->  garble

and a handshake runs eight of them -- two SAPHash calls of four rounds
each, with the fold after the fourth and the eighth.  `scramble(840)`
reproduces a real run's output byte for byte when started from the state
just after the load, which is the check `test_saphash` makes.

Every round loads from the SAME address, so the rounds chain through
that staging buffer rather than walking an input: something writes
0x1016f456c between them.  What that is, and the fold, are what is left.

What is NOT lifted yet is the fold that follows the four scramble
passes.  What is known about it:

* its 16-byte result lands at 0x1016f4554 and the SAP secret is that,
  XORed with 0x0d -- so `sap36[0:16]` is this call's output outright;
* it reads all four constants above;
* each delta block is built the way the published implementation builds
  its `keyOut`: initialised to **0xe1 sixteen times**, then folded into.
  Three of them are built here, in clusters of about 10,400 ops each
  (the delta-1 cluster ends at op 550794, delta-3's at 586374);
* it runs in three stages over the output buffer, and ALL THREE are
  plain 128-bit ADDs of a delta block, four 32-bit words at a time:

      stage 1  out[w] += delta1[w]     delta1 at 0x1016f43a4
      stage 2  out[w] += delta2[w]
      stage 3  out[w] += delta3[w]     delta3 at 0x1016f43dc

  so the fold is `out += delta1 + delta2 + delta3`, and everything
  interesting is in the deltas rather than in the folding.

  A plain XOR-fold of the 210-byte buffer into 16 is NOT the output, with
  or without the constants mixed in -- the first thing to try, and wrong.

Stage 2 took 1239 straight-line MBA instructions (0x100c7cb90) to hide
that add.  It reads all four bytes of the word and a constant and writes
back through the byte-reversing store idiom, which makes it look like a
transform; probing it with chosen words settles it in eight calls --
f(0)=0x44916789, f(1)=f(0)+1, f(0x10000)=f(0)+0x10000,
f(0xffffffff)=f(0)-1, and f(0x12345678)=f(0)+0x12345678 exactly.

WHAT THE PACKAGE GETS is `scramble`, `load` and the constants.  The rest
-- `rounds`, `buffer1_at`, `staging_windows`, `fold_windows`,
`call_tiling` -- reads a finished `vmdis.Sim` to find where in a traced
run something happened, which is a question only `devirt/` can ask, and
they stay there.
"""

__all__ = [
    "scramble",
    "load",
    "BLOCK_SIZE",
    "KEYOUT_AT",
    "ROUNDS_PER_CALL",
    "BUFFER_SIZE",
    "STEPS",
    "STAGING_PAD",
    "STAGING_PADS",
    "STAGING_ROUTINES",
    "TAPS",
    "INPUT_AT",
    "ROUNDS_PER_HANDSHAKE",
    "CONSTANT_35",
    "CONSTANT_21",
    "CONSTANT_35_AT",
    "CONSTANT_21_AT",
    "CONSTANT_17A",
    "CONSTANT_17B",
    "CONSTANT_17A_AT",
    "CONSTANT_17B_AT",
    "CONSTANT_MASK",
    "CONSTANT_20",
    "LIVE_BUFFER0",
    "LIVE_BUFFER1",
    "LIVE_BUFFER2",
    "LIVE_BUFFER3",
    "LIVE_BUFFER4",
]

# Two of SAPHash's three constant buffers sit in the slice verbatim, XORed
# with 0x6a -- the mask of the region they live in -- and the scramble's
# bursts read exactly those spans, 35 and 21 bytes.  They are byte for byte
# the `buffer2` and `buffer4` of airplay2-receiver's fairplay3.py, which is
# what ties this engine to the published FairPlay v3 routine rather than to
# something merely shaped like it.  (Its 20-byte `buffer0` is NOT in the
# image, under that mask or any other tried, so that one differs here.)
CONSTANT_MASK = 0x6A
CONSTANT_35_AT = 0x1014AF7E0
CONSTANT_21_AT = 0x1014B97E0
CONSTANT_35 = bytes.fromhex(
    "4354627a18c3d6b39a56f61c143f0c1d3b3683b139514aaa093efe44afdec3209d423a"
)
CONSTANT_21 = bytes.fromhex("ed25d1bbbc279f02a2a911000cb352c0bde31b49c7")

# Two more 17-byte constants, same mask, sitting 0x50 ahead of each of the
# two above.  They belong to the fold that follows the scramble rather than
# to the scramble itself.  The first begins 0xe1 -- the byte the published
# implementation fills its output with before folding into it, which is
# suggestive but not yet pinned to anything here.
CONSTANT_17A_AT = 0x1014AF790
CONSTANT_17B_AT = 0x1014B9810
CONSTANT_17A = bytes.fromhex("e1432a53f0ffe53d9aa37df6ed0d321134")
CONSTANT_17B = bytes.fromhex("ad49914004e9b07263c8ddc13890aa4b77")

# The third published buffer, `buffer0`.  Unlike the other two it is not
# in the static image; it is staged into the heap before the hash runs,
# and the garble step then rewrites it in place -- which is why sampling
# it after the fold shows something that only half matches.  These are the
# addresses the three live at while the hash runs, laid out back to back:
# 20, then 210, then 35 after two bytes of alignment.  The fold reads
# exactly 265 of the 267 bytes they span, which is how they were found.
CONSTANT_20 = bytes.fromhex("965fc653f846cc18dfbeb2f838d7ec2203d1208f")
LIVE_BUFFER0 = 0x1016F41A4
LIVE_BUFFER1 = 0x1016F41B8
LIVE_BUFFER2 = 0x1016F428C
LIVE_BUFFER3 = 0x1016F42E0  # 132 bytes, written by the garble step
LIVE_BUFFER4 = 0x1016F418C  # 21 bytes, == CONSTANT_21, just below buffer0

# All five of the published implementation's buffers, laid out in order:
#
#     buffer4  0x1016f418c   21    == CONSTANT_21
#     buffer0  0x1016f41a4   20    == CONSTANT_20
#     buffer1  0x1016f41b8  210    the scramble buffer
#     buffer2  0x1016f428c   35    == CONSTANT_35
#     buffer3  0x1016f42e0  132    written by garble
#
# buffer4 was the last to be found, and it names itself: garble reads it
# by index constantly, so a load of a byte three below buffer0 that equals
# CONSTANT_21[18] fixes the base immediately.

# The garble step runs between the last scramble pass and the keyOut fold
# (ops 538000..540408 in the reference run).  Feeding the live buffers to
# the vendored `HandGarble.Garble` reproduces MOST of its output but not
# all -- the port is close, not exact:
#
#     buffer0    7 of  20 bytes differ
#     buffer1   63 of 210
#     buffer2    8 of  35
#     buffer3   28 of 132, and every one at a multiple of 4
#
# Bisecting it against the trace -- the port prints every buffer write, so
# the two write sequences can be zipped -- shows what it does and does not
# get right.  Comparing the buffer3 VALUE sequences rather than the slots
# is what makes it legible:
#
#   port   0:1d 4:18 8:4c 12:d2 16:72 ... 56:c7      64:a5 68:3e 72:a1 ...
#   trace  0:1d 4:18 8:4c 12:d2 16:76 ... 56:1b 60:b7 64:b1 72:60 68:c1 ...
#
# * slots 0..44 agree except [16] and [28] -- and BOTH are wrong only in
#   an additive constant, confirmed against the trace's live operands:
#
#       buffer3[16] = (A*A + 114) & 0xff     port has 110
#       buffer3[28] = (70 + (B|C)**2) & 0xff port has  30
#
#   The method that settles these: read the loads immediately before the
#   store to identify the operands (they name themselves -- an index into
#   buffer2 or buffer4 shows up as `bN[i] % len` in the trace), recompute
#   the port's intermediate with the LIVE buffer values, and solve for the
#   constant.  For [16] the operands are buffer4[12]=0x0c and
#   buffer2[6]=0xd6, giving A=0x3e, and only 114 lands on the traced 0x76.
#   (For [28] the squared term happens to be 0 in this sample, so the
#   constant is pinned but the rest of that expression is not.);
# * the trace writes all 33 slots (0, 4, ... 128); the port writes 32 and
#   has no `buffer3[60] = ...` line at all;
# * the port's slots 64..96 hold, in order, exactly the values the trace
#   puts in slots 80..112 -- nine correct expressions placed four slots
#   early -- and its 120, 124 hold the trace's 124, 128, one slot early;
# * six of the port's values (its 100, 104, 108, 112, 116, 128) never
#   appear in the trace at all, and eight of the trace's never appear in
#   the port.
#
# So the port is not one index bug away from correct.  But with buffer4
# located, the defects sort into recognisable classes rather than noise:
#
#   * wrong additive constant, structure right:
#         buffer3[16] = (A*A + 114) & 0xff       port has 110
#         buffer3[28] = (70 + (B|C)**2) & 0xff   port has  30
#
#   * a buffer4 lookup HARDCODED as the value it happens to hold:
#         buffer3[56] = buffer4[18]              port has the literal 199
#         buffer3[52] = buffer2[buffer3[4] % 35] ^ buffer4[18]
#                                                port has the literal 27
#     (27 is buffer4[18] and 199 is buffer4[20] -- correct for a pristine
#     buffer4, wrong here because garble rewrites buffer4 as it runs.)
#
# The read sequences are what make this legible: instrument the port's
# buffers with a logging list and diff its reads against the trace's
# loads.  Before buffer3[48] the port reads b3[44], b3[4], b2[24] where
# the slice reads b3[4], b4[18], b2[24] -- so it is reaching into
# buffer3 where the real code reaches into buffer4.
#
# Repairing the rest properly still means lifting the real garble from
# the ARM (12,029 straight-line instructions), but the classes above
# cover a good share of it.
#
# Note the port's FIRST write, buffer2[12], has no counterpart in the
# trace at all: it is immediately overwritten by the literal 0x07 two
# lines later, and the slice does not perform the dead store.  Zip the
# sequences without dropping it and every later comparison is off by one,
# which reads as "everything after the first line is wrong".
#
# So it is a reference for the shape and not a drop-in -- but a bounded
# one: 22 wrong bytes, each checkable against the trace.

# the 210-byte block each round loads into buffer1.  Not an input
# pointer that advances: all eight rounds read from here, so the rounds
# chain through it.
INPUT_AT = 0x1016F456C
# where the fold's 16-byte result lands; the SAP secret's first half is
# this XORed with 0x0d
KEYOUT_AT = 0x1016F4554
ROUNDS_PER_HANDSHAKE = 8
ROUNDS_PER_CALL = 4

# SAPHash's input is a 64-BYTE block, tiled across the 210-byte buffer
# rather than padded into it.  That is what the published
# implementation's `block_words[((i % 64) >> 2)]` is doing -- an
# indexing that reads like a bug and is not one.  It also explains why
# only the first 63 bytes of the staging block change between rounds:
# 64 bytes are all there is to change.
BLOCK_SIZE = 64
BUFFER_SIZE = 210
STEPS = 840
TAPS = (155, 57, 13)


def _rotate(value, count):
    return (((value << count) & 0xFF) | ((value & 0xFF) >> (8 - count))) & 0xFF


def scramble(buffer, steps=STEPS):
    """Apply the scramble, in place on a copy; *steps* is four passes by default."""
    if len(buffer) != BUFFER_SIZE:
        raise ValueError(f"buffer must be {BUFFER_SIZE} bytes, got {len(buffer)}")
    state = bytearray(buffer)
    for i in range(steps):
        x = state[((i - TAPS[0]) & 0xFFFFFFFF) % BUFFER_SIZE]
        y = state[((i - TAPS[1]) & 0xFFFFFFFF) % BUFFER_SIZE]
        z = state[((i - TAPS[2]) & 0xFFFFFFFF) % BUFFER_SIZE]
        w = state[i % BUFFER_SIZE]
        state[i % BUFFER_SIZE] = (
            _rotate(y, 5) + (_rotate(z, 3) ^ w) - _rotate(x, 7)
        ) & 0xFF
    return bytes(state)


# how far either side of the staging writes a portable window has to
# reach: the values are computed a little before the first store lands
STAGING_PAD = (67, 46)

# Where each staging burst's window starts executing.  Two routines
# alternate through a SAPHash call -- and the second SAPHash call runs
# its own COPY of both, at different addresses, so a handshake's nine
# bursts enter at four places rather than two:
#
#     call 1   bursts 0, 2   0x100c70b70      bursts 1, 3   0x100c8903c
#     call 2   bursts 5, 7   0x100c8ef18      bursts 6, 8   0x100c8ebb0
#
# and burst 4, which spans the join between the two calls, enters at
# 0x100c71ec8 on its own.
#
# Entering at the same address is not the same as running the same
# instructions: the second routine takes a different path on different
# rounds (7,309 instructions at burst 1, 7,034 at burst 3), so a
# straight-line port of one of its occurrences does not serve the other.
# `saphash_render.routines` groups the bursts by the pc sequence they
# actually ran, which is the distinction that matters.
STAGING_ROUTINES = (0x100C70B70, 0x100C8903C, 0x100C8EF18, 0x100C8EBB0)

# How much earlier than `STAGING_PAD` puts it a burst's window has to
# open before its PORT stops depending on the handshake it was lifted
# from.  `ssa_lift.window_state` snapshots the interpreter's registers
# where a window opens and the generated port bakes them in as literals,
# so a value the input decided, computed just before the burst, becomes
# a constant of the port.  Three of the nine bursts do that at the bare
# burst boundary -- built from two M2 vectors their sources differ by
# one line (bursts 3 and 7) and by nine (burst 8) -- and opening earlier
# puts the computation that made the value inside the window instead.
#
# The amounts are measured, not chosen, and are the SMALLEST that work:
# every extra op drags in the tail of whatever ran before, so burst 3's
# window is 2,106 lines at 400 and burst 8's 6,017 at 2,500.  Nor is
# more always better -- burst 7 is exact at 400 and depends on the input
# again at 1,000, because the wider window opens on a different
# instruction with its own inherited register.
#
# The amounts were FITTED at two vectors, which is exactly the way to
# get a number that is right about those two and wrong in general: the
# lift constant-folds a load the two happen to agree about, and a pad
# that leaves such a load inside the port still gives two identical
# sources.  All three were re-measured at EIGHT vectors and all three
# hold -- as do the six bursts that need no pad at all.
#
# `test_window_independence` is what holds these to their job, and it
# builds every burst from those eight.
STAGING_PADS = {3: 400, 7: 400, 8: 2500}


def load(block):
    """Buffer1 from a 64-byte input block: tiled, not padded."""
    if len(block) < BLOCK_SIZE:
        raise ValueError(f"need {BLOCK_SIZE} bytes, got {len(block)}")
    return bytearray(block[i % BLOCK_SIZE] for i in range(BUFFER_SIZE))
