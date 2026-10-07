"""SAPHash's 210-byte scramble, its input loading and its constant tables.

SAPHash is the FairPlay v3 hash also implemented by airplay2-receiver's
``fairplay3.py``.  A 64-byte block is tiled across a 210-byte buffer
(:func:`load`), which is then scrambled for 840 steps (:func:`scramble`):

    for i in range(840):
        x = b[u32(i - 155) % 210]
        y = b[u32(i -  57) % 210]
        z = b[u32(i -  13) % 210]
        w = b[i % 210]
        b[i % 210] = rol8(y, 5) + (rol8(z, 3) ^ w) - rol8(x, 7)

The tap subtractions are unsigned 32-bit before the modulo: for i = 0 the
first tap is ``0xffffff65 % 210 == 101``, not the 55 that Python's ``%``
gives.  Getting this wrong still runs and still produces bytes, just the
wrong ones.

The garble step (:mod:`.garble_plain`) and the fold into a 16-byte delta
(:mod:`.saphash_fold`) follow the scramble; :mod:`.region_a` composes them.
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

# Constant buffers of the published implementation: CONSTANT_35 and
# CONSTANT_21 are its `buffer2` and `buffer4`, CONSTANT_20 the initial
# value of its `buffer0`.  The *_AT and LIVE_BUFFER* values below are
# addresses in the original implementation; nothing reads them.
CONSTANT_MASK = 0x6A
CONSTANT_35_AT = 0x1014AF7E0
CONSTANT_21_AT = 0x1014B97E0
CONSTANT_35 = bytes.fromhex(
    "4354627a18c3d6b39a56f61c143f0c1d3b3683b139514aaa093efe44afdec3209d423a"
)
CONSTANT_21 = bytes.fromhex("ed25d1bbbc279f02a2a911000cb352c0bde31b49c7")

# The same bytes as region_a.SUFFIX_1 and region_a.PREFIX_2.
CONSTANT_17A_AT = 0x1014AF790
CONSTANT_17B_AT = 0x1014B9810
CONSTANT_17A = bytes.fromhex("e1432a53f0ffe53d9aa37df6ed0d321134")
CONSTANT_17B = bytes.fromhex("ad49914004e9b07263c8ddc13890aa4b77")

CONSTANT_20 = bytes.fromhex("965fc653f846cc18dfbeb2f838d7ec2203d1208f")
LIVE_BUFFER0 = 0x1016F41A4
LIVE_BUFFER1 = 0x1016F41B8
LIVE_BUFFER2 = 0x1016F428C
LIVE_BUFFER3 = 0x1016F42E0  # 132 bytes, written by the garble step
LIVE_BUFFER4 = 0x1016F418C  # 21 bytes, == CONSTANT_21, just below buffer0

# Unused by the algorithm.  The SAP secret's first 16 bytes are the
# keyOut result XORed with 0x0d.
INPUT_AT = 0x1016F456C
KEYOUT_AT = 0x1016F4554
ROUNDS_PER_HANDSHAKE = 8
ROUNDS_PER_CALL = 4

# SAPHash's input is a 64-byte block, tiled across the 210-byte buffer
# rather than padded into it; the published implementation's
# `block_words[((i % 64) >> 2)]` does the same.
BLOCK_SIZE = 64
BUFFER_SIZE = 210
STEPS = 840
TAPS = (155, 57, 13)


def _rotate(value, count):
    return (((value << count) & 0xFF) | ((value & 0xFF) >> (8 - count))) & 0xFF


def scramble(buffer, steps=STEPS):
    """Return *buffer* scrambled for *steps* steps (four passes by default)."""
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


# STAGING_PAD, STAGING_ROUTINES and STAGING_PADS describe the original
# implementation's code layout and are not used by the algorithm.
STAGING_PAD = (67, 46)

STAGING_ROUTINES = (0x100C70B70, 0x100C8903C, 0x100C8EF18, 0x100C8EBB0)

STAGING_PADS = {3: 400, 7: 400, 8: 2500}


def load(block):
    """Return the 210-byte buffer for a 64-byte block: tiled, not padded."""
    if len(block) < BLOCK_SIZE:
        raise ValueError(f"need {BLOCK_SIZE} bytes, got {len(block)}")
    return bytearray(block[i % BLOCK_SIZE] for i in range(BUFFER_SIZE))
