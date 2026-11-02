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
    "BUFFER_SIZE",
    "STEPS",
    "TAPS",
    "CONSTANT_35",
    "CONSTANT_21",
    "CONSTANT_20",
]

# Constant buffers of the published implementation: CONSTANT_35 and
# CONSTANT_21 are its `buffer2` and `buffer4`, CONSTANT_20 the initial
# value of its `buffer0`.
CONSTANT_35 = bytes.fromhex(
    "4354627a18c3d6b39a56f61c143f0c1d3b3683b139514aaa093efe44afdec3209d423a"
)
CONSTANT_21 = bytes.fromhex("ed25d1bbbc279f02a2a911000cb352c0bde31b49c7")

CONSTANT_20 = bytes.fromhex("965fc653f846cc18dfbeb2f838d7ec2203d1208f")

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


def load(block):
    """Return the 210-byte buffer for a 64-byte block: tiled, not padded."""
    if len(block) < BLOCK_SIZE:
        raise ValueError(f"need {BLOCK_SIZE} bytes, got {len(block)}")
    return bytearray(block[i % BLOCK_SIZE] for i in range(BUFFER_SIZE))
