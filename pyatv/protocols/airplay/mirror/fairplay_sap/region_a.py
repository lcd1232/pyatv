"""Region A as an algorithm: M2 in, the 36-byte SAP secret out.

Region A was the last stage of the FPLY v3 handshake still running
through generated ports -- eight windows, about eight minutes to build.
Every piece of it had already been recovered; nobody had composed them.
This module is the composition, and it needs neither the emulator nor a
line of generated code.

WHAT REGION A IS.  Two runs of FairPlay's SAPHash over the SAME 290-byte
message, differing only in the seventeen bytes at each end:

    message = prefix(17) || A(128) || B(128) || suffix(17)

`A` is a constant of the slice; `B` is the only thing M2 decides --
``entry_image.payload(m2)``, which is ``m2[14:142]`` CBC-decrypted under
Region A's own cipher.  Both halves are XORed with 0x0d on the way in,
the same mask the slice wears over the secret everywhere else.

The message is MD5-padded to 320 bytes and cut into five 64-byte blocks;
each block is stored with every four-byte word byte-reversed, which is
what makes the hash read big-endian words out of a little-endian buffer.

WHAT A CALL DOES.  Per block, two things happen:

    A   key += SAPHash(block)      # the 210-byte scramble and garble
    C   key  = compress(key, block)    # the modified MD5

`SAPHash(block)` is the published FairPlay v3 routine and it is
STATELESS: buffer0, buffer2 and buffer4 are the published constants at
the start of every one of the ten blocks (checked at all eight garble
calls), buffer3's junk never reaches the answer, and buffer1 is loaded
from the block alone.  So a block's delta depends on nothing but the
block -- which is why call one's blocks 1, 2 and 3 and call two's give
identical deltas, the two calls' messages agreeing there.

The two calls run the same A and C, five of each, in OPPOSITE PHASE:

    call one   C A C A C A C A C A        keyOut is taken after the last A
    call two   A C A C A C A C A C C      and here after one extra C

and they shuffle differently at round 31 of the compression --
`saphash_fold.shuffle_pairs` for call one, `saphash_fold.shuffle` for
call two.  Both were already measured; this only says which is whose.

THE SECRET.  Sixteen bytes from call one, then the first four of call
two's, then sixteen more from the extra compression, each word big-endian
and the whole thing XORed with 0x0d:

    sap36 = (BE(k1) || BE(k2)[:4] || BE(k3)) ^ 0x0d

THE ONE JOIN THAT IS NOT WHERE IT LOOKS.  `garble_plain.garble` is not
the garble alone.  It starts by writing buffer1[159..209] -- the
fifty-one indices a 789-step scramble has not reached -- off the
scramble's own taps, (i-155), (i-57) and (i-13) at i = 789
(`garble_plain._finish_scramble`).  That is where `garble_gen`'s window
boundary fell, so the port carries the tail of the sweep with it, and so
does `garble_plain`, its readable twin and the one this module runs
(`garble_read` is the generated authority it is tested against).

So buffer1 is scrambled 789 steps here, not 840, and `garble` finishes
it.  Scrambling the full 840 first covers those fifty-one indices twice.
It raises nothing and produces bytes; they are the wrong bytes, and
nothing downstream would say so.

Run: uv run --with capstone python -m devirt.region_a
"""

import struct

from . import entry_image, garble_plain, saphash, saphash_fold

__all__ = [
    "sap_secret",
    "hash_block",
    "message",
    "blocks",
    "run",
    "IV",
    "MASK",
    "MESSAGE_A",
    "PREFIX_1",
    "SUFFIX_1",
    "PREFIX_2",
    "SUFFIX_2",
    "SCRAMBLE_STEPS",
    "BLOCK_COUNT",
    "SAP_LENGTH",
]

_M32 = 0xFFFFFFFF
# the mask the slice wears over the message, the constants and the secret
MASK = 0x0D
# the four-word value both calls start from, written at the top of each
# (0x6fffc568 in the slice, one 32-bit store per word)
IV = (0xB9F3DCDC, 0xFBDC740B, 0x60F77F86, 0x51907216)
# how far buffer1 is scrambled before `garble_plain.garble`, which runs
# the remaining fifty-one steps itself
SCRAMBLE_STEPS = 789
# five 64-byte blocks a call, ten a handshake
BLOCK_COUNT = 5
SAP_LENGTH = 36

# The 128 constant bytes the message carries between the two ends.  They
# sit at 0x6fffc65c in the slice's heap -- masked there, unmasked here --
# and `entry_image`'s six-vector diff says nothing about them moves with
# M2.  The 128 bytes AFTER them are the ones that do: the decrypted
# payload at 0x6fffcdd4.
MESSAGE_A = bytes.fromhex(
    "0d0cb6ea3ba3a6a23de15519699c14cada5c9fea2dee81876db06c18ece4dff2"
    "c1b8068b38a620b2be0c1fbe5488f20cb34d7aa5b6d63643911ee992ab07b779"
    "79f8e1ccef5590511fbfd2fcb67eb976b9d3af80afdce1797db53000ebfd585b"
    "3a65c97c89dfbc45a49daa7316809780d3c713976f9b01eab39aca964eac02bb"
)

# The four seventeen-byte constants that top and tail the message, as
# they sit in the image (the region's own 0x6a mask already off, `MASK`
# still on).  Two of them `saphash` already names: SUFFIX_1 is its
# CONSTANT_17A and PREFIX_2 its CONSTANT_17B.  The other two live 0x160
# below each of those.
#
#     0x33529cf0  PREFIX_1      0x33529e50  SUFFIX_1  (CONSTANT_17A)
#     0x33533ed0  PREFIX_2      0x33529ed0  SUFFIX_2
#       (CONSTANT_17B)
PREFIX_1 = bytes.fromhex("f791a04046652b8172fe8594d39f239813")
SUFFIX_1 = bytes.fromhex("e1432a53f0ffe53d9aa37df6ed0d321134")
PREFIX_2 = bytes.fromhex("ad49914004e9b07263c8ddc13890aa4b77")
SUFFIX_2 = bytes.fromhex("9ab80289ef185791299411f937046e584a")


def _unmask(data):
    return bytes(byte ^ MASK for byte in data)


def hash_block(block: bytes) -> bytes:
    """One SAPHash of a 64-byte block: the 16-byte delta it contributes.

    The published `SAPHash.hash` end to end -- tile the block across
    buffer1, scramble, garble, fold the five buffers down to sixteen
    bytes -- with the buffers freshly initialised, which is what the
    slice does for every block.

    buffer3 starts as junk in the slice and as zeros here: `garble`
    writes all thirty-three of its words and the byte past them, and
    those are the only bytes the fold reads.
    """
    b0 = bytearray(saphash.CONSTANT_20)
    b1 = bytearray(saphash.scramble(saphash.load(block), SCRAMBLE_STEPS))
    b2 = bytearray(saphash.CONSTANT_35)
    b3 = bytearray(140)  # the fold reads word 33, past 132
    b4 = bytearray(saphash.CONSTANT_21)
    garble_plain.garble(b0, b1, b2, b3, b4, SCRAMBLE_STEPS)
    return saphash_fold.delta(bytes(b0), bytes(b1), bytes(b2), bytes(b3))


def message(payload: bytes, prefix: bytes, suffix: bytes) -> bytes:
    """Return the 290-byte message one call hashes, MD5-padded to 320.

    *payload* is `entry_image.payload(m2)`; everything else is constant.
    The mask comes off all three pieces, which is the XOR the staging
    update does one byte at a time.
    """
    body = _unmask(prefix) + _unmask(MESSAGE_A) + _unmask(payload) + _unmask(suffix)
    out = bytearray(body) + b"\x80"
    while len(out) % 64 != 56:
        out.append(0)
    return bytes(out + (len(body) * 8).to_bytes(8, "little"))


def blocks(padded: bytes) -> list:
    """Return the padded message as the staging block holds it: words reversed.

    The staging update writes the message bytes and then swaps each
    four-byte word end for end, so a little-endian read of the buffer
    gives the big-endian word -- which is the indexing the published
    implementation writes as `(in_word >> ((3 - (i % 4)) << 3))`.
    """
    return [
        bytes(b"".join(padded[at + 4 * w : at + 4 * w + 4][::-1] for w in range(16)))
        for at in range(0, len(padded), 64)
    ]


def run(parts, step31, compress_first: bool) -> list:
    """One SAPHash call: five blocks, five adds and five compressions.

    *compress_first* is the phase.  Call one compresses a block before
    adding its delta; call two adds first.  Nothing else about the two
    differs but *step31*.
    """
    key = list(IV)
    for block in parts:
        delta = struct.unpack("<4I", hash_block(block))
        if compress_first:
            _spilled, key = saphash_fold.compress(
                key, list(struct.unpack("<16I", block)), step31
            )
            key = [(k + d) & _M32 for k, d in zip(key, delta)]
        else:
            key = [(k + d) & _M32 for k, d in zip(key, delta)]
            _spilled, key = saphash_fold.compress(
                key, list(struct.unpack("<16I", block)), step31
            )
    return key


def _big(key):
    return b"".join(struct.pack(">I", word) for word in key)


def sap_secret(m2: bytes) -> bytes:
    """Region A's whole output for *m2*: the 36-byte SAP secret.

    The same 36 bytes `opexec.sap_secret` reads out of a finished run,
    and the input to every stage after it -- Region B's device_tag, the
    M4 call's context, and through that Region C's ekey.
    """
    payload = entry_image.payload(m2)
    first = run(
        blocks(message(payload, PREFIX_1, SUFFIX_1)),
        saphash_fold.shuffle_pairs,
        compress_first=True,
    )
    parts = blocks(message(payload, PREFIX_2, SUFFIX_2))
    second = run(parts, saphash_fold.shuffle, compress_first=False)
    # call two does not stop at its keyOut: one more compression over
    # the last block, and the secret's tail is four bytes of the first
    # answer and all sixteen of the second
    _spilled, third = saphash_fold.compress(
        second, list(struct.unpack("<16I", parts[-1])), saphash_fold.shuffle
    )
    return _unmask(_big(first) + _big(second)[:4] + _big(third))
