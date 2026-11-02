"""M2 in, the 36-byte SAP secret out.

The secret is two runs of FairPlay's SAPHash over the same 290-byte
message, differing only in the seventeen bytes at each end:

    message = prefix(17) || A(128) || B(128) || suffix(17)

`A` is the constant :data:`MESSAGE_A`; `B` is the only part M2 decides:
``entry_image.payload(m2)``, which is ``m2[14:142]`` CBC-decrypted.  All
pieces are stored XORed with :data:`MASK` (0x0d), which comes off on the
way in.

The message is MD5-padded to 320 bytes and cut into five 64-byte blocks;
each block is stored with every four-byte word byte-reversed, so a
little-endian read gives the big-endian words the hash works on.

Per block, a call does two things:

    A   key += SAPHash(block)          # the 210-byte scramble and garble
    C   key  = compress(key, block)    # the modified MD5

`SAPHash(block)` is stateless: buffer0, buffer2 and buffer4 start as the
published constants for every block, and buffer1 is loaded from the block
alone.  The two calls run A and C in opposite order:

    call one   C A C A C A C A C A        keyOut is taken after the last A
    call two   A C A C A C A C A C C      and here after one extra C

and shuffle differently at round 31 of the compression
(`saphash_fold.shuffle_pairs` for call one, `saphash_fold.shuffle` for
call two).  The secret is

    sap36 = (BE(k1) || BE(k2)[:4] || BE(k3)) ^ 0x0d

with k1 call one's result, k2 call two's keyOut and k3 the extra C.

`garble_plain.garble` also finishes the scramble: buffer1 is scrambled 789
steps here, not 840, and `garble` runs the last fifty-one.  Scrambling the
full 840 first would run those steps twice; nothing would fail, the bytes
would just be wrong.
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
# the mask over the stored message pieces and the secret
MASK = 0x0D
# the four-word value both calls start from
IV = (0xB9F3DCDC, 0xFBDC740B, 0x60F77F86, 0x51907216)
# how far buffer1 is scrambled before `garble_plain.garble`, which runs
# the remaining fifty-one steps itself
SCRAMBLE_STEPS = 789
# five 64-byte blocks a call, ten a handshake
BLOCK_COUNT = 5
SAP_LENGTH = 36

# The 128 constant bytes the message carries after the prefix (masked).
MESSAGE_A = bytes.fromhex(
    "0d0cb6ea3ba3a6a23de15519699c14cada5c9fea2dee81876db06c18ece4dff2"
    "c1b8068b38a620b2be0c1fbe5488f20cb34d7aa5b6d63643911ee992ab07b779"
    "79f8e1ccef5590511fbfd2fcb67eb976b9d3af80afdce1797db53000ebfd585b"
    "3a65c97c89dfbc45a49daa7316809780d3c713976f9b01eab39aca964eac02bb"
)

# The seventeen-byte constants that top and tail each call's message
# (masked).
PREFIX_1 = bytes.fromhex("f791a04046652b8172fe8594d39f239813")
SUFFIX_1 = bytes.fromhex("e1432a53f0ffe53d9aa37df6ed0d321134")
PREFIX_2 = bytes.fromhex("ad49914004e9b07263c8ddc13890aa4b77")
SUFFIX_2 = bytes.fromhex("9ab80289ef185791299411f937046e584a")


def _unmask(data):
    return bytes(byte ^ MASK for byte in data)


def hash_block(block: bytes) -> bytes:
    """Return the 16-byte SAPHash delta of a 64-byte block.

    Tile the block across buffer1, scramble, garble, and fold the buffers
    down to sixteen bytes, starting from fresh buffers every time.  buffer3
    can start as anything: `garble` writes every byte the fold reads.
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
    The mask comes off every piece.
    """
    body = _unmask(prefix) + _unmask(MESSAGE_A) + _unmask(payload) + _unmask(suffix)
    out = bytearray(body) + b"\x80"
    while len(out) % 64 != 56:
        out.append(0)
    return bytes(out + (len(body) * 8).to_bytes(8, "little"))


def blocks(padded: bytes) -> list:
    """Return the padded message as 64-byte blocks with each word reversed.

    A little-endian read of a block then gives the big-endian word, which
    the published implementation indexes as `(in_word >> ((3 - (i % 4)) << 3))`.
    """
    return [
        bytes(b"".join(padded[at + 4 * w : at + 4 * w + 4][::-1] for w in range(16)))
        for at in range(0, len(padded), 64)
    ]


def run(parts, step31, compress_first: bool) -> list:
    """Run one SAPHash call: five blocks, five adds and five compressions.

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
    """Return the 36-byte SAP secret for *m2*.

    It is the input to every later stage: the device tag, the FairPlay
    context and the ekey.
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
