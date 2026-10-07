"""The M4 call's derive engine, as the algorithm instead of as its trace.

`sap_image.M4_DERIVE` says this engine one Python statement per executed
instruction: 86,021 ops become 53,728 statements and 2.6 MB of generated
source, half a minute to build, for a 276-byte answer.  Read instead of
compressed it is this file, and what it turns out to be is short enough
to state in one line:

    cph = AES-128-CBC(TEMPLATE with the secret spliced in), flag byte set

That is the whole of it.  A textbook AES-128 -- the FIPS-197 S-box, the
FIPS-197 key schedule, the FIPS-197 MixColumns -- under a hard-coded
16-byte key, in CBC over the 256-byte body of the FairPlay context, with
the 36-byte SAP secret sitting at offset 8 of the plaintext.  The last
20 bytes are not encrypted; one byte of them is set to 1.

HOW IT WAS READ.  `spn.recover_program` already knows how to read an
AES-shaped network off a trace -- it is what recovered the device_tag's
network in `spn.py` -- and the derive engine is the same shape, so it
reads straight out with `buffer` pointed at the staged context:

    8,225 stores    5,089 plain, 2,560 substitutions, 576 column steps

2,560 = 16 blocks x 10 rounds x 16 bytes and 576 = 16 x 9 x 4, which is
sixteen ten-round encryptions before anything else is looked at.  The
plain stores are the four things around them: an initial XOR of a 16-byte
constant over all 256 bytes, the CBC chaining (`ctx[16k+j] ^= ctx[16k-16+j]`,
visible as a load of the previous block against a load of this one), the
round keys, and a final XOR of a second 16-byte constant.

WHY THERE IS NO PLAINTEXT WHITENING IN THIS FILE.  The engine really does
XOR those two constants, and the round keys it applies really are not an
AES key schedule -- as the slice has them,

    F = d0d0d0d0 79797979 bfbfbfbf 67676767   before
    G = afafafaf eeeeeeee a1a1a1a1 3e3e3e3e   after

with sixteen more masks inside: each round's four substitution tables are
`S(x ^ d)` for four different d, the last round's sixteen are
`S(x ^ d) ^ e`, and the four column tables carry an offset that XORs to
0x4a4a4a4a.  Folding every one of those into the round keys where it
belongs -- an input mask into the key before it, an output mask into the
key after, MixColumns being linear with coefficient sum 1 so a constant
passes through it unchanged -- leaves eleven 16-byte round keys, and
words 8..39 of THOSE are a plain AES-128 expansion with the plain Rcon.
Inverting the expansion back to words 0..3 gives `KEY`, and the two
places the recovered keys then disagree with the schedule are exactly the
two a whitening constant can hide in: round key 0, which XORs where the
plaintext does, and round key 10, which XORs where the output does.  Both
differences come out equal to the whitening:

    RK[0]  ^ schedule[0]  = 7f7f7f7f 97979797 1e1e1e1e 59595959
    RK[10] ^ schedule[10] = G exactly, and F ^ that difference ^ G = 0

so F and G cancel and the IV is the last thing left, `IV`.  Nothing here
is fitted: every constant is a measured one folded by an identity.

THE TABLES ARE APPLE'S, THE CIPHER IS NOT APPLE'S.  52 substitution
tables of 256 bytes and 4 column tables of 1,024 sit in the slice's
masked rodata at 0x3352f908..0x33533d08.  Reduced by the same
`T(x) = R(x ^ d) ^ e` relation `extract_tables` uses on VM-17's networks
they collapse to TWO classes, one for rounds 0..8 and one for round 9,
and the round-9 class is `AES_SBOX[x ^ 0xf2] ^ 0x29`.  The other class is
not the S-box on its own; composed with the byte the column table looks
up it is -- `column(class0(x)) = AES_SBOX[x ^ 0x7d] ^ 0x35`, and the
column table minus its offset is `(2s, s, s, 3s)`, MixColumns by the
book, with lanes 1..3 the byte rotations of lane 0.  So the whitebox
splits its S-box across the substitution and the column table and the
join is textbook AES.

    17,408 bytes of Apple's tables  ->  the FIPS-197 S-box
    2.6 MB of generated Python      ->  this file, 10 KB

WHAT DEPENDS ON WHAT.  `TEMPLATE` is the 276-byte context as it stands
when the derive engine opens, with the secret's 36 bytes zeroed.  It is
the same for every handshake -- `test_m4_derive` checks that against the
emulator on eight of them -- which is why this map is a function of the
secret alone, the thing `boundary_image`'s docstring records from the
other side.  The dependency pattern it predicted falls straight out of
CBC: `sap36[0:8]` lands in block 0, `[8:24]` in block 1, `[24:36]` in
block 2, and the chaining carries each into everything after.

Run: uv run --with capstone python -m devirt.m4_derive
"""

__all__ = [
    "context",
    "encrypt_block",
    "cbc_encrypt",
    "expand_key",
    "KEY",
    "IV",
    "TEMPLATE",
    "SBOX",
    "RCON",
    "SECRET_AT",
    "SECRET_LENGTH",
    "BODY",
    "FLAG_AT",
    "FLAG",
    "CONTEXT_LENGTH",
    "SHIFT_ROWS",
]

# the AES-128 key the slice's round keys expand from, and the CBC IV --
# both recovered by folding the whitebox's masks into the round keys
KEY = bytes.fromhex("f83eb39446ec36c7b5e49af7676fac4d")
IV = bytes.fromhex("486474c19f83dbff8c53e93038fc4e7a")

# The 276-byte plaintext, with the secret's slot zeroed.  Sparse: an
# eight-byte header, the secret, a 36-byte run of the 0x0d mask this
# slice XORs over secrets everywhere, a four-byte version word at 124,
# and the 20-byte tail the cipher does not touch.
TEMPLATE = bytes.fromhex(
    "0005000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"
    "0d0d0d0d0000000000000000000000000000000000000000000000000203095e"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00a1a1d516e0d1d5deab98f2555e898150000000"
)

CONTEXT_LENGTH = 0x114  # 276
SECRET_AT, SECRET_LENGTH = 8, 36  # where the entry preamble stages it
BODY = 256  # how much of the context is encrypted
# the one byte of the tail the engine changes: 0 going in, 1 coming out
FLAG_AT, FLAG = 256, 1

# FIPS-197, verbatim
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
# ShiftRows on the column-major state: byte 4c+r comes from 4*((c+r)%4)+r
SHIFT_ROWS = tuple(4 * ((c + r) % 4) + r for c in range(4) for r in range(4))


def _xtime(value):
    value <<= 1
    return (value ^ 0x1B) & 0xFF if value & 0x100 else value


def expand_key(key=KEY):
    """Return the eleven round keys, by the book."""
    if len(key) != 16:
        raise ValueError(f"key is {len(key)} bytes, not 16")
    words = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    for index in range(4, 44):
        word = list(words[index - 1])
        if index % 4 == 0:
            word = [SBOX[byte] for byte in word[1:] + word[:1]]
            word[0] ^= RCON[index // 4 - 1]
        words.append([a ^ b for a, b in zip(words[index - 4], word)])
    return [bytes(sum(words[4 * r : 4 * r + 4], [])) for r in range(11)]


def encrypt_block(block, schedule=None):
    """One AES-128 encryption of sixteen bytes."""
    schedule = schedule or expand_key()
    state = bytearray(a ^ b for a, b in zip(block, schedule[0]))
    for index in range(1, 11):
        state = bytearray(SBOX[state[SHIFT_ROWS[p]]] for p in range(16))
        if index < 10:
            mixed = bytearray(16)
            for column in range(4):
                lane = state[4 * column : 4 * column + 4]
                for i in range(4):
                    mixed[4 * column + i] = (
                        _xtime(lane[i])
                        ^ _xtime(lane[(i + 1) % 4])
                        ^ lane[(i + 1) % 4]
                        ^ lane[(i + 2) % 4]
                        ^ lane[(i + 3) % 4]
                    )
            state = mixed
        state = bytearray(a ^ b for a, b in zip(state, schedule[index]))
    return bytes(state)


def cbc_encrypt(plaintext, key=KEY, iv=IV):
    """AES-128-CBC over a whole number of blocks."""
    if len(plaintext) % 16:
        raise ValueError(f"{len(plaintext)} bytes is not whole blocks")
    schedule = expand_key(key)
    chain, out = iv, bytearray()
    for at in range(0, len(plaintext), 16):
        chain = encrypt_block(
            bytes(a ^ b for a, b in zip(plaintext[at : at + 16], chain)), schedule
        )
        out += chain
    return bytes(out)


def context(sap36, template=TEMPLATE):
    """Return the 276-byte FairPlay context the M4 call derives from *sap36*.

    What `sap_image.context` reads out of the memory the generated port
    leaves behind, and what `boundary_image.build` needs.
    """
    if len(sap36) != SECRET_LENGTH:
        raise ValueError(f"sap36 is {len(sap36)} bytes, not {SECRET_LENGTH}")
    plain = bytearray(template)
    plain[SECRET_AT : SECRET_AT + SECRET_LENGTH] = sap36
    out = bytearray(cbc_encrypt(bytes(plain[:BODY])) + plain[BODY:])
    out[FLAG_AT] = FLAG
    return bytes(out)
