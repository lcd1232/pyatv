"""Derive the 276-byte FairPlay context that the M4 step leaves behind.

    context = AES-128-CBC(KEY, IV, plaintext[0:256]) || plaintext[256:276]

where ``plaintext`` is ``TEMPLATE`` with the 36-byte SAP secret at offset
8, and byte 256 of the unencrypted tail is then set to ``FLAG``.  The
cipher is textbook AES-128 (FIPS-197 S-box, key schedule and MixColumns)
under a fixed key and IV.

Apple ships it as a white-box: masked substitution tables, column tables
with constant offsets, and whitening constants before and after the
cipher.  Folding every mask into the adjacent round key leaves a plain
AES-128 key schedule expanding from ``KEY``, and the remaining whitening
reduces to the CBC IV, ``IV``.

``TEMPLATE`` is the same for every handshake, so the context is a function
of the SAP secret alone.  Through CBC, ``sap36[0:8]`` lands in block 0,
``[8:24]`` in block 1 and ``[24:36]`` in block 2, and each block chains
into all that follow.
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

# the AES-128 key and CBC IV that the white-box's masked round keys and
# whitening constants reduce to
KEY = bytes.fromhex("f83eb39446ec36c7b5e49af7676fac4d")
IV = bytes.fromhex("486474c19f83dbff8c53e93038fc4e7a")

# The 276-byte plaintext, with the secret's slot zeroed.  Sparse: an
# eight-byte header, the secret, a 36-byte run of FPLY's 0x0d mask, a
# four-byte version word at 124, and the 20-byte tail the cipher does not
# touch.
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
SECRET_AT, SECRET_LENGTH = 8, 36  # where the SAP secret sits in the plaintext
BODY = 256  # how much of the context is encrypted
# the one byte of the unencrypted tail that changes: 0 going in, 1 coming out
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
    """Return the 276-byte FairPlay context the M4 step derives from *sap36*."""
    if len(sap36) != SECRET_LENGTH:
        raise ValueError(f"sap36 is {len(sap36)} bytes, not {SECRET_LENGTH}")
    plain = bytearray(template)
    plain[SECRET_AT : SECRET_AT + SECRET_LENGTH] = sap36
    out = bytearray(cbc_encrypt(bytes(plain[:BODY])) + plain[BODY:])
    out[FLAG_AT] = FLAG
    return bytes(out)
