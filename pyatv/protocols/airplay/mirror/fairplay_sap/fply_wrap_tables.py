"""Tables of the ekey wrap network (see ``ekey_wrap``).

SUBSTITUTIONS holds three 256-byte tables; every one of the sixty-three
the network uses is `SUBSTITUTIONS[c][x ^ d] ^ e` for one of them.
ROUNDS, LAST, KEY_SBOXES and COLUMN give the (c, d, e) of each use.
"""

# Rounds are laid out as the 4x4 state they operate on.
# fmt: off

SUBSTITUTIONS = [
    bytes.fromhex(
        "d7448a6b839b21291fb3e54dd00055d5e71807c61c4f9c543675accf7812566f"
        "663cc3eca245de86e1ff5d6703a5716e013139eb572f0d4269a7d8c972ef9e9a"
        "6dbe357b05fd0843b25c3e6a9516ca8d252e73b1cdbfad17147fd6e38180b640"
        "0682aa876349edb40426924a1db05fbb1a93f3ea9f85d262e28c1590d4235ec5"
        "76c289c1fb4c52f1a4a9dfa6cb79af97707c7768ce6460f9206c0a3b7da0dcf5"
        "c828cc0f910e9d13e98b190c7eb92ce02d98f6bcc7fc343dfaeeae3f1e3ad37a"
        "e60bda5850baf72b32b5c061c453474111278802ab516510b8dd30598f24e822"
        "844ba85afe3396992ad1bdb7d9f8f41bf0a1e4db8e3846487409f24ea394375b"
    ),
    bytes.fromhex(
        "211cd0abeb4cc17b3774ae5f09f6566fcefa0eb517ba4ada84a5979ebc87fefb"
        "b00f59f788d70730cfef2ef4e2983cc98f8b9305f8320bb9e5686ad1bbe19c77"
        "ad7d50b1e44f2fd5261d22069b6d4692cbdc2a58c834331af3665d99d625b847"
        "8075270d485cdd1ed8bf780381c74eff6c45fcbd131f423b1816c3ca024d3a89"
        "e33ee69d53854119155428146e6bec9172c5ac355b9fde9690e0ee5286693dd9"
        "957f1b400079630871ea7ecdf98d39e8517a38a629603f5ad267d382a8558e2d"
        "d42bb2a2a0316176ed01497cf2122364364b6204a4c6b3bea7838ac2650a94db"
        "20f12caacc7044a3a157fdb79a10e70c24df11a98cb443e9c4f55eaf73b6f0c0"
    ),
    bytes.fromhex(
        "00b84972d11a300c6296d5867a479d7f5546d23477d3c7cc5e18d0ab252d9705"
        "6bcaaf586882a3f55de82050ee106ed78b5967c4011da0a8bf534e52d824852a"
        "283a1e0821cbf6a6e19c4aa4895648324088bbac8a8fba1704fa412b98f9220d"
        "dddf4c8c020703292ed495b9e231947573366039a7a9c119c5547eef7bde3bb3"
        "91b7817c7874cde5fe42691c92451bd6ecbc16b13ff4b2b066c2b4f22f8e06ae"
        "631f9b8de676be334d2c3ec6ea12c07179873d57f1aaf8a513e370b6da9e99cf"
        "261411f0a2fbf7ff90355aeddbc309c9e76f93f34fb5c85f6cad370f449adc51"
        "5c3ce461275b23e9804b7d8338e0a115d9ebfd0a846a646d0e0b659f43bdcefc"
    ),
]

# the nine full rounds: substitute, mix columns, add the round key
ROUNDS = [
    [
        (1, 0, 0), (1, 74, 0), (1, 87, 0), (1, 183, 0),
        (1, 74, 0), (1, 87, 0), (1, 183, 0), (1, 0, 0),
        (1, 87, 0), (1, 183, 0), (1, 0, 0), (1, 74, 0),
        (1, 183, 0), (1, 0, 0), (1, 74, 0), (1, 87, 0),
    ],
    [
        (1, 11, 0), (1, 171, 0), (1, 159, 0), (1, 12, 0),
        (1, 171, 0), (1, 159, 0), (1, 12, 0), (1, 11, 0),
        (1, 159, 0), (1, 12, 0), (1, 11, 0), (1, 171, 0),
        (1, 12, 0), (1, 11, 0), (1, 171, 0), (1, 159, 0),
    ],
    [
        (1, 45, 0), (1, 132, 0), (1, 25, 0), (1, 23, 0),
        (1, 132, 0), (1, 25, 0), (1, 23, 0), (1, 45, 0),
        (1, 25, 0), (1, 23, 0), (1, 45, 0), (1, 132, 0),
        (1, 23, 0), (1, 45, 0), (1, 132, 0), (1, 25, 0),
    ],
    [
        (1, 21, 0), (1, 147, 0), (1, 136, 0), (1, 157, 0),
        (1, 147, 0), (1, 136, 0), (1, 157, 0), (1, 21, 0),
        (1, 136, 0), (1, 157, 0), (1, 21, 0), (1, 147, 0),
        (1, 157, 0), (1, 21, 0), (1, 147, 0), (1, 136, 0),
    ],
    [
        (1, 163, 0), (1, 50, 0), (1, 184, 0), (1, 39, 0),
        (1, 50, 0), (1, 184, 0), (1, 39, 0), (1, 163, 0),
        (1, 184, 0), (1, 39, 0), (1, 163, 0), (1, 50, 0),
        (1, 39, 0), (1, 163, 0), (1, 50, 0), (1, 184, 0),
    ],
    [
        (1, 224, 0), (1, 208, 0), (1, 106, 0), (1, 79, 0),
        (1, 208, 0), (1, 106, 0), (1, 79, 0), (1, 224, 0),
        (1, 106, 0), (1, 79, 0), (1, 224, 0), (1, 208, 0),
        (1, 79, 0), (1, 224, 0), (1, 208, 0), (1, 106, 0),
    ],
    [
        (1, 234, 0), (1, 56, 0), (1, 80, 0), (1, 29, 0),
        (1, 56, 0), (1, 80, 0), (1, 29, 0), (1, 234, 0),
        (1, 80, 0), (1, 29, 0), (1, 234, 0), (1, 56, 0),
        (1, 29, 0), (1, 234, 0), (1, 56, 0), (1, 80, 0),
    ],
    [
        (1, 230, 0), (1, 220, 0), (1, 142, 0), (1, 145, 0),
        (1, 220, 0), (1, 142, 0), (1, 145, 0), (1, 230, 0),
        (1, 142, 0), (1, 145, 0), (1, 230, 0), (1, 220, 0),
        (1, 145, 0), (1, 230, 0), (1, 220, 0), (1, 142, 0),
    ],
    [
        (1, 246, 0), (1, 40, 0), (1, 164, 0), (1, 55, 0),
        (1, 40, 0), (1, 164, 0), (1, 55, 0), (1, 246, 0),
        (1, 164, 0), (1, 55, 0), (1, 246, 0), (1, 40, 0),
        (1, 55, 0), (1, 246, 0), (1, 40, 0), (1, 164, 0),
    ],
]

# the tenth round, which has no column step
LAST = [
    (0, 97, 34), (0, 75, 34), (0, 237, 34), (0, 216, 34),
    (0, 75, 196), (0, 237, 196), (0, 216, 196), (0, 97, 196),
    (0, 237, 138), (0, 216, 138), (0, 97, 138), (0, 75, 138),
    (0, 216, 33), (0, 97, 33), (0, 75, 33), (0, 237, 33),
]

# one per round key: the SubWord of AES's key schedule
KEY_SBOXES = [
    (0, 0, 0),
    (0, 157, 45),
    (0, 134, 51),
    (0, 12, 189),
    (0, 182, 72),
    (0, 222, 1),
    (0, 140, 7),
    (0, 0, 27),
    (0, 166, 114),
    (0, 167, 0),
]

# the S-box the four column tables fold MixColumns over
COLUMN = (2, 0, 0)

# AES's own round constants, byte for byte
RCON = (0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36)

PLAINTEXT_XOR = bytes.fromhex("e69033f48a0f4d4a79d904222fffd4ff")
KEY_XOR = bytes.fromhex("0f0f0f0fadadadad393939399e9e9e9e")
OUTPUT_XOR = bytes.fromhex("afafafafeeeeeeeea1a1a1a13e3e3e3e")
COLUMN_XOR = bytes.fromhex("4a4a4a4a")

# the four column tables' own offsets.  Only their XOR --
# COLUMN_XOR -- can reach the answer, because every column
# step XORs all four in.
COLUMN_OFFSETS = (
    bytes.fromhex("93a85908"),
    bytes.fromhex("37e12252"),
    bytes.fromhex("46d90010"),
    bytes.fromhex("a8da3100"),
)
