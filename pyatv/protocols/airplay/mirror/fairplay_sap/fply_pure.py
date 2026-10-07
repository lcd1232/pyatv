"""The FPLY device_tag and the M2 cipher.

    device_tag(sap_secret_tail) -> 20 bytes

Three MD5 compressions of a slightly modified kind (``fply_md5``) and one
block cipher run twice under one key:

    A      = [MD5(KEY_BASE, secret^0x0d || counter || salt) for r in 0..8]
    X      = network(CONST, A)                       forwards
    init   = MD5(LINK_IV, X || LINK_SALT)
    out    = network(init, A reversed) ^ FINAL_XOR   backwards
    tag    = out[0:4] || MD5(LINK_IV, init || out)

The two directions are one cipher: ``backward(forward(CONST)) == CONST``
under the same key, which is why the link in the middle has to be there.

The tables are in ``fply_tables``.  All 320 substitution tables are
XOR-equivalent to just six, so what ships is six tables and a (class,
in-xor, out-xor) triple per step.
"""

from . import fply_md5
from .fply_tables import (
    BACKWARD,
    BACKWARD_COLUMNS,
    FORWARD,
    FORWARD_COLUMNS,
    SUBSTITUTIONS,
)

__all__ = [
    "device_tag",
    "forward",
    "backward",
    "decrypt_m2",
    "CONSTANT_BLOCK",
    "REGION_A_KEYS",
    "ROUND_MASK",
]

# what the forward pass encrypts -- the same sixteen bytes every time
CONSTANT_BLOCK = bytes.fromhex("0f545e5ab77e16801aedd581d08726dc")

# AES's two row permutations: byte 4c+r is fed from 4*((c±r) % 4)+r
SHIFT_ROWS = [4 * ((c + r) % 4) + r for c in range(4) for r in range(4)]
INV_SHIFT_ROWS = [4 * ((c - r) % 4) + r for c in range(4) for r in range(4)]
_ROUNDS = 10


def _substitute(state, row, shift, key):
    """One round's sixteen table lookups, all reading the state as it was."""
    source = bytes(state)
    for position, (table, in_xor, out_xor) in enumerate(row):
        substituted = SUBSTITUTIONS[table][source[shift[position]] ^ in_xor]
        state[position] = substituted ^ out_xor ^ key[position]


def _mix(state, columns):
    """Four columns, each the XOR of one lookup per lane."""
    for column in range(4):
        word = bytearray(4)
        for lane in range(4):
            at = 4 * state[4 * column + lane]
            word = bytearray(a ^ b for a, b in zip(word, columns[lane][at : at + 4]))
        state[4 * column : 4 * column + 4] = word


def forward(block, keys):
    """Encrypt: ShiftRows, and the key applied after the mix."""
    state = bytearray(block)
    for index, row in enumerate(FORWARD):
        _substitute(state, row, SHIFT_ROWS, bytes(16))
        if index < _ROUNDS - 1:
            _mix(state, FORWARD_COLUMNS)
            state = bytearray(a ^ b for a, b in zip(state, keys[index]))
    return bytes(state)


def backward(block, keys):
    """Decrypt: InvShiftRows, and the key in the lookup."""
    state = bytearray(block)
    for index, row in enumerate(BACKWARD):
        _substitute(state, row, INV_SHIFT_ROWS, keys[index])
        if index < _ROUNDS - 1:
            _mix(state, BACKWARD_COLUMNS)
    return bytes(a ^ b for a, b in zip(state, fply_md5.FINAL_XOR))


def device_tag(secret):
    """Return the 20-byte device_tag for a 20-byte SAP secret tail."""
    schedule = fply_md5.round_keys(secret)  # backward order, 10 keys
    ciphertext = forward(CONSTANT_BLOCK, schedule[8::-1])
    initial = fply_md5.link(ciphertext)
    return fply_md5.device_tag(initial, backward(initial, schedule))


# ---------------------------------------------------------------------------
# The M2 cipher (used by region_a): the same network under a fixed key
# ---------------------------------------------------------------------------
#
# `m2 -> sap36` decrypts the M2 payload (see `entry_image.payload`) with
# this same network -- same tables, same per-step assignment, same column
# tables -- under one fixed schedule.
#
# Two differences from the tag network's backward pass: the state is
# XORed with 0x0d after every column step, and there is no FINAL_XOR at
# the end -- the tenth round key is the 0x0d mask instead.
REGION_A_KEYS = [
    bytes.fromhex("dae191aefb23b396cac502ffba36d387"),
    bytes.fromhex("fc770ca1e9d83f565070e3c7b27bf65d"),
    bytes.fromhex("e94bec1142d1fa92f9447b421e9b8bc2"),
    bytes.fromhex("e00f4e0e51b15a934e0f6aac9681fe59"),
    bytes.fromhex("3333bd4a1d6ee57f11352074c97a31dc"),
    bytes.fromhex("7b5fd80f61bbc25af3bfb2ba3d5b7696"),
    bytes.fromhex("c1439e3c762a19f1207c50e9bdf4468f"),
    bytes.fromhex("a4f03049e37661254f3c6e8a60df6045"),
    bytes.fromhex("fcaf0977a3e4d5b2d9cd667acc088194"),
    bytes.fromhex("0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d"),
]
ROUND_MASK = bytes([0x0D]) * 16
# The middle three blocks of the M2 payload, a convenient window for
# checking `decrypt_m2` before the CBC chaining XOR is applied.
M2_CIPHERTEXT = slice(62, 110)


def decrypt_m2(block):
    """Decrypt one 16-byte block of the M2 payload, without CBC chaining."""
    state = bytearray(block)
    for index, row in enumerate(BACKWARD):
        _substitute(state, row, INV_SHIFT_ROWS, REGION_A_KEYS[index])
        if index < _ROUNDS - 1:
            _mix(state, BACKWARD_COLUMNS)
            state = bytearray(a ^ b for a, b in zip(state, ROUND_MASK))
    return bytes(state)
