"""Decrypt the part of M2 that the SAP secret is derived from.

The 128 bytes ``m2[14:142]`` (M2 without its 14-byte header) are
CBC-decrypted under the cipher ``fply_pure.decrypt_m2`` implements:

    plain[j] = decrypt_m2(m2_block[j]) ^ (m2_block[j-1] or IV)

The result is the only M2-dependent input of ``region_a.sap_secret``; the
rest of M2 does not affect the secret.  Flipping one payload byte changes
seventeen bytes of the output: its own block and one byte of the next.
"""

from . import fply_pure

__all__ = [
    "payload",
    "IV",
    "WINDOW0",
    "LIVE_AT",
    "LIVE_LENGTH",
    "STAGE_AT",
    "FRAME_BASE",
    "SCRATCH",
    "ACCUMULATOR_RESIDUE",
]

# Locations in the reference sender's memory image; payload() does not
# use them.
WINDOW0 = 431_184
FRAME_BASE = 0x40001992
LIVE_AT, LIVE_LENGTH = 0xDD4, 128
STAGE_AT = 0x278C2
# the CBC initialisation vector, the same for every M2
IV = bytes.fromhex("df7b1563f005587752a90402b9a39295")
# Residue of a partially accumulated column step in the reference
# sender's scratch memory; payload() does not use it.
ACCUMULATOR_RESIDUE = bytes.fromhex("1abfdde0")
# where the encrypted payload sits in M2
PAYLOAD = slice(14, 142)
BLOCK = 16

# (offset, block, step, byte offset, width) of intermediate cipher states
# left in the reference sender's scratch memory; payload() does not use
# them.
SCRATCH = (
    (0x061C, 0, 25, 12, 1),
    (0x0628, 0, 25, 14, 1),
    (0x2E64, 0, 26, 3, 1),
    (0x192C, 0, 27, 12, 4),
    (0x263C, 1, 26, 3, 1),
    (0x0898, 1, 27, 12, 4),
)


def payload(m2: bytes) -> bytes:
    """Return `m2[14:142]` CBC-decrypted under the M2 cipher."""
    out, previous = bytearray(), IV
    for at in range(PAYLOAD.start, PAYLOAD.stop, BLOCK):
        block = m2[at : at + BLOCK]
        out += bytes(x ^ y for x, y in zip(fply_pure.decrypt_m2(block), previous))
        previous = block
    return bytes(out)
