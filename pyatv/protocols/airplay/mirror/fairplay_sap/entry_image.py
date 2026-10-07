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
]

# the CBC initialisation vector, the same for every M2
IV = bytes.fromhex("df7b1563f005587752a90402b9a39295")
# where the encrypted payload sits in M2
PAYLOAD = slice(14, 142)
BLOCK = 16


def payload(m2: bytes) -> bytes:
    """Return `m2[14:142]` CBC-decrypted under the M2 cipher."""
    out, previous = bytearray(), IV
    for at in range(PAYLOAD.start, PAYLOAD.stop, BLOCK):
        block = m2[at : at + BLOCK]
        out += bytes(x ^ y for x, y in zip(fply_pure.decrypt_m2(block), previous))
        previous = block
    return bytes(out)
