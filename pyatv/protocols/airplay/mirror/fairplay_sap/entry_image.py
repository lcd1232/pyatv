"""Window 0's entry image, built from M2 instead of emulated.

`garble_gen.build` turns any window of the program into straight-line
Python, and the generated source is byte-identical for every M2 -- so
the ports are a program, and the only thing that still needed the
emulator at handshake time was the first memory image the chain starts
from.  This module is that image.

WHAT DEPENDS ON M2.  Snapshotting window 0's `before` for six vectors and
diffing them leaves **272 of 163,332 bytes**, in nine runs:

    flat        logical       physical      len  what
    0x0061c     0x6fffc61c    0x1016f4608     1  cipher scratch (dead)
    0x00620     0x6fffc620    0x1016f460c     4  cipher scratch (dead)
    0x00628     0x6fffc628    0x1016f4614     1  cipher scratch (dead)
    0x00898     0x6fffc898    0x1016f4884     4  cipher scratch (dead)
    0x00dd4     0x6fffcdd4    0x1016f4dc0   128  the decrypted payload
    0x0192c     0x6fffd92c    0x1016f5918     4  cipher scratch (dead)
    0x0263c     0x6fffe63c    0x1016f6628     1  cipher scratch (dead)
    0x02e64     0x6fffee64    0x1016f6e50     1  cipher scratch (dead)
    0x278d0     0x40001acc    0x1016f9ab8   128  the staged M2 itself

Everything else -- the five garble buffers, SAPHash's 210-byte staging
block, the constant tables, the frame prefix -- is the same bytes for
every input, which is why a template captured once serves them all.

THE ONE LIVE PIECE.  Patching each run in turn into a template built
from a different M2 and running the eight-window chain shows that only
**one** of the nine matters: the 128 bytes at 0x1016f4dc0.  Patch that
alone and the chain produces the other M2's SAP secret exactly; patch
all the others and leave it alone and it produces the template's.  The
staged M2 is dead by then (the payload has already been decrypted out of
it) and so is the scratch.

WHAT THOSE 128 BYTES ARE.  `m2[14:142]` -- the message with its 14-byte
header off -- **CBC-decrypted** under Region A's cipher, the one
`fply_pure.decrypt_m2` already ports:

    plain[j] = decrypt_m2(m2_block[j]) ^ (m2_block[j-1] or IV)

The eight blocks run backwards through the buffer (block 7 first, at ops
44,821..48,575; block 0 last, ending at 76,403) and each byte is written
exactly 21 times, which is one pass of the ten-round network and nothing
else.  `test_region_a` only ever looked at three of the eight blocks and
compared them to the ECB output, which is the plaintext XOR the previous
ciphertext away from what the buffer actually ends up holding -- the
missing XOR is the whole reason the buffer looked unrecognisable.

CBC also explains the diffusion: flipping one byte of the payload moves
seventeen bytes of the buffer, sixteen in its own block and the one byte
of the next block that the chaining carries.

THE DEAD SCRATCH.  The other 11 bytes are intermediates the cipher left
behind on its last two blocks, and they are reproducible too -- the
round-8 states of blocks 0 and 1, plus one partial mix accumulator:

    0x061c = state8_sub(block0)[12]        0x2e64 = state8_mix(block0)[3]
    0x0628 = state8_sub(block0)[14]        0x263c = state8_mix(block1)[3]
    0x192c = state8_out(block0)[12:16]     0x0898 = state8_out(block1)[12:16]
    0x0620 = MIX3[state8_sub(block0)[15]] ^ ACCUMULATOR_RESIDUE

so `build` reproduces the emulator's image byte for byte, not merely
where it matters.

WHAT THE PACKAGE GETS is `payload` and the offsets, and nothing else:
`build` and the snapshotting it is checked against are about an emulator
run, and an installed pyatv has no emulator to run.  They stay in
`devirt/`.

Run: uv run --with capstone python -m devirt.entry_image
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

# op index of the first garble call -- where window 0 opens
WINDOW0 = 431_184
# the staging allocator hands the entry call this frame; the message
# lands at +0x12c and the FairPlay context at +0x18
FRAME_BASE = 0x40001992
# flat offsets into the image `garble_gen.BLOCKS` lays out
LIVE_AT, LIVE_LENGTH = 0xDD4, 128
STAGE_AT = 0x278C2
# the CBC initialisation vector, recovered as the residue between the
# buffer's first block and the ECB decryption of the first ciphertext
# block -- constant across every vector tried
IV = bytes.fromhex("df7b1563f005587752a90402b9a39295")
# what the last partial mix accumulator carries besides the lane-3 table
# entry.  The store happens after only one of the four lookups (the
# traced lane order is 3, 1, 0, 2), and this is the rest of it.
ACCUMULATOR_RESIDUE = bytes.fromhex("1abfdde0")
# where the message the payload is decrypted from sits
PAYLOAD = slice(14, 142)
BLOCK = 16

# (flat offset, block, step, byte offset, width) for the dead scratch.
# `step` indexes the state list `devirt.entry_image.states` returns: 25
# is round 8's substitution, 26 its column step, 27 the 0x0d mask that
# follows.
SCRATCH = (
    (0x061C, 0, 25, 12, 1),
    (0x0628, 0, 25, 14, 1),
    (0x2E64, 0, 26, 3, 1),
    (0x192C, 0, 27, 12, 4),
    (0x263C, 1, 26, 3, 1),
    (0x0898, 1, 27, 12, 4),
)


def payload(m2: bytes) -> bytes:
    """Return the 128 live bytes: `m2[14:142]`, CBC-decrypted under Region A."""
    out, previous = bytearray(), IV
    for at in range(PAYLOAD.start, PAYLOAD.stop, BLOCK):
        block = m2[at : at + BLOCK]
        out += bytes(x ^ y for x, y in zip(fply_pure.decrypt_m2(block), previous))
        previous = block
    return bytes(out)
