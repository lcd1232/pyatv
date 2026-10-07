"""Region B as the algorithm it already was: 3.9 MB of port, deleted.

Region B is the device_tag engine -- ops 846,292 to 924,164 of the first
entry call, VM-17, the 20-byte MAC the receiver checks and the one piece
of FPLY the notes call the blob wall.  `sap_image` ships it as ONE
generated window, because tiling it at 36,000 ops bakes an inherited
register into the middle port and 38 bytes come out wrong; one window
avoids that, and it is the biggest port in the directory.

None of that is needed.  Region B was recovered as an ALGORITHM under
task 6, before the engine-window port existed, and the recovery lives in
`fply_pure.device_tag` and `fply_md5`.  Nothing had to be re-derived
here; what this module is, is the proof of equivalence and the call site
that lets `sap_image.handshake` stop generating the window at all.

WHAT REGION B COMPUTES.  Its live input is 20 bytes, not 36:
``sap36[16:36]``, at 0x400019c2 where the entry preamble staged the SAP
secret (`sap_image` measures that boundary from the memory side;
`test_opexec.test_sap_secret_splits_into_tag_and_wrap_halves` proves it
from the black-box side -- the first sixteen bytes move none of the
tag's 160 bits).  Its output is 20 bytes at 0x40001be8, the M3 buffer
plus 144.  Between them:

    A      = [MD5(KEY_BASE, secret^0x0d || r || SALT) for r in 0..8]
    X      = forward(CONSTANT_BLOCK, A)          one AES-shaped network
    init   = MD5(LINK_IV, X || LINK_SALT)
    out    = backward(init, A reversed) ^ FINAL_XOR
    tag    = out[:4] || MD5(LINK_IV, init || out)

-- nine modified MD5 compressions for the key schedule, a 10-round
block cipher run forwards over a fixed block and backwards over the
link's output, and two more compressions.  The MD5 is MD5 by the book
except that step 31 shuffles the message block with the state; the
cipher is 320 substitution tables that reduce to six plus a
(class, in-xor, out-xor) triple per step.  `fply_md5` and `fply_pure`
say all of it in 12 KB, over the 26 KB of tables Region A shares.

BEFORE AND AFTER.  The window's port against what replaces it, both
measured rather than quoted (`garble_gen.build` on seed 1001):

    sap_image.REGION_B, one window   3,891,056 bytes  83,339 lines  31 s
    region_b + fply_pure + fply_md5     17,324 bytes     no build
    (fply_tables and md5probe, shared with Region A)

and the tag itself goes from generated straight-line Python over a
167 KB image to 0.45 ms.

Measuring it turned up one stale number.  `sap_image`'s docstring gave
the two single-engine windows as "2.6 MB and 3.9 MB of source" in the
order Region B, M4; they are the other way round -- Region B's 77,872
ops are 3,891,056 bytes and the M4 call's 86,021 ops are 2,620,767 --
and the brief for this work inherited the swap.  Fixed there.  Region B
was the larger of the two all along.

WHAT WAS VERIFIED, AND AGAINST WHAT.  The trap in this directory is that
a generated port is not a faithful oracle -- the lift folds any load it
knew the value of, so a rule fitted to the port alone can be right on
the handshakes it was lifted from and wrong everywhere else.  So nothing
here is checked against a port.  `test_region_b_read` checks against
`opexec`, which runs the slice:

* 16 fresh handshakes, two each from seeds 13, 99, 555, 2024, 12345,
  65535, 424242 and 8 -- none of them a seed `fply_pure` was fitted or
  frozen against -- M2 through `opexec.sap_secret` into
  `fply_pure.device_tag`, compared with the emulator's own
  ``m3[144:164]``.  All 16 exact.
* 32 CHOSEN secrets through `opexec.device_tag_for_sap`: zeros, 0xff,
  the 0x0d mask itself, counting bytes, six random, one random base and
  five single-bit neighbours of it, and that base with its first secret
  byte's low nibble driven through all sixteen values -- which is the
  exact shape of the fold's constant-folding trap, where a nibble that
  happened to be 8 on both bench handshakes got baked in.  All 32
  exact.
* the 8 frozen rows in `devirt.vectors` (seeds 2026 x4, 1001, 4242, 7,
  31337), which is what the quick tier runs.

Run: uv run python -m devirt.region_b
"""

from . import fply_pure

__all__ = ["device_tag", "SAP_LENGTH", "TAG_LENGTH", "TAG_HALF"]

SAP_LENGTH = 36
TAG_LENGTH = 20
# the only part of the secret Region B reads
TAG_HALF = slice(16, 36)


def device_tag(sap36: bytes) -> bytes:
    """The 20-byte device_tag, from the whole 36-byte SAP secret.

    Takes the boundary's value rather than `fply_pure.device_tag`'s
    20-byte tail, so it drops into `sap_image.handshake` where the
    generated window used to go.  ``sap36[0:16]`` is accepted and
    ignored, which is what the engine does with it.
    """
    if len(sap36) != SAP_LENGTH:
        raise ValueError(f"sap36 is {len(sap36)} bytes, not {SAP_LENGTH}")
    return fply_pure.device_tag(bytes(sap36[TAG_HALF]))
