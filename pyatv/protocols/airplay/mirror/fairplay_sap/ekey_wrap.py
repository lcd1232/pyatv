"""Region C -- the ekey wrap -- read rather than compressed.

Region C ships as seven generated windows (`boundary_image.windows()`,
engine span 1,094,859..1,333,775), tens of thousands of machine-translated
statements each.  This module is what those windows turn out to BE --
all of them, in closed form, with no emulator and no interpreter.  What
is claimed is measured, and every measurement says how.

    ekey(sap36, raw16)
        = HEADER || mac(sap36, raw16) || wrap(sap36[0:16], raw16)
            36    +        20         +           16              = 72

WHAT REGION C ACTUALLY READS.  Its boundary is 276 bytes of FairPlay
context plus `raw16`, but flipping one bit of the context at a time --
all 276 of them, through `opexec`-grade replays, not through the
generated port -- says only 48 of those bytes reach the answer:

    ctx[0:16]     a gate.  Any bit flipped and the entry returns an
                  EMPTY ekey (length 0), so it is checked, not used.
    ctx[16:32]    moves all 36 session-dependent bytes.
    ctx[32:48]    moves ekey[0x24:0x38] only -- the 20-byte MAC.
    ctx[48:256]   DEAD.  208 bytes, not one of them reaches the ekey.
    ctx[256:273]  a second gate (same empty-ekey behaviour).
    ctx[273:276]  dead.

And those 48 live bytes are the **SAP secret, encrypted**.  Ops 0
through ~145,000 of the engine -- windows 0 to 4, three fifths of the
region -- are one thing: they decrypt the context in place, and when
they are done the package frame at logical 0x40001d70 holds
``opexec.sap_secret(m2)`` verbatim, all 36 bytes of it.  (Peeked out of
a live Sim at op 145,000; the same run finds sap36[16:36] already in
place at op 121,000, which is when the MAC starts.)  Region A already
produces sap36 from M2 with no emulator, so for a SENDER that whole
stretch is redundant work: it is the receiver's context being unwrapped
back into a secret the sender computed itself in Region A.

HOW THE SECRET SPLITS.  Injecting a one-bit change into sap36 with
``opexec.handshake_with_sap`` -- 36 probes, one per byte -- splits the
secret perfectly in two:

    sap36[0:16]   -> ekey[0x38:0x48] and nothing else
    sap36[16:36]  -> ekey[0x24:0x38] and nothing else

So the wrap key and the MAC key are disjoint halves of the SAP secret,
and the two outputs are independent.

THE MAC -- SOLVED, EXACTLY.  ``ekey[0x24:0x38]`` is a **stock
HMAC-SHA-1**, no modification of any kind:

    ekey[0x24:0x38] = HMAC-SHA1(sap36[16:36] ^ 0x0d, HEADER || raw16)

The key is the secret's tail under FPLY's usual 0x0d mask -- the same
mask ``fply_md5.SECRET_MASK`` applies before the device_tag's hashing.
The message is 52 bytes: the ekey's own constant header with the
plaintext ``raw16`` where the wrapped key will later sit.

This was read out of the engine, not guessed.  The four SHA-1
compressions are ops 121,167..140,921 and they are shaped 16 + 64 + 20 +
20 + 20 + 20: sixteen message words, sixty-four schedule expansions,
four round groups of twenty.  Their block buffer stores everything
XORed with 0x0d0d0d0d, and unmasked it reads

    block 1  key^0x36...            eleven words of 0x36363636   ipad
    block 2  "FPLY" 01 02 01 ...    length 0x3a0 = 928 bits      message
    block 3  key^0x5c...            eleven words of 0x5c5c5c5c   opad
    block 4  the inner digest       length 0x2a0 = 672 bits      outer

which is HMAC by construction.  The expansion array at 0x6ffff8bc is
masked with 0x55f3fdec and satisfies
``w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)`` under it for 61 of the
64 expansions (the last three are overwritten before the snapshot).
``mac`` below reproduces ``ekey[0x24:0x38]`` on all eight handshakes in
``VECTORS`` -- 1001, 4242, 7, 13, 99, 555, 2024 and 12345 -- byte for
byte.

THE WRAP -- SOLVED.  ``ekey[0x38:0x48]`` is **AES-128 with Apple's own
tables**: AES's key schedule, AES's ShiftRows, AES's MixColumns matrix
over the Rijndael field, ten rounds, and not one of AES's S-boxes.

    wrap(key16, raw16) = the block cipher below, keyed by sap36[0:16]

It runs at ops 148,918..152,817 over the sixteen bytes at logical
0x40001ecc, and what it does there is

    state = raw16 ^ PLAINTEXT_XOR ^ K[0]
    for r in 0..8:
        state[p] = ROUND[r][p][ state[SHIFT_ROWS[p]] ]      substitute
        state[4c:4c+4] = MixColumns(COLUMN[state[4c:4c+4]]) ^ COLUMN_XOR
        state ^= K[r + 1]
    state[p] = LAST[p][ state[SHIFT_ROWS[p]] ] ^ K[10][p] ^ OUTPUT_XOR[p]

with ``K = key_schedule(sap36[0:16] ^ KEY_XOR)`` -- AES's own schedule,
AES's own round constants (01 02 04 08 10 20 40 80 1B 36), one SubWord
table per round key instead of one for all ten.

Every table is a permutation and every one of them is Apple's.  There
are sixty-three: ten for the key schedule, four per round for the nine
full rounds, sixteen for the tenth, and one folded into the four column
tables.  They live in a 19,968-byte block at 0x3352ef08, and they are
static rodata -- byte-identical in the entry image, before the run and
after it, on every seed.  Under ``T(x) = R[x ^ d] ^ e`` all sixty-three
collapse into **three** classes, which is what ``fply_wrap_tables``
ships: three 256-byte tables and a (class, in-xor, out-xor) triple per
use, 1.7 KB in total.

The column step is the prettiest part.  The four 1,024-byte tables are
not linear, which is what made this look unlike MixColumns at first;
subtract each one's four-byte offset and what is left IS MixColumns --
``columns[lane][x] = rotate_right([2q, q, q, 3q], lane) ^ offset[lane]``
for ``q = COLUMN[x]``, and rotating ``[2, 1, 1, 3]`` by the lane is
exactly AES's circulant.  So the tables carry one more substitution and
one more constant than AES does, and nothing else.  Only the XOR of the
four offsets can reach the answer, since every column step XORs all four
in; that XOR is ``COLUMN_XOR``, 4a4a4a4a.

None of this was guessed.  ``extract_wrap_tables`` reads the program off
a traced run with the same ``spn.recover_program`` that read Region B's
network, finds the ten SubWord tables as the last ten runs of four
consecutive lookups before the network starts, derives the column lanes
from the traced state with ``spn.mix_lanes``, and refuses to write the
file unless the column tables really are MixColumns on all 1,024 inputs
and the result reproduces the traced ekey.

Two earlier readings were wrong and are worth recording.  It is not
stock AES: neither AES's S-box nor its inverse is anywhere in the image
under any single-byte mask, and no 176-byte AES-128 key schedule is
either -- because the schedule uses ten different S-boxes and none of
them is AES's.  And Region C touches none of ``fply_tables``' addresses
-- 0 accesses in 239,294 ops, counted -- because this is a second copy
of the network with its own table set, in a different constant region.

WHAT ELSE IS IN THE SEVEN WINDOWS.  From the dispatch trace (6,667
indirect dispatches, 260 distinct handler entries) and the loop counts:

    op       0..  11,500   two modified-MD5 compressions
    op  11,900..  23,600   a 256-step byte loop, then a 10/36/16 triple
    op  23,600..  67,600   16 blocks, 2,743 ops each, walking the context
                           backwards -- straight-line, no dispatch
    op  67,600.. 116,000   a second 256-step loop, then four passes of
                           (227, 396) over a 2,560-byte table region
    op 116,300.. 141,000   raw16 enters; the four HMAC-SHA-1 compressions
    op 143,000.. 152,800   the SPN: key schedule, then the 31 passes
    op 152,800.. 164,300   two more modified-MD5 compressions, over a
                           48-byte message that is ASCII-salted:
                           "3498vyregm9i314n" || 16 bytes ||
                           "lvq34n9p30;sce;," -- both salts are built at
                           runtime, neither is in the image
    op 164,700.. 233,100   the context re-encrypted (the mirror of
                           23,600..67,600, forwards this time)
    op 233,100.. 239,294   a last 256-step loop and the 72-byte assembly

So of the seven windows: 0-3 and most of 4 are the context decryption,
which a sender does not need at all -- Region A already has the secret;
the MAC and the wrap are windows 4-5, and both are closed here; windows
5-6 are the context write-back and the assembly, of which only the
ekey's constant header survives.

WHAT THIS WAS CHECKED ON.  Sixteen SAP secrets and sixteen plaintexts
that no handshake produces (all zeros, all ones, one bit set,
structured, and random ones), pushed through the real engine with
``opexec.handshake_with_sap``; the eight frozen ``VECTORS``; and eight
further seeds -- 31337, 8, 424242, 65535, 111, 90210, 2718, 1618 -- run
end to end through ``opexec.run_handshake``.  Thirty-two agreements, all
72 bytes each.  The chosen inputs are the ones that matter: the
generated port constant-folds loads whose value it happened to know, so
a rule fitted to handshakes that agree by accident reproduces them and
nothing else.  ``test_ekey_wrap``'s slow tier re-runs a sample of both.

Run: uv run --with capstone python -m pytest \\
         examples/mirror_pyfply/devirt/test_ekey_wrap.py -v
     ... --runslow      to also re-derive the tables from a live trace
                        and re-check chosen inputs against the engine
"""

import hashlib
import hmac

from .fply_wrap_tables import (
    COLUMN,
    COLUMN_XOR,
    KEY_SBOXES,
    KEY_XOR,
    LAST,
    OUTPUT_XOR,
    PLAINTEXT_XOR,
    RCON,
    ROUNDS,
    SUBSTITUTIONS,
)

__all__ = [
    "HEADER",
    "ekey",
    "mac",
    "assemble",
    "split",
    "mac_key",
    "wrap",
    "key_schedule",
    "SHIFT_ROWS",
    "MAC_KEY_MASK",
    "MAC_AT",
    "WRAP_AT",
    "LIVE_CONTEXT",
    "DEAD_CONTEXT",
    "VECTORS",
]

# The ekey's constant 36 bytes: "FPLY" 01 02 01, a zero, the remaining
# length 0x3c big-endian, a 16-byte constant, then the wrapped-key
# length 0x10.  Identical on every handshake -- test_characterization
# proves it and every vector below repeats it.
HEADER = bytes.fromhex(
    "46504c59010201000000003c00000000" + "99ef4c8b1d98dadd67c71a3c76a68da600000010"
)

# where the two session-dependent fields sit in the 72-byte ekey
MAC_AT = slice(0x24, 0x38)  # the 20-byte HMAC-SHA1
WRAP_AT = slice(0x38, 0x48)  # the 16-byte wrapped secret

# FPLY's usual byte mask, the one `fply_md5.SECRET_MASK` also applies
MAC_KEY_MASK = 0x0D

# of the 276-byte FairPlay context, what Region C reads at all
LIVE_CONTEXT = (
    (0, 16, "gate"),
    (16, 48, "the encrypted SAP secret"),
    (256, 273, "gate"),
)
DEAD_CONTEXT = ((48, 256), (273, 276))


def mac_key(sap36: bytes) -> bytes:
    """The HMAC key: the SAP secret's 20-byte tail under the 0x0d mask."""
    if len(sap36) != 36:
        raise ValueError(f"sap36 must be 36 bytes, got {len(sap36)}")
    return bytes(byte ^ MAC_KEY_MASK for byte in sap36[16:36])


def mac(sap36: bytes, raw16: bytes) -> bytes:
    """``ekey[0x24:0x38]`` -- the 20-byte tag, in closed form.

    Stock HMAC-SHA-1 over the ekey's header followed by the PLAINTEXT
    secret, keyed by ``sap36[16:36] ^ 0x0d``.  Note what the message is
    not: it is not the ekey as it goes on the wire, because the wrapped
    key has not been substituted in yet.
    """
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    return hmac.new(mac_key(sap36), HEADER + bytes(raw16), hashlib.sha1).digest()


# ---------------------------------------------------------------------------
# The wrap: AES-128 with Apple's tables
# ---------------------------------------------------------------------------

# AES's row permutation: byte 4c+r is fed from 4*((c + r) % 4)+r.  The
# tenth round uses it too, as AES does.
SHIFT_ROWS = [4 * ((c + r) % 4) + r for c in range(4) for r in range(4)]


def _expand(use):
    """One use of a substitution class, as a plain 256-byte table."""
    table, in_xor, out_xor = use
    return bytes(SUBSTITUTIONS[table][x ^ in_xor] ^ out_xor for x in range(256))


_ROUND_TABLES = [[_expand(use) for use in row] for row in ROUNDS]
_LAST_TABLES = [_expand(use) for use in LAST]
_KEY_TABLES = [_expand(use) for use in KEY_SBOXES]
_COLUMN_TABLE = _expand(COLUMN)
# x -> 2x in GF(2^8) mod the Rijndael polynomial, precomputed
_XTIME = bytes(((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1 for x in range(256))


def key_schedule(key16: bytes) -> list:
    """The eleven round keys -- AES's schedule with ten SubWord tables.

    ``w[i] = w[i-4] ^ w[i-1]``, except that every fourth word first
    goes through RotWord, then that round's own S-box, then AES's own
    round constant.  Which is AES exactly, apart from there being ten
    S-boxes where AES has one.
    """
    if len(key16) != 16:
        raise ValueError(f"key16 must be 16 bytes, got {len(key16)}")
    words = [list(key16[4 * i : 4 * i + 4]) for i in range(4)]
    for index in range(4, 44):
        word = list(words[index - 1])
        if index % 4 == 0:
            sbox = _KEY_TABLES[index // 4 - 1]
            word = [sbox[byte] for byte in word[1:] + word[:1]]
            word[0] ^= RCON[index // 4 - 1]
        words.append([a ^ b for a, b in zip(words[index - 4], word)])
    return [
        bytes(byte for word in words[4 * r : 4 * r + 4] for byte in word)
        for r in range(11)
    ]


def _mix_columns(state):
    """AES MixColumns over one more substitution, plus a constant."""
    for column in range(4):
        at = 4 * column
        q = [_COLUMN_TABLE[byte] for byte in state[at : at + 4]]
        for row in range(4):
            state[at + row] = (
                _XTIME[q[row]]
                ^ _XTIME[q[(row + 1) % 4]]
                ^ q[(row + 1) % 4]
                ^ q[(row + 2) % 4]
                ^ q[(row + 3) % 4]
                ^ COLUMN_XOR[row]
            )


def wrap(key16: bytes, raw16: bytes) -> bytes:
    """``ekey[0x38:0x48]`` -- the wrapped secret, in closed form.

    Ten rounds keyed by ``sap36[0:16]``; see the module docstring for
    what each constant is and how it was measured.
    """
    if len(key16) != 16:
        raise ValueError(f"key16 must be 16 bytes, got {len(key16)}")
    if len(raw16) != 16:
        raise ValueError(f"raw16 must be 16 bytes, got {len(raw16)}")
    keys = key_schedule(bytes(a ^ b for a, b in zip(key16, KEY_XOR)))
    state = bytearray(a ^ b ^ c for a, b, c in zip(raw16, PLAINTEXT_XOR, keys[0]))
    for index, tables in enumerate(_ROUND_TABLES):
        state = bytearray(tables[p][state[SHIFT_ROWS[p]]] for p in range(16))
        _mix_columns(state)
        state = bytearray(a ^ b for a, b in zip(state, keys[index + 1]))
    return bytes(
        _LAST_TABLES[p][state[SHIFT_ROWS[p]]] ^ keys[10][p] ^ OUTPUT_XOR[p]
        for p in range(16)
    )


def ekey(sap36: bytes, raw16: bytes) -> bytes:
    """The whole 72-byte ekey, from the SAP secret and the secret to wrap.

    This is Region C: 239,294 interpreted ops, or the three lines below.
    """
    return assemble(sap36, raw16, wrap(sap36[:16], raw16))


def assemble(sap36: bytes, raw16: bytes, wrapped16: bytes) -> bytes:
    """The 72-byte ekey, given its wrapped key from anywhere."""
    if len(wrapped16) != 16:
        raise ValueError(f"wrapped16 must be 16 bytes, got {len(wrapped16)}")
    return HEADER + mac(sap36, raw16) + bytes(wrapped16)


def split(blob: bytes) -> tuple:
    """``(header, mac, wrapped)`` for a 72-byte ekey."""
    if len(blob) != 72:
        raise ValueError(f"ekey must be 72 bytes, got {len(blob)}")
    return blob[:0x24], blob[MAC_AT], blob[WRAP_AT]


# (seed, sap36, raw16, ekey) for the eight handshakes the recovery was
# checked on.  `sap36` is `oracle.golden_vectors(...)["ctx_m3"][8:44]`,
# i.e. Region A's output for that seed's M2; `test_ekey_wrap` re-derives
# every one of them from the emulator in its slow tier, so this table
# cannot drift away from the oracle without saying so.
VECTORS = (
    (
        1001,
        "ae5be6678a6299aeb69466f6cf05e2eacaa08e7523ebe004eef65bb8cac1ee4d4f234edb",
        "657e13ec31113c7e8d3e06b78ac8d8b3",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000108dc89d389acad02decab206ad37c459bb2f1fb163e5745ce9603adbc"
        "41a73a2aef6f99de",
    ),
    (
        4242,
        "5a01e21c10f331c8a9b048034f8b46706191d7436082717471f2eb531b307acda61e10fc",
        "84a2db3ca97517dd27d544b0efd9d591",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000103ec7fd9073a8f26ec0541bc811da9e33b5861a1cc4af28014511ff16"
        "7ff26c8215e5d66d",
    ),
    (
        7,
        "31b51ed24fa228ba5d6550479dfc6d2d68220d173ad7f0d33f5fb9c7c948a2108f5d8e81",
        "b5769fa0f1483f95a90d9df2f130d60f",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "0000001041c28f61682ec7f1a490986b0e87d19282955a5b2eac417bd2308144"
        "553d3a4b9ff77399",
    ),
    (
        13,
        "e4b1e34a7b963be77bfaef8b1594556b155fd7fcf4eeb80088ab503bfd678d06ad506b5f",
        "4bd7b103ca9e33fe783e9d4625069ad5",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010ba30205fc2d6cb0e3433e87bcd0e087258df013934ff2ef7baaf2e22"
        "aa11792d5c377a4f",
    ),
    (
        99,
        "2c8869e79ae2f78165aed22404fc4c86c06091b9738427e935878035472b268a123516f9",
        "414c5b63bbc08adc05b9afaecd5a6c36",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010d48c1fc8533c2854aaac1524135070ded806fcc1632bebc35563583f"
        "e5ce2669e672564f",
    ),
    (
        555,
        "82286edb1700bb41c5517f4abaa7d372d3640946f775c92d0b933ee935a11c0f6ee3314a",
        "4cb97c534eabe0987f1c8298c2801dcd",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "000000104c581182585f90affecd715d3fef7a9f4907cbd1f7743b8ebf3be767"
        "92a6064850d4ecc5",
    ),
    (
        2024,
        "73aaa5bb9b0d53363ff366ec702f4708f4f3978cb70ab1a1531f43c18ccb8573d9d8b843",
        "066a3abb775f3dc611ece9ffa47ffadd",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010a84839741ea82583c92aca836697d7b34bf3931c7b7a5df2cd482983"
        "8022cbd044922d43",
    ),
    (
        12345,
        "2e62cf7e090d45e7d7240384bf02958df204b931a7425a3da5097cc2523ff2aa4be59f19",
        "922688fa428d42bc1fa8806998fbc595",
        "46504c59010201000000003c0000000099ef4c8b1d98dadd67c71a3c76a68da6"
        "00000010819cba16229269ed446261f933d752fdcf44d3a23965b0856de375a2"
        "1c688e712ca2b7ce",
    ),
)
