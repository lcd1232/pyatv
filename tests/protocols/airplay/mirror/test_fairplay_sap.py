"""The recovered FairPlay handshake against the emulator that produced it.

``fply_pure_golden.jsonl`` is 256 handshakes recorded from the Unicorn
emulation of AirParrot's own FairPlay code, before that code was read out
as algorithms: for each one the M2 that went in and the M3, the M4, the
chosen raw16, the ekey and the first 44 bytes of the FairPlay context that
came out.  pyatv no longer ships that emulator (it lives in
``examples/mirror_pyfply/`` with the devirtualisation tooling), so these
rows are what stands between
:mod:`pyatv.protocols.airplay.mirror.fairplay_sap` and a silent
regression: every byte of M3 and of the ekey has to still come out the
same.
"""

from __future__ import annotations

import importlib
import importlib.abc
import json
import pathlib
import sys

import pytest

from pyatv.protocols.airplay.mirror import fairplay_sap, fply
from pyatv.protocols.airplay.mirror.fairplay_sap import (
    ekey_wrap,
    fply_md5,
    m4_derive,
    region_b,
    saphash,
    saphash_fold,
)

_GOLDEN = pathlib.Path(__file__).parent / "fply_pure_golden.jsonl"


def _vectors() -> list:
    with _GOLDEN.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


VECTORS = _vectors()


def test_golden_file_is_the_recorded_emulator_run():
    """256 handshakes, with the field widths the wire has."""
    assert len(VECTORS) == 256
    for v in VECTORS:
        assert len(bytes.fromhex(v["m2"])) == 142
        assert len(bytes.fromhex(v["m3"])) == 164
        assert len(bytes.fromhex(v["m4"])) == 32
        assert len(bytes.fromhex(v["raw16"])) == 16
        assert len(bytes.fromhex(v["ekey"])) == 72


def test_every_recorded_m3_is_reproduced_exactly():
    """M3, all 164 bytes, for all 256 recorded handshakes."""
    for v in VECTORS:
        handshake = fply.FPLYHandshake(mode_byte=1)
        handshake.build_m1()
        assert handshake.consume_m2_build_m3(bytes.fromhex(v["m2"])).hex() == v["m3"]


def test_every_recorded_ekey_is_reproduced_exactly():
    """The 72-byte ekey, from the same M2 and the raw16 that was wrapped."""
    for v in VECTORS:
        handshake = fply.FPLYHandshake(mode_byte=1)
        handshake.build_m1()
        handshake.consume_m2_build_m3(bytes.fromhex(v["m2"]))
        ekey = handshake.finish_ekey(bytes.fromhex(v["m4"]), bytes.fromhex(v["raw16"]))
        assert ekey.hex() == v["ekey"]
        assert handshake.ekey == ekey
        assert handshake.chosen_raw16 == bytes.fromhex(v["raw16"])


def test_device_tag_varies_with_m2_and_nothing_else_in_m3_does():
    """M3[0:144] is the same in every session; M3[144:164] is not."""
    tags = {bytes.fromhex(v["m3"])[144:164] for v in VECTORS}
    heads = {bytes.fromhex(v["m3"])[:144] for v in VECTORS}
    assert len(tags) == len(VECTORS)
    assert len(heads) == 1
    assert heads.pop() == bytes.fromhex(VECTORS[0]["m3"])[:144]


def test_the_shipped_m3_constants_are_the_recorded_ones():
    """:data:`fply.M3_CIPHER_BLOCK` and the aux header come from the capture."""
    m3 = bytes.fromhex(VECTORS[0]["m3"])
    assert m3[16:144] == fply.M3_CIPHER_BLOCK
    assert m3[13:16] == fply.M3_AUX_HEADER


def test_sap_secret_is_the_recorded_context_at_8_44():
    """The SAP secret sits at ctx[8:44], which is what session.py reads."""
    for v in VECTORS:
        sap36 = fairplay_sap.sap_secret(bytes.fromhex(v["m2"]))
        recorded = bytes.fromhex(v["ctx_m3"])
        assert len(sap36) == 36
        assert sap36 == recorded[8:44]
        assert fairplay_sap.context_after_m3(sap36)[:44] == recorded


def test_handshake_helper_agrees_with_the_state_machine():
    """:func:`fairplay_sap.handshake` is the same four answers in one call."""
    for v in VECTORS[:8]:
        m2, raw16 = bytes.fromhex(v["m2"]), bytes.fromhex(v["raw16"])
        sap36, tag, context, ekey = fairplay_sap.handshake(m2, raw16)
        assert sap36 == fairplay_sap.sap_secret(m2)
        assert tag == bytes.fromhex(v["m3"])[144:164]
        assert ekey.hex() == v["ekey"]
        # the post-M4 context is the post-M3 one encrypted -- 276 bytes
        # either way, and only the state byte and the secret differ going in
        assert len(context) == 276
        assert context != fairplay_sap.context_after_m3(sap36)


def test_a_different_raw16_wraps_to_a_different_ekey_tail():
    """Only the last 36 bytes of the ekey carry the session."""
    v = VECTORS[0]
    sap36 = fairplay_sap.sap_secret(bytes.fromhex(v["m2"]))
    first = fairplay_sap.ekey(sap36, b"\x00" * 16)
    second = fairplay_sap.ekey(sap36, b"\x01" * 16)
    assert first[:0x24] == second[:0x24]
    assert first[0x24:] != second[0x24:]


def test_split_takes_every_recorded_ekey_apart_where_the_fields_are():
    """:func:`ekey_wrap.split` on all 256 recorded ekeys.

    The three parts have to be the ekey again when concatenated (nothing
    dropped, nothing reordered), they have to be exactly what
    :data:`~ekey_wrap.MAC_AT` and :data:`~ekey_wrap.WRAP_AT` name -- those
    slices are what a receiver indexes with, so a `split` that disagreed
    with them would be the more dangerous half of the pair -- and the two
    session-dependent fields have to be the ones the algorithm derives:
    the tag is :func:`ekey_wrap.mac` of that handshake's secret, and the
    wrapped key puts the ekey back together through
    :func:`ekey_wrap.assemble`.
    """
    for v in VECTORS:
        raw = bytes.fromhex(v["ekey"])
        sap36 = bytes.fromhex(v["ctx_m3"])[8:44]
        raw16 = bytes.fromhex(v["raw16"])

        header, tag, wrapped = ekey_wrap.split(raw)

        assert header + tag + wrapped == raw
        assert (len(header), len(tag), len(wrapped)) == (0x24, 20, 16)
        assert header == raw[:0x24] == ekey_wrap.HEADER
        assert tag == raw[ekey_wrap.MAC_AT] == ekey_wrap.mac(sap36, raw16)
        assert wrapped == raw[ekey_wrap.WRAP_AT]
        assert ekey_wrap.assemble(sap36, raw16, wrapped) == raw


def test_split_rejects_anything_that_is_not_a_72_byte_ekey():
    """The guard, from both sides: one byte short and one byte long."""
    good = bytes.fromhex(VECTORS[0]["ekey"])
    ekey_wrap.split(good)
    for bad in (good[:71], good + b"\x00", b""):
        with pytest.raises(ValueError):
            ekey_wrap.split(bad)


def test_ekey_rejects_a_wrong_length_secret():
    sap36 = fairplay_sap.sap_secret(bytes.fromhex(VECTORS[0]["m2"]))
    with pytest.raises(ValueError):
        fairplay_sap.ekey(sap36, b"\x00" * 15)


def test_nothing_here_needs_the_emulator():
    """The whole point: no unicorn, no blobs."""
    fairplay_sap.handshake(bytes.fromhex(VECTORS[0]["m2"]), b"\x02" * 16)
    assert "unicorn" not in sys.modules


class _Unavailable(importlib.abc.MetaPathFinder):
    """An import of *names*, or of anything under them, fails outright.

    What an installed pyatv looks like.  ``unicorn`` is a dev dependency and
    ``devirt`` lives in ``examples/``, which is not packaged -- but both are
    importable in this checkout, so a shipped module that reached for one
    would pass the suite here and raise :class:`ImportError` on a user's
    machine.  Making them genuinely absent is the only way to see it.
    """

    def __init__(self, *names):
        self.names = names

    def find_spec(self, fullname, path=None, target=None):
        """Refuse *fullname* if it is one of ours; fall through if not.

        Falling through is returning ``None``, which is what the finder
        protocol asks for and what this does implicitly.
        """
        if fullname.split(".")[0] in self.names:
            raise ImportError(f"no module named {fullname!r}")


def test_the_whole_handshake_runs_with_the_harness_unavailable():
    """All 256, on a package imported with unicorn and devirt made absent.

    The package is dropped from ``sys.modules`` and imported again inside
    the blocker, so a top-level import is caught as well as a deferred one
    -- and put back afterwards, so the rest of the suite keeps the module
    objects it already holds.
    """
    package = "pyatv.protocols.airplay.mirror.fairplay_sap"
    loaded = {
        name: module
        for name, module in sys.modules.items()
        if name == package or name.startswith(package + ".")
    }
    blocker = _Unavailable("unicorn", "devirt")
    for name in loaded:
        del sys.modules[name]
    sys.meta_path.insert(0, blocker)
    try:
        fresh = importlib.import_module(package)
        for v in VECTORS:
            sap36, tag, _, ekey = fresh.handshake(
                bytes.fromhex(v["m2"]), bytes.fromhex(v["raw16"])
            )
            assert sap36.hex() == v["ctx_m3"][16:88]
            assert tag == bytes.fromhex(v["m3"])[144:164]
            assert ekey.hex() == v["ekey"]
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(loaded)
    assert "unicorn" not in sys.modules
    assert "devirt" not in sys.modules


# ---------------------------------------------------------------------------
# Length guards
#
# Every remaining uncovered statement in the package was one of these, and
# they are not decoration: `sap_secret` and everything downstream index into
# fixed-size buffers, so a short input reaches a generated port and comes back
# as `IndexError: index out of range` from the middle of recovered code.
# `fply.parse_m2` keeps that off the wire, but these are the guards that make
# the package safe to call directly.  A guard with the wrong comparison or a
# copy-pasted message passes silently today; this notices.
# ---------------------------------------------------------------------------

_GOOD = {36: bytes(36), 20: bytes(20), 16: bytes(16), 210: bytes(210), 64: bytes(64)}


@pytest.mark.parametrize(
    "call, wrong, want",
    [
        (lambda b: ekey_wrap.mac_key(b), 36, "36 bytes"),
        (lambda b: ekey_wrap.mac(b, _GOOD[16]), 36, "36 bytes"),
        (lambda b: ekey_wrap.mac(_GOOD[36], b), 16, "16 bytes"),
        (lambda b: ekey_wrap.key_schedule(b), 16, "16 bytes"),
        (lambda b: ekey_wrap.wrap(b, _GOOD[16]), 16, "16 bytes"),
        (lambda b: ekey_wrap.assemble(_GOOD[36], _GOOD[16], b), 16, "16 bytes"),
        (lambda b: m4_derive.expand_key(b), 16, "not 16"),
        (lambda b: m4_derive.context(b), 36, "not "),
        (lambda b: fply_md5.message_block(b, 0), 20, "20 bytes"),
        (lambda b: fply_md5.link(b), 16, "16 bytes"),
        (lambda b: saphash.scramble(b), 210, "bytes"),
        (lambda b: region_b.device_tag(b), 36, "not "),
    ],
)
def test_a_wrong_length_is_refused_with_its_own_message(call, wrong, want):
    for delta in (-1, +1):
        with pytest.raises(ValueError) as excinfo:
            call(bytes(wrong + delta))
        assert want in str(excinfo.value)
        assert str(wrong + delta) in str(excinfo.value)
    call(_GOOD[wrong])  # the same call succeeds at the right length


def test_load_refuses_a_short_block_but_accepts_a_long_one():
    """`load` guards with `<`, not `!=`, and that is deliberate.

    Its docstring says "tiled, not padded": buffer1 is filled by repeating
    the block, so anything at least BLOCK_SIZE long is usable and only a
    short one is an error.  Asserting `!=` here would pin a stricter
    contract than the function offers.
    """
    with pytest.raises(ValueError, match="need 64 bytes"):
        saphash.load(bytes(63))
    assert len(saphash.load(bytes(64))) == saphash.BUFFER_SIZE
    assert len(saphash.load(bytes(65))) == saphash.BUFFER_SIZE


def test_cbc_encrypt_refuses_a_partial_block():
    with pytest.raises(ValueError, match="whole blocks"):
        m4_derive.cbc_encrypt(bytes(17), _GOOD[16], _GOOD[16])
    m4_derive.cbc_encrypt(bytes(32), _GOOD[16], _GOOD[16])


def test_the_fold_refuses_a_buffer3_that_stops_short():
    with pytest.raises(ValueError, match="word 33"):
        saphash_fold.delta(bytes(20), bytes(210), bytes(35), bytes(132))


def test_context_after_m3_rejects_a_wrong_length_secret():
    """The SAP secret is a fixed 36 bytes; the error must name the length."""
    with pytest.raises(ValueError, match="sap36 must be 36 bytes"):
        fairplay_sap.context_after_m3(b"\x00" * 35)


def test_asr_sign_extends_from_the_top_bit():
    """``garble_read._asr`` is ARM's arithmetic shift, not Python's.

    Values with the top bit set must shift in ones. Only the ported FairPlay
    code calls this, and the golden handshakes happen never to reach it with a
    negative value, so this is the sole exercise of the sign-extension branch.
    """
    from pyatv.protocols.airplay.mirror.fairplay_sap.garble_read import _asr

    # Top bit set: shifting in ones, wrapped back to the field width.
    assert _asr(0x80, 1, 8) == 0xC0
    assert _asr(0xFF, 1, 8) == 0xFF
    assert _asr(0x80000000, 4, 32) == 0xF8000000
    # Top bit clear: an ordinary logical shift, for contrast.
    assert _asr(0x40, 1, 8) == 0x20
    assert _asr(0x7F, 1, 8) == 0x3F


def test_the_constants_duplicated_across_recovered_modules_still_agree():
    """Several constants are defined in more than one recovered module.

    ``region_a`` and ``region_b`` each define ``SAP_LENGTH``;
    ``fply_wrap_tables`` and ``m4_derive`` each define the AES ``RCON``
    table; three modules each define the 32-bit mask.  That is not
    sloppiness to be tidied away: these modules are generated from the
    devirtualisation sources by ``test_fairplay_sap_sync.py``'s ``port()``,
    and each is self-contained the way the routine it was recovered from is.
    Editing them by hand to share a definition would fail that sync test.

    So the duplication stays and this checks it stays *consistent*.  Nothing
    else would notice one copy being changed and the other not -- the two
    ``SAP_LENGTH``s in particular describe the same 36-byte SAP secret, and
    a disagreement would corrupt either the tag or the ekey depending on
    which module read its own copy.
    """
    from pyatv.protocols.airplay.mirror.fairplay_sap import (
        fply_md5,
        fply_wrap_tables,
        m4_derive,
        region_a,
        region_b,
        saphash_fold,
    )

    assert region_a.SAP_LENGTH == region_b.SAP_LENGTH == 36
    assert fply_wrap_tables.RCON == m4_derive.RCON
    assert len(set(fply_wrap_tables.RCON)) == len(fply_wrap_tables.RCON), "RCON repeats"
    assert region_a._M32 == saphash_fold._M32 == fply_md5._M32 == 0xFFFFFFFF


@pytest.mark.parametrize(
    "call,expected",
    [
        pytest.param(
            lambda: ekey_wrap.key_schedule(bytes(15)), "key16", id="key_schedule"
        ),
        pytest.param(lambda: ekey_wrap.wrap(bytes(15), bytes(16)), "key16", id="wrap"),
        pytest.param(
            lambda: ekey_wrap.assemble(bytes(36), bytes(16), bytes(15)),
            "wrapped16",
            id="assemble",
        ),
        pytest.param(lambda: ekey_wrap.split(bytes(71)), "ekey", id="split"),
        pytest.param(
            lambda: fply_md5.message_block(bytes(19), 0), "secret", id="message_block"
        ),
        pytest.param(lambda: fply_md5.link(bytes(15)), "16 bytes", id="link"),
        pytest.param(
            lambda: m4_derive.cbc_encrypt(bytes(17), bytes(16), bytes(16)),
            "whole blocks",
            id="cbc_encrypt",
        ),
    ],
)
def test_a_wrong_length_is_refused_by_name(call, expected):
    """Each length guard must say which argument was wrong.

    Every one of these raises already ran -- checked with coverage, with this
    test deselected -- so the ``NameError``-in-an-unevaluated-f-string failure
    that ``test_session_error_paths`` guards against does not apply here.
    What nothing checked was the *message*: the callers reached these guards
    through ``pytest.raises(ValueError)`` with no ``match``, so a guard naming
    the wrong argument would have passed.

    That is the whole claim, and it is worth having: renaming ``wrapped16`` to
    ``raw16`` in ``assemble``'s guard fails this and nothing else, which is
    exactly the mistake a copy-pasted validator makes.

    Nothing here checks the algorithms -- the 256 golden handshakes do that.
    This is only about what a caller sees when they pass the wrong shape.
    """
    with pytest.raises(ValueError, match=expected):
        call()
