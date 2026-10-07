"""Golden-vector tests for :mod:`pyatv.protocols.airplay.mirror.fairplay_sap`.

``fply_pure_golden.jsonl`` holds 256 recorded FairPlay handshakes: for each,
the M2 that went in and the M3, M4, chosen raw16, ekey and first 44 bytes of
the FairPlay context that came out.  Every byte of M3 and the ekey must match.
"""

from __future__ import annotations

import json
import pathlib

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
    """:data:`fply.M3_CIPHER_BLOCK` and the aux header match the recording."""
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

    The parts must concatenate back to the ekey, agree with the
    :data:`~ekey_wrap.MAC_AT` and :data:`~ekey_wrap.WRAP_AT` slices, and match
    what :func:`ekey_wrap.mac` and :func:`ekey_wrap.assemble` derive.
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


# Length guards: the algorithms index fixed-size buffers, so a wrong-length
# input must raise a clear ValueError rather than an IndexError deep inside.

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
    """`load` tiles the block, so only a block shorter than 64 bytes is an error."""
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


def test_the_constants_duplicated_across_recovered_modules_still_agree():
    """Constants defined in more than one module must keep the same value.

    ``SAP_LENGTH``, the AES ``RCON`` table and the 32-bit mask each appear in
    several self-contained modules; a disagreement would corrupt the tag or
    the ekey.
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
    """Each length guard's message names the argument that was wrong."""
    with pytest.raises(ValueError, match=expected):
        call()
