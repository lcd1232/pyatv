"""FPLY wire layout against a captured (M1, M2, M3, M4) handshake.

The bytes come from a live mirroring session between a third-party sender
and an Apple TV; they are protocol data, embedded as constants.  pyatv does
not reproduce this capture's M3 -- the sender's session block and device
tag came from its own randomness, while pyatv's FairPlay path is
deterministic -- but it must parse M2 and lay out M3 exactly as the wire
does.  Known-answer tests for pyatv's own values live in
``test_fairplay_sap.py``.
"""

from __future__ import annotations

from pyatv.protocols.airplay.mirror import fply

# A mode 0x01 handshake
_CAP_M2_P1 = bytes.fromhex(
    "46504c5903010200000000820201babd9d6f2ad3b8d49dae581f259bf47cd3"
    "2c31570738f2f15371952eac7620f1b8c6f8f42485b3aaf01c4a1d6c04e6faf"
    "92b7c59878ea1b8a2a38711debfa6e54d4209da1d5088d32d60331581a8fce1"
    "7c9b337de8cdf8e8ffc796a374f41773f95d7dae1a1174de3b72d7611cf5c66"
    "511d645aebe886f517fd30472e169733c"
)
_CAP_M3_P1 = bytes.fromhex(
    "46504c590301030000000098018f1a9c7b977b6e2324dd777934af944a4e07"
    "2d544f4124957876cd7ad08301568bb4fafabf8f3e2ddee645358e5503d81a2"
    "89881faf760c01e9c95a206cab2530720e7d4d1971c2dfa178ed05c23d47469"
    "e9e894786e08b43624d02322814fba5196a608a4532c3b808f2c50bb36e436a"
    "03d408af40a0fdc15c45c5ee423df23985e4817a6c457904703389305d02aa8"
    "196102934e8a08"
)


# Where the fields sit in the capture.
_M2_CIPHER_INPUT_P1 = _CAP_M2_P1[14:142]  # 128 bytes
_M3_AUX_HEADER_P1 = _CAP_M3_P1[13:16]  # 3 bytes (8f 1a 9c)
_M3_CIPHER_OUTPUT_P1 = _CAP_M3_P1[16:144]  # 128 bytes ground truth
_M3_DEVICE_TAG_P1 = _CAP_M3_P1[144:164]  # 20 bytes


def test_parse_m2_against_capture():
    """parse_m2 must extract the 128-byte cipher input region from M2[14:142]."""
    parsed = fply.parse_m2(_CAP_M2_P1)
    assert parsed.mode == 0x01
    assert len(parsed.payload) == 128
    assert parsed.payload == _M2_CIPHER_INPUT_P1


def test_build_m3_layout_matches_capture_with_known_pieces():
    """Assembling M3 from known cipher output, aux header, and device tag
    reproduces the captured M3 byte-for-byte.

    Validates the M3 layout (mode at 12, aux header at 13:16, cipher
    output at 16:144, device tag at 144:164) regardless of whether we can
    *generate* the cipher output ourselves yet.
    """
    rebuilt = fply.build_m3(
        mode=0x01,
        cipher_payload=_M3_CIPHER_OUTPUT_P1,
        device_tag=_M3_DEVICE_TAG_P1,
        aux_header=_M3_AUX_HEADER_P1,
    )
    assert rebuilt == _CAP_M3_P1


# ---------------------------------------------------------------------------
# What pyatv sends against what the reference sender sent
# ---------------------------------------------------------------------------


def test_pyatv_agrees_with_the_capture_on_everything_but_the_session():
    """Same framing, same aux header, different session material.

    pyatv's session block is the constant :data:`fply.M3_CIPHER_BLOCK` (the
    sender randomness is pinned), the reference sender's was random, so M3[16:144] and
    the device tag after it differ by construction.  Everything the wire
    format fixes must still agree.
    """
    ours = fply.build_m3(
        mode=0x01,
        device_tag=bytes(20),
        aux_header=_M3_AUX_HEADER_P1,
    )
    assert len(ours) == len(_CAP_M3_P1) == 164
    assert ours[:16] == _CAP_M3_P1[:16]  # header, mode, aux
    assert ours[16:144] != _CAP_M3_P1[16:144]  # session material
