"""Ground-truth FPLY tests against captured (M1, M2, M3, M4) bytes.

Capture provenance: a live mirroring session of the reference sender against an Apple TV
the pyatv project was tested with. Bytes are functional protocol data, not source code,
so they may be embedded as constants.

Four independent (M1, M2, M3, M4) pairs captured from the same client/server
combination, exercising mode=1, 2, 3, 3:

* pair 1: mode 0x01
* pair 2: mode 0x02
* pair 3: mode 0x03
* pair 4: mode 0x03 (different session, fully independent random material)

Empirical observations (Phase 12 analysis, /tmp/fply_phase12.md):

* M3[13:16] = ``8f 1a 9c`` is constant across all four pairs (literal aux
  header emitted by the sender, not derived from M2).
* M3[144:164] echoes verbatim into M4[12:32] for every pair (server-verified
  20-byte device tag).
* Pairs 3 and 4 are both mode 3 yet differ in 127/128 bytes of M2 cipher
  input — the server returns session-randomised material.
* Across all four pairs, no byte of M3[16:144] is stable, and no byte
  position i has ``M2[14+i] == M3[16+i]`` — confirms full cipher avalanche
  with no cleartext passthrough.

These tests pin the empirical M2 and M3 wire layouts: offsets, header
bytes, and where the session block and the device tag actually live.

They do NOT expect pyatv to reproduce this capture's M3.  The reference sender's
session block and device tag are functions of ITS ``arc4random``, and
pyatv's FairPlay path (``fairplay_sap``, recovered from the emulator that
pinned that randomness to zero) is deterministic: it sends its own
constant block and the tag that goes with it, and the receiver derives the
session from the block it is sent.  Both are accepted.  The known-answer
tests for pyatv's own values live in ``test_fairplay_sap.py``.
"""

from __future__ import annotations

from pyatv.protocols.airplay.mirror import fply

# ---------------------------------------------------------------------------
# Captured handshake bytes (see /tmp/airplay_capture/{M1,M2,M3,M4}_p[1-4].bin)
# ---------------------------------------------------------------------------

# Pair 1 — mode 0x01
_CAP_M1_P1 = bytes.fromhex("46504c590301010000000004020001bb")
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
_CAP_M4_P1 = bytes.fromhex(
    "46504c59030104000000001417a6c457904703389305d02aa8196102934e8a08"
)


def _read_capture(name: str) -> bytes:
    """Load a captured byte file from /tmp/airplay_capture if present."""
    from pathlib import Path

    p = Path("/tmp/airplay_capture") / name
    if p.is_file():
        return p.read_bytes()
    return b""


# Pairs 2..4 are loaded lazily from /tmp/airplay_capture/.  When the
# capture directory is missing (CI / fresh checkout) the multi-pair tests
# skip rather than fail.
_PAIRS_DEFS: tuple[tuple[int, str, str, str, str], ...] = (
    (1, "M1_p1.bin", "M2_p1.bin", "M3_p1.bin", "M4_p1.bin"),
    (2, "M1_p2.bin", "M2_p2.bin", "M3_p2.bin", "M4_p2.bin"),
    (3, "M1_p3.bin", "M2_p3.bin", "M3_p3.bin", "M4_p3.bin"),
    (4, "M1_p4.bin", "M2_p4.bin", "M3_p4.bin", "M4_p4.bin"),
)


def _all_pairs() -> list[tuple[int, bytes, bytes, bytes, bytes]]:
    out: list[tuple[int, bytes, bytes, bytes, bytes]] = []
    for n, m1f, m2f, m3f, m4f in _PAIRS_DEFS:
        m1 = _read_capture(m1f)
        m2 = _read_capture(m2f)
        m3 = _read_capture(m3f)
        m4 = _read_capture(m4f)
        if m1 and m2 and m3 and m4:
            out.append((n, m1, m2, m3, m4))
    # Always include pair 1 from inline constants as a fall-back so the
    # match-score test runs even when /tmp/airplay_capture is absent.
    if not any(p[0] == 1 for p in out):
        out.append((1, _CAP_M1_P1, _CAP_M2_P1, _CAP_M3_P1, _CAP_M4_P1))
    return out


# Empirically derived offsets within pair 1 (used by layout tests).
_M2_CIPHER_INPUT_P1 = _CAP_M2_P1[14:142]  # 128 bytes
_M3_AUX_HEADER_P1 = _CAP_M3_P1[13:16]  # 3 bytes (8f 1a 9c)
_M3_CIPHER_OUTPUT_P1 = _CAP_M3_P1[16:144]  # 128 bytes ground truth
_M3_DEVICE_TAG_P1 = _CAP_M3_P1[144:164]  # 20 bytes


# ---------------------------------------------------------------------------
# Single-pair (pair 1) layout tests — exercised in CI without external files.
# ---------------------------------------------------------------------------


def test_capture_lengths():
    """Captured messages match documented wire sizes."""
    assert len(_CAP_M1_P1) == 16
    assert len(_CAP_M2_P1) == 142
    assert len(_CAP_M3_P1) == 164
    assert len(_CAP_M4_P1) == 32


def test_capture_m4_echoes_m3_device_tag():
    """The 20 trailing bytes of M3 (device tag) appear verbatim at end of M4.

    First clue that M3[144:164] is a 20-byte server-verifiable tag rather
    than part of the cipher output region.
    """
    assert _CAP_M3_P1[-20:] == _CAP_M4_P1[-20:]
    assert _CAP_M3_P1[-20:] == _M3_DEVICE_TAG_P1


def test_capture_mode_echoes():
    """Mode byte propagates through M1, M2, M3 (M4 has no mode field)."""
    assert _CAP_M1_P1[14] == 0x01
    assert _CAP_M2_P1[13] == 0x01
    assert _CAP_M3_P1[12] == 0x01
    # M4 body length is 0x14 (20 bytes — just the device-tag echo).
    assert _CAP_M4_P1[8:12] == b"\x00\x00\x00\x14"


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
# Multi-pair invariants (Phase 12 findings)
# ---------------------------------------------------------------------------


def test_aux_header_constant_across_pairs():
    """M3[13:16] = ``8f 1a 9c`` across every captured pair.

    Confirms the aux header is a literal sender-emitted constant, not a
    cipher-derived field.
    """
    pairs = _all_pairs()
    for _, _, _, m3, _ in pairs:
        assert m3[13:16] == b"\x8f\x1a\x9c"


def test_m4_echoes_device_tag_across_pairs():
    """M3[-20:] == M4[-20:] for every captured pair."""
    for _, _, _, m3, m4 in _all_pairs():
        assert m3[-20:] == m4[-20:]


def test_m2_is_session_random_in_same_mode():
    """Two mode-0x03 captures (pairs 3 and 4) differ in nearly every M2 byte.

    Confirms the server randomises M2 even for identical mode requests,
    so the sender's M3 must depend on M2 contents (cipher) rather than
    being a static reply.
    """
    by_n = {n: m2 for n, _, m2, _, _ in _all_pairs()}
    if 3 not in by_n or 4 not in by_n:
        # Multi-pair captures not available (e.g. fresh checkout);
        # the single-pair tests still cover the layout invariants.
        import pytest

        pytest.skip("pair 3/4 captures not present")
    p3 = by_n[3][14:142]
    p4 = by_n[4][14:142]
    differing = sum(1 for a, b in zip(p3, p4) if a != b)
    assert differing >= 100, (
        f"expected M2 cipher input to be heavily session-random, only "
        f"{differing}/128 bytes differed between two mode-3 captures"
    )


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
