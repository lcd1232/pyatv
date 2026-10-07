"""Tests for pyatv.protocols.airplay.mirror.pacer."""

from pathlib import Path

import pytest

from pyatv.protocols.airplay.mirror import pacer

TEST_FILE = Path(__file__).parent / "test_pattern.h264"


def test_split_nalus_three_byte_start_code():
    # [SPS][PPS] separated by 3-byte start codes
    data = b"\x00\x00\x01\x67\xaa" + b"\x00\x00\x01\x68\xbb"
    result = pacer.split_nalus(data)
    assert result == [b"\x67\xaa", b"\x68\xbb"]


def test_split_nalus_four_byte_start_code():
    data = b"\x00\x00\x00\x01\x67\xaa" + b"\x00\x00\x00\x01\x68\xbb"
    result = pacer.split_nalus(data)
    assert result == [b"\x67\xaa", b"\x68\xbb"]


def test_split_nalus_mixed_start_codes():
    data = b"\x00\x00\x00\x01\x67\xaa" + b"\x00\x00\x01\x68\xbb"
    result = pacer.split_nalus(data)
    assert result == [b"\x67\xaa", b"\x68\xbb"]


def test_split_nalus_empty():
    assert pacer.split_nalus(b"") == []


def test_split_nalus_no_start_code_returns_empty():
    assert pacer.split_nalus(b"\x67\xaa\xbb\xcc") == []


def test_nal_type_extraction():
    sps_nal = b"\x67\xaa"
    pps_nal = b"\x68\xbb"
    idr_nal = b"\x65\xcc"
    nonidr_nal = b"\x41\xdd"
    assert pacer.nal_type(sps_nal) == 7
    assert pacer.nal_type(pps_nal) == 8
    assert pacer.nal_type(idr_nal) == 5
    assert pacer.nal_type(nonidr_nal) == 1


def test_h264_file_pacer_yields_sps_pps_before_first_idr():
    p = pacer.H264NaluPacer(TEST_FILE, fps=30)
    nalus = []
    for nal, pts, frame_type in p.iter_once():
        nalus.append((pacer.nal_type(nal), frame_type))
    types = [t for t, _ in nalus]
    # First IDR must be preceded by SPS(7) and PPS(8) somewhere before it
    first_idr = types.index(5)
    assert 7 in types[:first_idr]
    assert 8 in types[:first_idr]


def test_h264_file_pacer_pts_monotonic_within_one_loop():
    p = pacer.H264NaluPacer(TEST_FILE, fps=30)
    last_pts = -1
    for _, pts, _ in p.iter_once():
        assert pts >= last_pts
        last_pts = pts


def test_h264_file_pacer_loops_with_pts_resync():
    p = pacer.H264NaluPacer(TEST_FILE, fps=30)
    # Drain one full pass
    pts_first_pass = [pts for _, pts, _ in p.iter_once()]
    pts_second_pass = [pts for _, pts, _ in p.iter_once()]
    # PTS in second pass strictly increases past first pass
    assert pts_second_pass[0] > pts_first_pass[-1]


@pytest.mark.asyncio
async def test_h264_pacer_async_paces_at_fps(monkeypatch):
    p = pacer.H264NaluPacer(TEST_FILE, fps=30)
    sleeps: list[float] = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(pacer.asyncio, "sleep", fake_sleep)

    count = 0
    async for _ in p.iter_paced(loop=False):
        count += 1
        if count >= 60:  # ~2 seconds of frames
            break

    # Sum of sleeps should approximate (count / fps) seconds, allowing for
    # the SPS/PPS prepends which share a frame's PTS slot.
    total = sum(sleeps)
    assert 1.0 <= total <= 3.0, f"unexpected total sleep: {total}"


def test_silent_aac_pacer_emits_constant_frame():
    p = pacer.SilentAacPacer()
    gen = p.iter_once()
    f1 = next(gen)
    f2 = next(gen)
    payload1, pts1, ft1 = f1
    payload2, pts2, ft2 = f2
    assert payload1 == payload2
    assert pts2 == pts1 + pacer.AUDIO_FRAME_SAMPLES
    assert ft1 == pacer.FRAME_AUDIO
    assert len(payload1) > 0
    assert len(payload1) < 200  # sanity: silence is small


@pytest.mark.asyncio
async def test_silent_aac_pacer_paces_at_audio_interval(monkeypatch):
    p = pacer.SilentAacPacer()
    sleeps: list[float] = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(pacer.asyncio, "sleep", fake_sleep)

    count = 0
    async for _ in p.iter_paced():
        count += 1
        if count >= 100:
            break

    expected_step = pacer.AUDIO_FRAME_SAMPLES / pacer.AUDIO_SAMPLE_RATE_HZ
    assert all(abs(s - expected_step) < 1e-6 for s in sleeps)


def _annexb(*nalus: bytes) -> bytes:
    """Join NAL units with 4-byte start codes."""
    return b"".join(b"\x00\x00\x00\x01" + n for n in nalus)


def test_scan_file_requires_sps_and_pps(tmp_path):
    """An asset with no parameter sets cannot configure a decoder.

    The message names the offending path, which is the only thing that makes
    the failure actionable.
    """
    asset = tmp_path / "no_ps.h264"
    asset.write_bytes(_annexb(b"\x65\x11\x22"))  # a lone IDR slice

    with pytest.raises(ValueError, match=f"{asset}: no SPS/PPS found"):
        pacer._scan_file(asset)


def test_scan_file_requires_an_idr(tmp_path):
    """Parameter sets without a keyframe give the receiver nothing to show."""
    asset = tmp_path / "no_idr.h264"
    # SPS, PPS and a non-IDR slice (type 1).
    asset.write_bytes(_annexb(b"\x67\xaa\xbb\xcc", b"\x68\xdd", b"\x41\x11"))

    with pytest.raises(ValueError, match=f"{asset}: no IDR found"):
        pacer._scan_file(asset)


@pytest.mark.asyncio
async def test_iter_paced_stops_at_end_of_file_when_not_looping():
    """With loop=False the generator must terminate after one pass."""
    once = list(pacer.H264NaluPacer(TEST_FILE, fps=60).iter_once())

    packer = pacer.H264NaluPacer(TEST_FILE, fps=60)
    produced = [item async for item in packer.iter_paced(loop=False)]

    assert produced == once
    assert produced, "the test asset must yield at least one NAL"


def test_find_start_codes_reports_offset_and_width():
    """Both Annex-B widths, at the offsets they actually occur.

    ``session.py``'s live-encoder path needs the offsets rather than the
    payloads, and carried its own copy of this scan nested inside an
    I/O-bound coroutine, where no test could reach it -- it sat at zero
    coverage for a reason that never applied to it: it needs bytes, not an
    encoder.  ``split_nalus`` is now expressed in terms of this too, so the
    two cannot drift.
    """
    assert pacer.find_start_codes(b"\x00\x00\x01\x65") == [(0, 3)]
    assert pacer.find_start_codes(b"\x00\x00\x00\x01\x65") == [(0, 4)]
    assert pacer.find_start_codes(b"\x00\x00\x01a\x00\x00\x00\x01b") == [(0, 3), (4, 4)]

    # A run of zeros: the code starts at the last zero that still leads 00 00 01,
    # and the leading zeros are not themselves start codes.
    assert pacer.find_start_codes(b"\x00\x00\x00\x00\x01") == [(1, 4)]

    # Nothing to find. The all-zero cases matter more than they look: the
    # four-byte branch reads data[i + 3], and its `i + 3 < n` guard is the
    # only thing keeping that in bounds. Relaxing it to `<=` raises
    # IndexError on exactly these -- and on nothing else here, because every
    # other input short-circuits at `data[i + 2] == 0` first.
    for data in (
        b"",
        b"\x00",
        b"\x00\x00",
        b"\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x02",
        b"abc",
    ):
        assert pacer.find_start_codes(data) == [], data


def test_find_start_codes_never_returns_overlapping_codes():
    """Each match consumes its own start code before scanning resumes.

    Back-to-back start codes are the case that separates skipping by the
    code's width from skipping by one: scanning by one would report a second,
    overlapping code inside ``00 00 01 00 00 01``.
    """
    codes = pacer.find_start_codes(b"\x00\x00\x01" * 4)
    assert codes == [(0, 3), (3, 3), (6, 3), (9, 3)]

    ends = [off + length for off, length in codes]
    starts = [off for off, _ in codes]
    assert all(e <= s for e, s in zip(ends, starts[1:])), codes

    # The four-byte case is where skipping by the width rather than by one
    # actually matters: the last three bytes of `00 00 00 01` are themselves
    # a valid three-byte code, so a scanner that advanced by one would report
    # (0, 4) and then an overlapping (1, 3).
    assert pacer.find_start_codes(b"\x00\x00\x00\x01") == [(0, 4)]


def test_split_nalus_and_find_start_codes_agree_on_the_same_buffer():
    """The payloads must be exactly the gaps between the codes.

    This is what stops the two from drifting apart again: whatever the
    scanner finds, ``split_nalus`` must carve at precisely those boundaries.
    """
    data = b"junk\x00\x00\x01\x65\x41\x00\x00\x00\x01\x67\x00\x00\x01\x68"
    codes = pacer.find_start_codes(data)
    expected = [
        data[off + length : (codes[i + 1][0] if i + 1 < len(codes) else len(data))]
        for i, (off, length) in enumerate(codes)
    ]
    assert pacer.split_nalus(data) == expected
    assert expected == [b"\x65\x41", b"\x67", b"\x68"]


@pytest.mark.asyncio
async def test_a_sleep_falls_between_two_frames_exactly_when_the_pts_changes(
    monkeypatch,
):
    """Where the sleeps land, not just how long they add up to.

    ``test_h264_pacer_async_paces_at_fps`` sums them and accepts anything
    between one and three seconds, which is the right check for the rate and
    blind to one sleep in the wrong place.  Two of the conditions deciding
    that place are easy to get subtly wrong:

    ``last_pts`` starts at -1 and the guard is ``last_pts >= 0``, meaning
    "not the first frame".  Written ``> 0`` it still reads that way and is
    not, because ``_pts_cursor`` starts at 0: the first frame's PTS *is* the
    sentinel's neighbour, so the very first gap silently stops being paced.
    The suite did not notice that change.

    So: between consecutive emissions there is a sleep exactly when the PTS
    moved -- never before the first frame, never between NAL units sharing a
    slot, always across a slot boundary.

    Measured with this test deselected rather than assumed: the sentinel and
    the guard both survive without it, so it is the sole catch for those.
    Changing the interval itself does not -- ``test_h264_pacer_async_paces_at_fps``
    already catches that -- so what this adds is the placement, not the rate.
    """
    paced = pacer.H264NaluPacer(TEST_FILE, fps=30)
    events: list = []

    async def fake_sleep(delay):
        events.append(("sleep", delay))

    monkeypatch.setattr(pacer.asyncio, "sleep", fake_sleep)

    async for _, pts, _ in paced.iter_paced(loop=False):
        events.append(("yield", pts))
        if sum(1 for kind, _ in events if kind == "yield") >= 12:
            break

    assert events[0][0] == "yield", "slept before emitting anything"

    seen = []
    slept_since_last_yield = 0
    for kind, value in events:
        if kind == "sleep":
            slept_since_last_yield += 1
            assert value == pytest.approx(1.0 / 30), value
        else:
            seen.append((value, slept_since_last_yield))
            slept_since_last_yield = 0

    for (previous, _), (pts, slept) in zip(seen, seen[1:]):
        want = 1 if pts != previous else 0
        assert slept == want, "pts %d -> %d: %d sleeps, wanted %d" % (
            previous,
            pts,
            slept,
            want,
        )


_SC4 = b"\x00\x00\x00\x01"


def _asset(tmp_path, *nalus: bytes) -> Path:
    path = tmp_path / "asset.h264"
    path.write_bytes(b"".join(_SC4 + nal for nal in nalus))
    return path


def test_a_file_missing_its_pps_is_refused(tmp_path):
    """Either parameter set missing is fatal, not both.

    ``_scan_file`` raises when ``sps is None or pps is None``. Written
    ``and`` it only objects when the file has neither, so a stream carrying
    an SPS and no PPS is accepted and goes on to build an avcC around a
    ``None``. Every asset the suite uses has both, so the change was
    invisible.
    """
    sps_only = _asset(tmp_path, b"\x67\x42\x00\x1f", b"\x65" + b"\xa0" * 8)
    with pytest.raises(ValueError, match="no SPS/PPS"):
        pacer.H264NaluPacer(sps_only, fps=30)

    pps_only = _asset(tmp_path, b"\x68\xce\x38\x80", b"\x65" + b"\xa0" * 8)
    with pytest.raises(ValueError, match="no SPS/PPS"):
        pacer.H264NaluPacer(pps_only, fps=30)


def test_the_parameter_sets_are_chosen_by_type_not_by_position(tmp_path):
    """The first SPS, not the first NAL.

    ``if t == NAL_SPS and sps is None`` keeps the FIRST SPS and ignores
    later ones. Written ``or`` it does two things instead: it takes whatever
    NAL arrives while the slot is empty, and it lets every later SPS
    overwrite the choice. Neither shows on the assets this suite ships --
    they open with their SPS and carry exactly one -- so the file here opens
    with an SEI, which is legal and common, and repeats the parameter sets
    partway through, which is how a stream stays joinable.
    """
    sps = b"\x67\x42\x00\x1f"
    later_sps = b"\x67\x4d\x40\x28"
    pps = b"\x68\xce\x38\x80"
    later_pps = b"\x68\xee\x3c\x80"
    stream = _asset(
        tmp_path,
        b"\x06" + b"\x90" * 8,
        sps,
        pps,
        b"\x65" + b"\xa0" * 8,
        later_sps,
        later_pps,
        b"\x65" + b"\xb0" * 8,
    )
    paced = pacer.H264NaluPacer(stream, fps=30)

    # pylint: disable-next=protected-access
    state = paced._state
    assert state.sps == sps, "kept %s, not the first SPS" % state.sps.hex()
    assert state.pps == pps, "kept %s, not the first PPS" % state.pps.hex()
