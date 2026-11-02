"""Tests for pyatv.protocols.airplay.mirror.pacer."""

from pathlib import Path

import pytest

from pyatv.protocols.airplay.mirror import pacer


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


def _annexb(*nalus: bytes) -> bytes:
    """Join NAL units with 4-byte start codes."""
    return b"".join(b"\x00\x00\x00\x01" + n for n in nalus)


def test_scan_file_requires_sps_and_pps(tmp_path):
    """An asset with no parameter sets is refused, naming the path."""
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


def test_find_start_codes_reports_offset_and_width():
    """Both Annex-B start-code widths are reported at their offsets."""
    assert pacer.find_start_codes(b"\x00\x00\x01\x65") == [(0, 3)]
    assert pacer.find_start_codes(b"\x00\x00\x00\x01\x65") == [(0, 4)]
    assert pacer.find_start_codes(b"\x00\x00\x01a\x00\x00\x00\x01b") == [(0, 3), (4, 4)]

    # A run of zeros: the code starts at the last zero that still leads 00 00 01,
    # and the leading zeros are not themselves start codes.
    assert pacer.find_start_codes(b"\x00\x00\x00\x00\x01") == [(1, 4)]

    # Nothing to find. The all-zero inputs exercise the bounds check on the
    # four-byte branch, which reads data[i + 3].
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
    """Each match consumes its own start code before scanning resumes."""
    codes = pacer.find_start_codes(b"\x00\x00\x01" * 4)
    assert codes == [(0, 3), (3, 3), (6, 3), (9, 3)]

    ends = [off + length for off, length in codes]
    starts = [off for off, _ in codes]
    assert all(e <= s for e, s in zip(ends, starts[1:])), codes

    # The last three bytes of a four-byte code are a valid three-byte code;
    # it must not also be reported as (1, 3).
    assert pacer.find_start_codes(b"\x00\x00\x00\x01") == [(0, 4)]


def test_split_nalus_and_find_start_codes_agree_on_the_same_buffer():
    """``split_nalus`` returns exactly the gaps between the found codes."""
    data = b"junk\x00\x00\x01\x65\x41\x00\x00\x00\x01\x67\x00\x00\x01\x68"
    codes = pacer.find_start_codes(data)
    expected = [
        data[off + length : (codes[i + 1][0] if i + 1 < len(codes) else len(data))]
        for i, (off, length) in enumerate(codes)
    ]
    assert pacer.split_nalus(data) == expected
    assert expected == [b"\x65\x41", b"\x67", b"\x68"]


_SC4 = b"\x00\x00\x00\x01"


def _asset(tmp_path, *nalus: bytes) -> Path:
    path = tmp_path / "asset.h264"
    path.write_bytes(b"".join(_SC4 + nal for nal in nalus))
    return path


def test_a_file_missing_its_pps_is_refused(tmp_path):
    """A file with only one of SPS and PPS is refused."""
    sps_only = _asset(tmp_path, b"\x67\x42\x00\x1f", b"\x65" + b"\xa0" * 8)
    with pytest.raises(ValueError, match="no SPS/PPS"):
        pacer._scan_file(sps_only)

    pps_only = _asset(tmp_path, b"\x68\xce\x38\x80", b"\x65" + b"\xa0" * 8)
    with pytest.raises(ValueError, match="no SPS/PPS"):
        pacer._scan_file(pps_only)
