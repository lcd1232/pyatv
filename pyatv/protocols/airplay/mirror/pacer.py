"""Annex-B H.264 parsing helpers for the AirPlay 2 mirror sender."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


def find_start_codes(data: bytes) -> List[Tuple[int, int]]:
    """Return ``(offset, length)`` for every Annex-B start code in *data*.

    Handles both 3-byte (00 00 01) and 4-byte (00 00 00 01) forms, and skips
    past each one it finds, so the codes returned never overlap.

    Split out because ``session.py``'s live-encoder path needs the offsets
    themselves rather than the NAL payloads, and had its own copy of this
    scan nested inside an I/O-bound function -- where no test could reach it.
    """
    codes: List[Tuple[int, int]] = []
    i = 0
    n = len(data)
    while i < n - 2:
        if data[i] == 0 and data[i + 1] == 0:
            if data[i + 2] == 1:
                codes.append((i, 3))
                i += 3
                continue
            if i + 3 < n and data[i + 2] == 0 and data[i + 3] == 1:
                codes.append((i, 4))
                i += 4
                continue
        i += 1
    return codes


def split_nalus(data: bytes) -> List[bytes]:
    """Split an Annex-B H.264 byte string into raw NAL unit payloads.

    Handles both 3-byte (00 00 01) and 4-byte (00 00 00 01) start codes.
    The returned NAL units do NOT include the start code. Anything before
    the first start code is dropped.
    """
    codes = find_start_codes(data)
    return [
        data[off + clen : codes[idx + 1][0] if idx + 1 < len(codes) else len(data)]
        for idx, (off, clen) in enumerate(codes)
    ]


def nal_type(nalu: bytes) -> int:
    """Return the H.264 NAL unit type for a raw NAL payload (no start code)."""
    return nalu[0] & 0x1F


# H.264 NAL unit types we care about
NAL_SPS = 7
NAL_PPS = 8
NAL_IDR = 5


@dataclass
class _FileState:
    """A scanned file: its NAL units plus its SPS/PPS.

    ``sps``/``pps`` are non-optional because :func:`_scan_file` -- the only
    thing that builds this -- refuses to return without both.
    """

    sps: bytes
    pps: bytes
    nalus: List[bytes] = field(default_factory=list)


def _scan_file(path: Path) -> _FileState:
    """Read the entire H.264 file once, cache SPS/PPS, return ordered NAL list."""
    data = path.read_bytes()
    nalus = split_nalus(data)
    sps: Optional[bytes] = None
    pps: Optional[bytes] = None
    for nal in nalus:
        t = nal_type(nal)
        if t == NAL_SPS and sps is None:
            sps = nal
        elif t == NAL_PPS and pps is None:
            pps = nal
    if sps is None or pps is None:
        raise ValueError(f"{path}: no SPS/PPS found in test asset")
    if not any(nal_type(n) == NAL_IDR for n in nalus):
        raise ValueError(f"{path}: no IDR found in test asset")
    return _FileState(sps=sps, pps=pps, nalus=list(nalus))
