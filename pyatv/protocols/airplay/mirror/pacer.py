"""Frame pacers for the AirPlay 2 mirror MVP.

Reads a pre-encoded H.264 elementary stream (Annex-B), emits one NAL unit per
send cycle paced at the file's declared FPS, and loops at EOF. Also provides a
silent AAC-ELD pacer that emits one constant frame every 10 ms.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import AsyncIterator, Iterator, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)


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

# Mirror frame "type" tags pushed into the stream channel queue.
# These are local enum-style constants — the exact wire-level type byte is
# applied later by streams.py / framing.py.
FRAME_VIDEO_NORMAL = 0
FRAME_VIDEO_KEYFRAME = 1
FRAME_AUDIO = 2

# 90 kHz video clock (same as MPEG-TS / H.264 PTS convention)
VIDEO_CLOCK_HZ = 90_000


@dataclass
class _FileState:
    """A scanned file: its NAL units plus the SPS/PPS the pacer replays.

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


class H264NaluPacer:
    """Iterates NAL units from an Annex-B file, FPS-paced, looping forever.

    Yields (nal_payload, pts_90khz, frame_type) tuples. SPS and PPS are
    prepended before each IDR (sharing the IDR's PTS slot). At EOF, the
    iterator rewinds and continues with PTS resynced to wall clock.
    """

    def __init__(self, path: Path, fps: int) -> None:
        """Scan *path* once and pace its access units at *fps*."""
        self._state = _scan_file(path)
        self._fps = fps
        self._pts_step = VIDEO_CLOCK_HZ // fps
        self._pts_cursor = 0  # accumulates across iter_once() calls

    def iter_once(self) -> Iterator[Tuple[bytes, int, int]]:
        """Yield one full pass of the file. Continues PTS from previous calls."""
        for nal in self._state.nalus:
            t = nal_type(nal)
            if t == NAL_IDR:
                # Prepend cached SPS+PPS at the same PTS slot
                yield self._state.sps, self._pts_cursor, FRAME_VIDEO_KEYFRAME
                yield self._state.pps, self._pts_cursor, FRAME_VIDEO_KEYFRAME
                yield nal, self._pts_cursor, FRAME_VIDEO_KEYFRAME
                self._pts_cursor += self._pts_step
            elif t in (NAL_SPS, NAL_PPS):
                # Skip — we prepend our cached copies before each IDR
                continue
            else:
                yield nal, self._pts_cursor, FRAME_VIDEO_NORMAL
                self._pts_cursor += self._pts_step

    async def iter_paced(
        self, loop: bool = True
    ) -> AsyncIterator[Tuple[bytes, int, int]]:
        """Async iterator that paces emission at the configured FPS.

        Sleeps `1/fps` seconds between PTS-advancing yields. Multiple NAL units
        sharing one PTS slot (SPS/PPS/IDR triple) are emitted back-to-back with
        no sleep between them; the sleep happens after the slot completes.
        """
        last_pts = -1
        while True:
            for nal, pts, ft in self.iter_once():
                if pts != last_pts and last_pts >= 0:
                    await asyncio.sleep(1.0 / self._fps)
                last_pts = pts
                yield nal, pts, ft
            if not loop:
                return
            # Looped: reset pts to one step beyond the last
            # (already advancing inside iter_once via _pts_cursor)


# AAC-LC parameters used for the silent audio stream.
# Note: spec originally targeted AAC-ELD (480-sample frames at 48 kHz). The
# `aac_ld` profile is not available in stock ffmpeg builds (needs libfdk_aac),
# so the MVP ships AAC-LC instead. Apple TVs accept AAC-LC for mirror audio.
# If hardware testing reveals the receiver requires AAC-ELD specifically,
# regenerate the silence with libfdk_aac and update both the constant and
# the SDP `audioFormat`/`rtpmap` strings in session.py.
AUDIO_SAMPLE_RATE_HZ = 48_000
AUDIO_FRAME_SAMPLES = 1024  # AAC-LC frame size (~21.33 ms at 48 kHz)

# Steady-state 6-byte silent AAC-LC frame at 48 kHz / stereo, raw (no ADTS
# header). Generated offline with:
#   ffmpeg -f lavfi -i "anullsrc=channel_layout=stereo:sample_rate=48000" \
#       -t 0.05 -c:a aac -b:a 64k -f adts silence.aac
# Then walk the ADTS frames and pick the most common (steady-state) payload
# after the first warm-up frame. If you regenerate, replace the bytes below
# verbatim — do NOT hand-edit.
_AAC_LC_SILENCE_FRAME = bytes.fromhex("211004608c1c")


class SilentAacPacer:
    """Emits a single constant AAC-LC silence frame at the AAC frame interval."""

    def __init__(self) -> None:
        """Start the PTS cursor at zero."""
        self._pts_cursor = 0

    def iter_once(self) -> Iterator[Tuple[bytes, int, int]]:
        """Yield one frame and advance PTS by AUDIO_FRAME_SAMPLES (audio clock)."""
        while True:
            yield _AAC_LC_SILENCE_FRAME, self._pts_cursor, FRAME_AUDIO
            self._pts_cursor += AUDIO_FRAME_SAMPLES

    async def iter_paced(self) -> AsyncIterator[Tuple[bytes, int, int]]:
        """Async iterator paced at AUDIO_FRAME_SAMPLES / AUDIO_SAMPLE_RATE_HZ."""
        step = AUDIO_FRAME_SAMPLES / AUDIO_SAMPLE_RATE_HZ
        gen = self.iter_once()
        while True:
            try:
                yield next(gen)
            except StopIteration:
                return
            await asyncio.sleep(step)
