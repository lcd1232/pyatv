"""Error and edge branches in :mod:`~pyatv.protocols.airplay.mirror.session`.

These cover a misbehaving receiver: unexpected statuses, missing plist keys,
split requests, malformed media. Tests assert on what the caller sees -- the
exception type and message, or the formatted log record -- so that error
paths that never run in a healthy session are actually evaluated.

Where practical, a real :class:`~pyatv.protocols.airplay.mirror.MirrorSession`
is driven against
:class:`~tests.protocols.airplay.mirror.fake_receiver.FakeMirrorReceiver` over
real sockets.

pyatv's HTTP layer raises :class:`exceptions.HttpError` for any non-2xx
response before the session's ``resp.code != 200`` checks run, so the fake
uses RTSP 250 "Low on Storage Space" (a 2xx that is not 200) to reach them.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
import plistlib
import struct
import sys
from unittest.mock import MagicMock

import pytest

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import (
    MirrorContext,
    MirrorSession,
    fairplay,
    framing,
)
from pyatv.protocols.airplay.mirror import (
    tcp_stream,
)
from pyatv.protocols.airplay.mirror import session as session_mod
from pyatv.support.http import http_connect
from pyatv.support.rtsp import RtspSession

from tests.protocols.airplay.mirror.fake_receiver import FakeMirrorReceiver

TEST_FILE = Path(__file__).parent / "test_pattern.h264"

#: Only a failure guard -- asyncio.sleep is stubbed repo-wide, so every wait
#: below completes in milliseconds.
GUARD_TIMEOUT = 60.0

#: A 2xx status that is not 200. See the module docstring.
RTSP_LOW_ON_STORAGE = 250

pytestmark = pytest.mark.asyncio


@contextlib.asynccontextmanager
async def driven_session(
    monkeypatch,
    *,
    with_audio_ekey: bool = True,
    with_ekey: bool = True,
    with_raw16: bool = True,
    with_pair32: bool = True,
    stream_encryptor: bool = True,
    ctx_overrides: dict | None = None,
    session_kwargs: dict | None = None,
    **receiver_kwargs,
):
    """Yield ``(receiver, session)`` wired together over real sockets.

    Runs the real FairPlay handshake against the fake first, so the session
    starts in the same state as a live one. Everything is torn down on exit,
    even when the body raises.

    ``ctx_overrides`` sets MirrorContext fields before the session runs;
    ``session_kwargs`` are passed to :class:`MirrorSession`.
    """
    receiver = FakeMirrorReceiver(**receiver_kwargs)
    host, port = await receiver.start()

    connection = None
    sess = None
    try:
        connection = await http_connect(host, port)
        handshake = await fairplay.run_handshake(connection)

        ctx = MirrorContext(
            stream_encryptor=handshake.stream_encryptor if stream_encryptor else None
        )
        if with_audio_ekey:
            ctx.audio_ekey = b"\x33" * 72
        if with_ekey:
            ctx.ekey = b"\x44" * 72
        if with_raw16:
            ctx.stream_raw16 = b"\x55" * 16
        for _field, _value in (ctx_overrides or {}).items():
            assert hasattr(ctx, _field), f"MirrorContext has no {_field!r}"
            setattr(ctx, _field, _value)

        verifier = MagicMock()
        verifier.encryption_keys.return_value = (b"\x11" * 32, b"\x22" * 32)
        verifier.srp._shared = b"\x66" * 32 if with_pair32 else None

        sess = MirrorSession(
            rtsp=RtspSession(connection),
            verifier=verifier,
            ctx=ctx,
            h264_path=TEST_FILE,
            pair_secret=b"\x66" * 32 if with_pair32 else None,
            **(session_kwargs or {}),
        )
        yield receiver, sess
        # Only on a clean exit, so a failure in the body is not masked.
        receiver.assert_protocol_ok()
    finally:
        if sess is not None:
            with contextlib.suppress(Exception):
                await sess.stop()
        if connection is not None:
            with contextlib.suppress(Exception):
                connection.close()
        await receiver.close()


async def run_until_error(sess) -> BaseException:
    """Run the session and return whatever ``run()`` raised."""
    task = asyncio.ensure_future(sess.run())
    try:
        await asyncio.wait_for(task, timeout=GUARD_TIMEOUT)
    except BaseException as ex:  # noqa: BLE001 - the test asserts on it
        return ex
    raise AssertionError("MirrorSession.run() completed without raising")


async def stream_then_stop(receiver, sess, *, video_frames: int = 1) -> None:
    """Run a session to steady state, then stop it cleanly.

    Waits for the receiver to see a video frame, so ``stop()`` is not called
    while ``run()`` is still setting up.
    """
    task = asyncio.ensure_future(sess.run())
    waiter = asyncio.ensure_future(
        receiver.video_server.wait_frames(video_frames, timeout=GUARD_TIMEOUT)
    )
    # If run() dies, surface that error rather than waiting out the guard
    # timeout on an event that can never fire.
    done, _pending = await asyncio.wait(
        [waiter, task], return_when=asyncio.FIRST_COMPLETED
    )
    if task in done:
        waiter.cancel()
        task.result()  # re-raise whatever killed the session
        raise AssertionError("MirrorSession.run() returned before streaming started")
    await waiter

    await sess.stop()
    with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
        await asyncio.wait_for(task, timeout=GUARD_TIMEOUT)
    if not task.done():
        task.cancel()
        with contextlib.suppress(BaseException):
            await task


# ---------------------------------------------------------------------------
# ProtocolError guards on an unexpected status
# ---------------------------------------------------------------------------


async def test_audio_setup_non_200_raises_protocol_error(monkeypatch):
    """The type-96 audio SETUP guard must name the stream type."""
    async with driven_session(
        monkeypatch,
        status_overrides={"setup_audio": RTSP_LOW_ON_STORAGE},
    ) as (receiver, sess):
        error = await run_until_error(sess)

    assert isinstance(error, exceptions.ProtocolError), repr(error)
    assert "AUDIO SETUP" in str(error)
    assert "96" in str(error)
    assert str(RTSP_LOW_ON_STORAGE) in str(error)
    assert receiver.audio_setup_received


async def test_video_setup_non_200_raises_protocol_error(monkeypatch):
    """The type-110 video SETUP guard must name the video stream."""
    async with driven_session(
        monkeypatch,
        status_overrides={"setup_video": RTSP_LOW_ON_STORAGE},
    ) as (receiver, sess):
        error = await run_until_error(sess)

    assert isinstance(error, exceptions.ProtocolError), repr(error)
    assert "SETUP" in str(error)
    assert "video stream" in str(error)
    assert str(RTSP_LOW_ON_STORAGE) in str(error)
    assert receiver.stream_setup_received


async def test_record_non_200_raises_protocol_error(monkeypatch):
    """RECORD's guard must name RECORD and the status."""
    async with driven_session(
        monkeypatch,
        status_overrides={"record": RTSP_LOW_ON_STORAGE},
    ) as (receiver, sess):
        error = await run_until_error(sess)

    assert isinstance(error, exceptions.ProtocolError), repr(error)
    assert "RECORD failed" in str(error)
    assert str(RTSP_LOW_ON_STORAGE) in str(error)
    assert receiver.record_received


async def test_non_2xx_setup_never_reaches_protocol_error(monkeypatch):
    """A 4xx SETUP surfaces as HttpError, *not* the ProtocolError above.

    ``HttpConnection.send_and_receive`` raises for anything outside 2xx before
    the session's own status check runs. This pins which error a caller sees.
    """
    async with driven_session(
        monkeypatch,
        status_overrides={"setup_video": 455},
    ) as (_receiver, sess):
        error = await run_until_error(sess)

    assert isinstance(error, exceptions.HttpError), repr(error)
    assert "455" in str(error)
    # HttpError subclasses ProtocolError, so the message tells the paths apart.
    assert "method SETUP failed" in str(error)
    assert "video stream" not in str(error)


async def test_setup_session_without_stream_encryptor_raises(monkeypatch):
    """Without the FairPlay handshake's encryptor, SETUP must refuse to start."""
    async with driven_session(monkeypatch, stream_encryptor=False) as (
        receiver,
        sess,
    ):
        error = await run_until_error(sess)

    assert isinstance(error, exceptions.ProtocolError), repr(error)
    assert "stream_encryptor" in str(error)
    assert "_setup_session" in str(error)
    # It must fail *before* talking to the receiver at all.
    assert receiver.setup_count == 0


# ---------------------------------------------------------------------------
# Missing/absent fields in an otherwise well-formed response
# ---------------------------------------------------------------------------


async def test_missing_event_port_skips_event_channel(monkeypatch, caplog):
    """A SETUP answer with no eventPort must be logged and skipped, not crash."""
    caplog.set_level(logging.DEBUG, logger="pyatv.protocols.airplay.mirror.session")
    async with driven_session(monkeypatch, omit_event_port=True) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess)

    assert any("No eventPort returned" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]
    # The session still streamed: a missing eventPort is degraded, not fatal.
    assert receiver.video_server.frames_received >= 1
    assert receiver.event_server.frames_received == 0


async def test_audio_setup_without_control_port_skips_sync(monkeypatch, tmp_path):
    """No controlPort in the audio SETUP answer means no sync packets sent.

    ``_send_sync`` must not send to port 0.
    """
    eld_file = tmp_path / "silence.eld"
    frame = bytes(range(64))
    eld_file.write_bytes(
        b"".join(len(frame).to_bytes(4, "big") + frame for _ in range(4))
    )
    monkeypatch.setattr(session_mod, "AUDIO_SYNC_EVERY", 1)

    async with driven_session(
        monkeypatch,
        omit_audio_control_port=True,
        session_kwargs={"eld_path": eld_file},
    ) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=2)

    # Audio data still flows...
    assert receiver.audio_data_server.frames_received >= 2
    # ...but not one sync packet, because there is nowhere to send it.
    assert receiver.audio_control_server.frames_received == 0


async def test_event_request_split_across_segments_is_buffered(monkeypatch):
    """A POST /command split headers-then-body must still get one 200 reply.

    Answering the partial request, or answering twice, would desynchronise the
    channel; an unanswered receiver ends the session after about 30 s.
    """
    async with driven_session(monkeypatch, split_event_request=True) as (
        receiver,
        sess,
    ):
        # The event channel is opened and answered during setup, before video.
        await stream_then_stop(receiver, sess)
        assert receiver.event_server.command_answered.is_set()

    reply = receiver.event_server.command_response
    assert reply.startswith(b"RTSP/1.0 200 OK\r\n"), reply[:64]
    assert b"CSeq: 7\r\n" in reply, reply[:64]
    # No second reply from a half-parsed request.
    assert reply.count(b"RTSP/1.0 200 OK") == 1, reply


async def test_missing_pair32_logs_proven_key_unavailable(monkeypatch, caplog):
    """Without a 32-byte pair-verify secret, a warning reports both lengths."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.session")

    async with driven_session(monkeypatch, with_pair32=False) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    matching = [
        r.getMessage()
        for r in caplog.records
        if "PROVEN video key unavailable" in r.getMessage()
    ]
    assert matching, [r.getMessage() for r in caplog.records]
    assert "raw16=16B" in matching[0], matching[0]
    assert "pair32=None" in matching[0], matching[0]


async def test_audio_setup_skipped_without_audio_ekey(monkeypatch):
    """No audio ekey means the type-96 SETUP is skipped entirely."""
    async with driven_session(monkeypatch, with_audio_ekey=False) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess)

    assert not receiver.audio_setup_received
    # Only the video SETUP went out.
    assert receiver.setup_count == 1
    assert receiver.stream_setup_received


async def test_malformed_eld_file_stops_at_bad_length(monkeypatch, tmp_path):
    """A length prefix running past EOF ends ELD parsing without overrunning."""
    frame = bytes(range(32))
    good = b"".join(len(frame).to_bytes(4, "big") + frame for _ in range(2))
    truncated = (9999).to_bytes(4, "big") + b"\x00" * 8
    eld_file = tmp_path / "truncated.eld"
    eld_file.write_bytes(good + truncated)

    async with driven_session(monkeypatch, session_kwargs={"eld_path": eld_file}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=2)

    # The two readable frames were sent; the bad one contributed nothing.
    assert receiver.audio_data_server.frames_received >= 2


async def test_empty_eld_file_warns_and_sends_no_audio(monkeypatch, tmp_path, caplog):
    """An ELD file whose first length is unreadable yields no frames at all."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.session")
    eld_file = tmp_path / "empty.eld"
    eld_file.write_bytes((0).to_bytes(4, "big"))

    async with driven_session(monkeypatch, session_kwargs={"eld_path": eld_file}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess)

    assert any(
        "screen audio: no frames from" in r.getMessage() for r in caplog.records
    ), [r.getMessage() for r in caplog.records]
    assert receiver.audio_data_server.frames_received == 0


async def test_no_ekey_omits_stream_keys_from_setup(monkeypatch):
    """With no ekey to send, the video SETUP body must simply omit ekey/eiv.

    plistlib cannot serialise ``None``, so both keys must be left out.
    """
    bodies: list[dict] = []

    async with driven_session(monkeypatch, with_ekey=False) as (receiver, sess):
        original = receiver._dispatch_setup

        def _capture(body: bytes):
            if body:
                with contextlib.suppress(Exception):
                    bodies.append(plistlib.loads(bytes(body)))
            return original(body)

        receiver._dispatch_setup = _capture
        await stream_then_stop(receiver, sess)

    video = [
        b for b in bodies if any(s.get("type") == 110 for s in b.get("streams", []))
    ]
    assert video, bodies
    assert "ekey" not in video[0], video[0]
    assert "eiv" not in video[0], video[0]


# ---------------------------------------------------------------------------
# Branches only reachable by direct call
# ---------------------------------------------------------------------------


async def test_audio_stream_setup_is_idempotent(monkeypatch):
    """A second ``_setup_audio_stream()`` must be a no-op.

    ``run()`` only calls it once, so the guard is exercised directly.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await sess._setup_session()
        await sess._setup_audio_stream()
        assert receiver.audio_setup_received
        assert receiver.setup_count == 1

        # Second call: must not put another SETUP on the wire.
        await sess._setup_audio_stream()
        assert receiver.setup_count == 1


async def test_dead_audio_data_port_logs_the_icmp_error(monkeypatch, tmp_path, caplog):
    """A screen-audio dataPort nothing listens on must surface the UDP error.

    The audio socket is a connected datagram endpoint, so ICMP port
    unreachable reaches ``error_received``; otherwise a dead port looks like
    silence. Relies on the OS reporting ICMP on loopback (Linux and macOS do).
    """
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.session")
    eld_file = tmp_path / "silence.eld"
    frame = bytes(range(64))
    eld_file.write_bytes(
        b"".join(len(frame).to_bytes(4, "big") + frame for _ in range(4))
    )
    async with driven_session(
        monkeypatch,
        dead_audio_data_port=True,
        session_kwargs={"eld_path": eld_file},
    ) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=3)

    matching = [
        r.getMessage() for r in caplog.records if "UDP error (ICMP?)" in r.getMessage()
    ]
    assert matching, [r.getMessage() for r in caplog.records]
    assert "screen audio[DATA]" in matching[0], matching[0]


async def test_a_stopped_session_refuses_to_run_again(monkeypatch):
    """``run()`` after ``stop()`` names the mistake instead of failing later.

    ``stop()`` has closed the connection, and tasks started afterwards would
    never be cancelled.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

        with pytest.raises(RuntimeError, match="already stopped"):
            await sess.run()

        assert all(
            task.done() for task in sess._tasks
        ), "the refused run() left tasks behind"  # noqa: SLF001


@pytest.mark.parametrize("channel", ["video", "control"])
async def test_a_dropped_receiver_does_not_end_the_session(monkeypatch, channel):
    """Characterisation: losing the video or control connection is not fatal.

    The loss is logged but not propagated, so ``run()`` keeps streaming until
    the caller stops it. This records current behaviour, not a requirement;
    change it deliberately.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            await asyncio.wait_for(
                receiver.video_server.wait_frames(2, timeout=GUARD_TIMEOUT),
                timeout=GUARD_TIMEOUT,
            )

            if channel == "video":
                writers = list(receiver.video_server._writers)  # noqa: SLF001
            else:
                writers = list(receiver._control_writers)  # noqa: SLF001
            assert writers, f"no {channel} connection to drop"
            for writer in writers:
                writer.transport.abort()

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), timeout=1.0)
            assert not task.done(), "run() ended -- the loss is now noticed"
        finally:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task


@pytest.mark.parametrize("yields", [2, 5, 8, 12])
async def test_stop_during_setup_leaves_no_task_registered_after_it(
    monkeypatch, yields
):
    """``run()`` must not add work to a session that has already stopped.

    ``stop()`` only cancels tasks registered before it, but ``run()`` may still
    be mid-setup. Stopping after a varying number of loop turns hits different
    setup stages; the task count must not grow after ``stop()``.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            for _ in range(yields):
                await asyncio.sleep(0.002)

            await sess.stop()
            registered_at_stop = len(sess._tasks)  # noqa: SLF001

            for _ in range(10):  # let run() carry on as far as it will
                await asyncio.sleep(0.002)

            assert len(sess._tasks) == registered_at_stop, (  # noqa: SLF001
                f"{len(sess._tasks) - registered_at_stop} task(s) registered "  # noqa: SLF001
                "after stop() -- nothing will cancel them"
            )
        finally:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task


# ---------------------------------------------------------------------------
# the live-encoder path
# ---------------------------------------------------------------------------

_SC = b"\x00\x00\x00\x01"
_SPS = b"\x67\x42\x00\x1f"
_PPS = b"\x68\xce\x38\x80"


def _annexb(*nalus: bytes) -> bytes:
    """Annex-B stream, ending in a start code.

    The reader only emits a NAL once the next start code arrives.
    """
    return b"".join(_SC + nal for nal in nalus) + _SC


@pytest.mark.asyncio
async def test_the_live_encoder_path_parses_a_stream_off_a_subprocess(
    monkeypatch, tmp_path
):
    """``video_command`` output is parsed into a config frame and access units.

    A subprocess writes hand-built Annex-B NAL units. The config frame must
    carry the SPS and PPS from the pipe, and types 1 and 5 each complete an
    access unit.
    """
    # SEI (sent with the following access unit), then an IDR and a non-IDR
    # slice: two access units after the config frame.
    stream = _annexb(
        _SPS,
        _PPS,
        b"\x06" + b"\x90" * 8,
        b"\x65" + b"\xa0" * 24,
        b"\x41" + b"\xb0" * 24,
    )
    source = tmp_path / "stream.h264"
    source.write_bytes(stream)

    feeder = tmp_path / "feeder.py"
    feeder.write_text(
        "import sys\n" "sys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(source),
        encoding="utf-8",
    )
    live_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"video_command": live_cmd}
    ) as (receiver, sess):
        # Wait for three whole messages (config plus two access units).
        # Counted with _messages rather than wait_frames, which counts TCP
        # reads and could wait forever if two messages share one read.
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while len(_messages(receiver.video_server.head)) < 3:
                if task.done():
                    task.result()
                    break
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            wire = receiver.video_server.head
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    assert (
        len(_messages(wire)) >= 3
    ), "config plus two access units expected, got %d" % len(_messages(wire))
    assert wire, "no video reached the receiver from the live path"
    assert _SPS in wire, "the config frame does not carry the pipe's SPS"
    assert _PPS in wire, "the config frame does not carry the pipe's PPS"


@pytest.mark.asyncio
async def test_the_live_audio_reader_parses_length_prefixed_frames(
    monkeypatch, tmp_path
):
    """``audio_command`` output is parsed as 4-byte big-endian length frames.

    A malformed run in the middle (zero lengths) forces a byte-by-byte
    resync; the frames after it must still arrive intact and in order.
    """
    frames = [bytes([0x30 + i]) * (40 + i) for i in range(4)]
    payload = b"".join(struct.pack(">I", len(f)) + f for f in frames[:2])
    # An odd-length run, so only a one-byte resync stride realigns.
    payload += b"\x00" * 5
    payload += b"".join(struct.pack(">I", len(f)) + f for f in frames[2:])

    source = tmp_path / "audio.eld"
    source.write_bytes(payload)
    feeder = tmp_path / "audio_feeder.py"
    feeder.write_text(
        "import sys\n" "sys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(source),
        encoding="utf-8",
    )

    monkeypatch.setattr(session_mod, "AUDIO_PREBUFFER", 1)
    audio_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"audio_command": audio_cmd}
    ) as (receiver, sess):
        # Wait on audio directly; stream_then_stop waits on video, which may
        # be ready before the audio subprocess has started.
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while len(receiver.audio_data_server.datagrams) < len(frames):
                if task.done():
                    task.result()
                    raise AssertionError("run() ended before audio was sent")
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.02)
            packets = list(receiver.audio_data_server.datagrams)
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    assert packets, "no audio reached the receiver from the live command"
    # The cipher preserves length, so each packet is its frame plus a 12-byte
    # RTP header.
    sizes = [len(p) - 12 for p in packets[: len(frames)]]
    assert sizes == [
        len(f) for f in frames
    ], "payload sizes %s do not match the frames %s" % (sizes, [len(f) for f in frames])


@pytest.mark.asyncio
async def test_the_event_channel_frames_on_content_length_not_on_a_blank_line(
    monkeypatch,
):
    """Event requests are framed by Content-Length, not by a blank line.

    A binary plist body may contain ``\\r\\n\\r\\n``; both commands must
    still be answered, each under its own CSeq.
    """
    inside = b"\r\n\r\nCSeq: 999\r\n\r\n"
    bodies = [
        plistlib.dumps({"a": inside}, fmt=plistlib.FMT_BINARY),
        plistlib.dumps({"b": True}, fmt=plistlib.FMT_BINARY),
    ]
    assert b"\r\n\r\n" in bodies[0], "the fixture must carry a blank line"

    async with driven_session(monkeypatch, command_bodies=bodies) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=2)
        replies = receiver.event_server.command_response

    text = replies.decode("latin-1", "replace")
    assert (
        text.count("RTSP/1.0 200 OK") == 2
    ), "expected a reply to each command, got %d" % text.count("RTSP/1.0 200 OK")
    assert "CSeq: 7" in text, "the first command went unanswered"
    assert "CSeq: 8" in text, (
        "the second command was answered under the wrong CSeq: %r" % text
    )


@pytest.mark.asyncio
async def test_a_live_stream_missing_its_pps_sends_no_video(monkeypatch, tmp_path):
    """A live stream with an SPS but no PPS sends no video.

    The video producer gives up while the rest of the session keeps running.
    """
    stream = _annexb(_SPS, b"\x65" + b"\xa0" * 24, b"\x41" + b"\xb0" * 24)
    source = tmp_path / "nopps.h264"
    source.write_bytes(stream)
    feeder = tmp_path / "feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(source),
        encoding="utf-8",
    )
    live_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"video_command": live_cmd}
    ) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            # Once the feeder has exited, the source has been read to EOF.
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while asyncio.get_event_loop().time() < deadline:
                if task.done():
                    task.result()  # surface whatever killed it
                    break
                proc = sess._live_proc  # noqa: SLF001
                if proc is not None and proc.returncode is not None:
                    break
                if receiver.video_server.frames_received:
                    break
                await asyncio.sleep(0.01)
            for _ in range(10):  # let anything already queued drain
                await asyncio.sleep(0)
            sent = receiver.video_server.frames_received
            alive = not task.done()
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    assert sent == 0, "%d video message(s) sent for a stream with no PPS" % sent
    assert alive, "the session died instead of giving up on the source"


def _messages(wire: bytes) -> list:
    """Split the raw video stream into whole messages.

    Each is a 128-byte header with the little-endian payload length at offset
    0, then the payload. A trailing partial message is dropped.
    """
    out = []
    off = 0
    while off + 128 <= len(wire):
        (length,) = struct.unpack_from("<I", wire, off)
        body = wire[off + 128 : off + 128 + length]
        if len(body) < length:
            break
        out.append(body)
        off += 128 + length
    return out


@pytest.mark.asyncio
async def test_the_access_unit_keeps_its_sei_ahead_of_the_slice(monkeypatch, tmp_path):
    """An SEI precedes the slice in the access unit it belongs to.

    The access unit is decrypted with the session's key (AES-CTR, so
    encrypting again decrypts) to check the NAL order.
    """
    sei = b"\x06" + b"\x90" * 8
    idr = b"\x65" + b"\xa0" * 24
    stream = _annexb(_SPS, _PPS, sei, idr)
    source = tmp_path / "au.h264"
    source.write_bytes(stream)
    feeder = tmp_path / "feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(source),
        encoding="utf-8",
    )
    live_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"video_command": live_cmd}
    ) as (receiver, sess):
        # Count whole messages; wait_frames counts TCP reads.
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while len(_messages(receiver.video_server.head)) < 2:
                if task.done():
                    task.result()
                    break
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            wire = receiver.video_server.head
            raw16 = sess._ctx.stream_raw16  # noqa: SLF001
            sid = sess._ctx.stream_connection_id  # noqa: SLF001
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    messages = _messages(wire)
    assert len(messages) >= 2, "expected a config frame and an access unit"

    pair32 = bytes.fromhex("66" * 32)
    key, iv = framing.derive_tcp_stream_key_iv(raw16, pair32, sid)
    plain = framing.MirrorEncryptor.from_key_iv(key, iv).encrypt(messages[1])

    assert plain == tcp_stream.to_avcc([sei, idr]), (
        "access unit came out as %s" % plain[:8].hex()
    )


@pytest.mark.asyncio
async def test_a_full_live_queue_drops_the_oldest_access_unit(monkeypatch, tmp_path):
    """A full live video queue drops its oldest access unit to bound latency.

    The reader fills the queue during the ``LIVE_VIDEO_PREBUFFER`` wait. The
    first access unit sent must be one of the later ones, not the first.
    """
    sei_free = [b"\x41" + bytes([0xB0 + i]) * 24 for i in range(6)]
    stream = _annexb(_SPS, _PPS, *sei_free)
    source = tmp_path / "many.h264"
    source.write_bytes(stream)
    feeder = tmp_path / "feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(source),
        encoding="utf-8",
    )
    monkeypatch.setattr(session_mod, "LIVE_VIDEO_BUFFER", 2)
    live_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"video_command": live_cmd}
    ) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while len(_messages(receiver.video_server.head)) < 2:
                if task.done():
                    task.result()
                    break
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            wire = receiver.video_server.head
            raw16 = sess._ctx.stream_raw16  # noqa: SLF001
            sid = sess._ctx.stream_connection_id  # noqa: SLF001
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    messages = _messages(wire)
    assert len(messages) >= 2, "no access unit followed the config frame"

    pair32 = bytes.fromhex("66" * 32)
    key, iv = framing.derive_tcp_stream_key_iv(raw16, pair32, sid)
    first_au = framing.MirrorEncryptor.from_key_iv(key, iv).encrypt(messages[1])

    assert first_au != tcp_stream.to_avcc([sei_free[0]]), (
        "the first access unit sent was the source's first -- the queue kept "
        "the stale end"
    )
    assert first_au in [tcp_stream.to_avcc([n]) for n in sei_free[2:]], (
        "sent an access unit that is not one of the later ones: %s" % first_au[:8].hex()
    )


@pytest.mark.asyncio
async def test_the_receiver_closing_the_event_channel_does_not_end_the_session(
    monkeypatch,
):
    """Characterisation: EOF on the event channel does not end the session.

    The event reader stops; video and the other channels keep running. Like
    ``test_a_dropped_receiver_does_not_end_the_session``, this records
    current behaviour rather than a requirement.
    """
    async with driven_session(monkeypatch, hang_up_event_channel=True) as (
        receiver,
        sess,
    ):
        task = asyncio.ensure_future(sess.run())
        try:
            await asyncio.wait_for(
                receiver.event_server.command_answered.wait(), timeout=GUARD_TIMEOUT
            )
            # Give the sender's reader time to see the hang-up after the reply.
            for _ in range(20):
                await asyncio.sleep(0)

            assert not task.done(), "the session ended when the event channel shut"
            await receiver.video_server.wait_frames(1, timeout=GUARD_TIMEOUT)
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
