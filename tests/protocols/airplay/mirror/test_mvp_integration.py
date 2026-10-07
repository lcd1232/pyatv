"""End-to-end MVP integration: MirrorSession against FakeMirrorReceiver."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pyatv.protocols.airplay.mirror import (
    MirrorContext,
    MirrorSession,
    fairplay,
    fairplay_sap,
    framing,
)
from pyatv.protocols.airplay.mirror import session as session_mod
from pyatv.support.http import http_connect
from pyatv.support.rtsp import RtspSession

from tests.protocols.airplay.mirror.fake_receiver import FakeMirrorReceiver

# Five seconds of ffmpeg's testsrc, 1280x720 at 30 fps, baseline H.264 with
# an IDR every 30 frames and no B-frames:
#   ffmpeg -f lavfi -i testsrc=size=1280x720:rate=30 -t 5 -c:v libx264 \
#     -profile:v baseline -g 30 -keyint_min 30 -sc_threshold 0 -bf 0 \
#     -pix_fmt yuv420p -f h264 test_pattern.h264
TEST_FILE = Path(__file__).parent / "test_pattern.h264"

#: Recorded FPLY v3 handshakes (``m2`` in, ``ekey``/``raw16`` out); one is
#: used below as a genuine receiver M2.
GOLDEN_VECTORS = Path(__file__).parent / "fply_pure_golden.jsonl"

# Video writes the receiver must see before the test stops the session.
REQUIRED_VIDEO_FRAMES = 5

# Only bounds a hang; waits normally complete in milliseconds.
GUARD_TIMEOUT = 60.0

pytestmark = pytest.mark.asyncio


async def test_mvp_streams_to_fake_receiver_after_mfisap_handshake(
    monkeypatch, tmp_path
):
    """A full session streams video and audio after a real MFiSAP handshake.

    Flow: audio SETUP, RECORD, then a type-110 video SETUP over a TCP
    ``dataPort``.  The FairPlay ``ekey``/``raw16`` are placeholder constants
    here; ``test_real_fairplay_material_crosses_into_session`` uses real ones.
    """
    # Screen audio is off by default, so supply an ELD file to enable it.
    eld_file = tmp_path / "silence.eld"
    frame = bytes(range(64))
    eld_file.write_bytes(
        b"".join(len(frame).to_bytes(4, "big") + frame for _ in range(4))
    )
    # One sync packet per audio frame, so the sync path is exercised
    # by frame count rather than by elapsed time.
    monkeypatch.setattr(session_mod, "AUDIO_SYNC_EVERY", 1)

    receiver = FakeMirrorReceiver()
    host, port = await receiver.start()

    connection = None
    sess = None
    run_task = None
    try:
        connection = await http_connect(host, port)

        sm = await fairplay.run_handshake(connection)
        assert receiver.fp_setup_received
        assert receiver.auth_setup_received

        rtsp = RtspSession(connection)
        ctx = MirrorContext(stream_encryptor=sm.stream_encryptor)
        # The fake does not unwrap ekey; these only exercise key transport
        # and derivation.
        ctx.audio_ekey = b"\x33" * 72
        ctx.ekey = b"\x44" * 72
        ctx.stream_raw16 = b"\x55" * 16
        verifier = MagicMock()
        verifier.encryption_keys.return_value = (b"\x11" * 32, b"\x22" * 32)
        verifier.srp._shared = b"\x66" * 32
        sess = MirrorSession(
            rtsp=rtsp,
            verifier=verifier,
            ctx=ctx,
            h264_path=TEST_FILE,
            eld_path=eld_file,
            pair_secret=b"\x66" * 32,
        )

        # asyncio.sleep is stubbed repo-wide (tests/conftest.py) to just yield,
        # so wait on the receiver's frame-count event, not on wall-clock time.
        run_task = asyncio.create_task(sess.run())
        wait_frames = asyncio.ensure_future(
            receiver.video_server.wait_frames(
                REQUIRED_VIDEO_FRAMES, timeout=GUARD_TIMEOUT
            )
        )
        # If run() dies, surface its error instead of waiting out the guard.
        done, _ = await asyncio.wait(
            [wait_frames, run_task], return_when=asyncio.FIRST_COMPLETED
        )
        if run_task in done:
            wait_frames.cancel()
            run_task.result()  # re-raise whatever killed the session
            pytest.fail("MirrorSession.run() returned before streaming started")
        await wait_frames
        await asyncio.wait_for(
            receiver.event_server.command_answered.wait(),
            timeout=GUARD_TIMEOUT,
        )
        await receiver.audio_data_server.wait_frames(
            REQUIRED_VIDEO_FRAMES, timeout=GUARD_TIMEOUT
        )
        await receiver.audio_control_server.wait_frames(1, timeout=GUARD_TIMEOUT)

        await sess.stop()
        try:
            await asyncio.wait_for(run_task, timeout=GUARD_TIMEOUT)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

        # The screen-audio sender runs on its own task; it must not outlive
        # stop().  Twenty loop turns is ample for a runaway sender to show.
        settled = receiver.audio_control_server.frames_received
        for _ in range(20):
            await asyncio.sleep(0)
        assert (
            receiver.audio_control_server.frames_received == settled
        ), "screen-audio sender still running after stop()"

        # SETUP bodies carry the expected constants (fake_receiver.CAPTURED_*).
        receiver.assert_protocol_ok()
        # Modern mirroring sends no ANNOUNCE/SDP.
        assert not receiver.announce_received, "ANNOUNCE must not be sent"
        # The session opens with the type-96 audio SETUP (which carries the
        # eventPort); there is no metadata-only session SETUP.
        assert receiver.audio_setup_received, "audio SETUP not received"
        assert not receiver.session_setup_received
        # The receiver sends POST /command on the event channel and tears the
        # session down after ~30 s if it goes unanswered.
        assert (
            receiver.event_server.command_answered.is_set()
        ), "sender never answered the receiver's POST /command"
        reply = receiver.event_server.command_response
        assert reply.startswith(b"RTSP/1.0 200 OK\r\n"), reply[:64]
        assert b"CSeq: 7\r\n" in reply, reply[:64]
        assert receiver.stream_setup_received, "stream SETUP not received"
        assert (
            receiver.setup_count == 2
        ), f"expected 2 SETUPs, got {receiver.setup_count}"
        assert receiver.record_received, "RECORD not received"
        assert receiver.teardown_received, "TEARDOWN not received"
        assert (
            receiver.video_server.frames_received >= REQUIRED_VIDEO_FRAMES
        ), f"too few video bursts: {receiver.video_server.frames_received}"
        assert receiver.video_server.bytes_received > 0
        assert receiver.audio_data_server.bytes_received > 0
        # The receiver only schedules audio after a sync packet (PT 84).
        assert receiver.audio_control_server.frames_received >= 1
    finally:
        if sess is not None:
            try:
                await sess.stop()
            except Exception:
                pass
        if run_task is not None and not run_task.done():
            run_task.cancel()
            try:
                await run_task
            except BaseException:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        await receiver.close()


async def test_real_fairplay_material_crosses_into_session(monkeypatch):
    """Real ``fairplay_sap`` output reaches the wire and the key derivation.

    Runs the FairPlay handshake on a recorded receiver M2 and checks the
    resulting ``ekey``, SAP context and ``raw16`` are sent and used unchanged
    by a :class:`MirrorSession`.  Value correctness is covered by the golden
    vectors in ``test_fairplay_sap.py``; this test covers shape and placement.
    """
    with GOLDEN_VECTORS.open(encoding="utf-8") as fh:
        vector = json.loads(fh.readline())
    m2 = bytes.fromhex(vector["m2"])
    raw16 = bytes.fromhex(vector["raw16"])

    sap36, tag, _context, ekey = fairplay_sap.handshake(m2, raw16)
    # The session sends `ekey` whole and reads the context at [8:44].
    assert len(sap36) == 36, len(sap36)
    assert len(tag) == 20, len(tag)
    assert len(ekey) == 72, len(ekey)
    assert ekey.hex() == vector["ekey"]

    pair32 = bytes.fromhex("66" * 32)

    # The derived key is local to the session, so spy on the derivation call
    # (the real one still runs) to see which raw16 it was given.
    derivations = []
    real_derive = framing.derive_tcp_stream_key_iv

    def recording_derive(*args, **kwargs):
        result = real_derive(*args, **kwargs)
        derivations.append((args, kwargs, result))
        return result

    monkeypatch.setattr(framing, "derive_tcp_stream_key_iv", recording_derive)

    receiver = FakeMirrorReceiver()
    host, port = await receiver.start()

    connection = None
    sess = None
    run_task = None
    try:
        connection = await http_connect(host, port)
        sm = await fairplay.run_handshake(connection)

        rtsp = RtspSession(connection)
        ctx = MirrorContext(stream_encryptor=sm.stream_encryptor)
        ctx.ekey = ekey
        ctx.audio_ekey = ekey
        ctx.stream_raw16 = raw16
        ctx.sap_context = fairplay_sap.context_after_m3(sap36)

        verifier = MagicMock()
        verifier.encryption_keys.return_value = (b"\x11" * 32, b"\x22" * 32)
        verifier.srp._shared = pair32
        sess = MirrorSession(
            rtsp=rtsp,
            verifier=verifier,
            ctx=ctx,
            h264_path=TEST_FILE,
            pair_secret=pair32,
        )

        run_task = asyncio.create_task(sess.run())
        wait_frames = asyncio.ensure_future(
            receiver.video_server.wait_frames(
                REQUIRED_VIDEO_FRAMES, timeout=GUARD_TIMEOUT
            )
        )
        done, _ = await asyncio.wait(
            [wait_frames, run_task], return_when=asyncio.FIRST_COMPLETED
        )
        if run_task in done:
            wait_frames.cancel()
            run_task.result()
            pytest.fail("MirrorSession.run() returned before streaming started")
        await wait_frames

        await sess.stop()
        try:
            await asyncio.wait_for(run_task, timeout=GUARD_TIMEOUT)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

        # 1. The ekey reaches both stream SETUPs unchanged.
        receiver.assert_protocol_ok()
        assert receiver.video_setup_ekey == ekey, "video SETUP ekey altered in transit"
        assert receiver.video_setup_et == 32
        assert receiver.audio_setup_ekey == ekey, "audio SETUP ekey altered in transit"
        # The video eiv is random, so only its length is fixed; the audio eiv
        # is kept on the context and can be compared.
        assert len(receiver.video_setup_eiv) == 16, receiver.video_setup_eiv
        assert receiver.audio_setup_eiv == ctx.audio_eiv

        # 2. The SAP context holds the secret where the session reads it.
        assert len(ctx.sap_context) == 276
        assert ctx.sap_context[8:44] == sap36

        # 3. The video key is derived from the real raw16 and the negotiated
        #    streamConnectionID.
        assert derivations, "video key derivation never ran"
        (d_raw16, d_pair32, d_sid), _kwargs, (key, iv) = derivations[0]
        assert d_raw16 == raw16, "session keyed video from something other than raw16"
        assert d_pair32 == pair32
        assert d_sid == ctx.stream_connection_id
        assert (key, iv) == real_derive(raw16, pair32, ctx.stream_connection_id)
        assert key != real_derive(b"\x55" * 16, pair32, ctx.stream_connection_id)[0]

        # 4. The session still streams.
        assert receiver.record_received
        assert receiver.teardown_received
        assert receiver.video_server.frames_received >= REQUIRED_VIDEO_FRAMES
        assert receiver.video_server.bytes_received > 0
    finally:
        if sess is not None:
            try:
                await sess.stop()
            except Exception:
                pass
        if run_task is not None and not run_task.done():
            run_task.cancel()
            try:
                await run_task
            except BaseException:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        await receiver.close()
