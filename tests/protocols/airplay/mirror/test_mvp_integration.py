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

TEST_FILE = Path(__file__).parent / "test_pattern.h264"

#: Recorded FPLY v3 handshakes (``m2`` in, ``ekey``/``raw16`` out) captured from
#: the Unicorn emulator. ``test_fairplay_sap.py`` pins the pure-Python port
#: against every one of them; the seam test below reuses a single vector as a
#: source of a *genuine* receiver M2 to hand to the real handshake.
GOLDEN_VECTORS = Path(__file__).parent / "fply_pure_golden.jsonl"

# How many video writes must land before the test stops the session. The fake
# receiver signals the exact moment the Nth one arrives, so this is a
# threshold, never a duration.
REQUIRED_VIDEO_FRAMES = 5

# Only a failure guard. Under normal operation every wait below completes in
# milliseconds; the value is generous so a loaded machine cannot turn a pass
# into a flake.
GUARD_TIMEOUT = 60.0

pytestmark = pytest.mark.asyncio


async def test_mvp_streams_to_fake_receiver_after_mfisap_handshake(
    monkeypatch, tmp_path
):
    """A real MFiSAP handshake must feed a stream the receiver actually sees.

    The flow is the one that renders on tvOS 26: audio SETUP first, RECORD,
    then a type-110 video SETUP over a TCP ``dataPort``.

    Scope, because there are two unrelated handshakes in this package and the
    name used to blur them: the *MFiSAP* handshake below is real, run over the
    wire against the fake. The *FairPlay SAP* handshake (``fairplay_sap``, the
    ``/fp-setup`` FPLY v3 exchange that yields ``ekey``/``raw16``) is **not**
    run here -- its outputs are the ``\\x44``/``\\x55`` constants below, chosen
    for shape only. This test is about the streaming path, so that substitution
    is deliberate; ``test_real_fairplay_material_crosses_into_session`` is the
    one that puts genuine ``fairplay_sap`` output through the same session.
    """
    # Screen audio: AAC-ELD frames over UDP/RTP, AES-128-CBC keyed from
    # raw16 + the media pair-verify shared secret. Off by default in
    # production, so it has to be switched on explicitly here.
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
        # Open the control connection
        connection = await http_connect(host, port)

        # Run the real MFiSAP handshake against the fake
        sm = await fairplay.run_handshake(connection)
        assert receiver.fp_setup_received
        assert receiver.auth_setup_received

        # Build the session context with the handshake's stream encryptor
        rtsp = RtspSession(connection)
        ctx = MirrorContext(stream_encryptor=sm.stream_encryptor)
        # A FairPlay-wrapped stream key is transported in the SETUP body and
        # the video is keyed from the raw16 it wraps. The fake receiver does
        # not unwrap it, but supplying both exercises the real key-transport
        # and key-derivation code paths.
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

        # Drive the session until the receiver has counted enough video writes.
        #
        # asyncio.sleep is stubbed repo-wide (tests/conftest.py) to yield
        # instead of sleeping, so the pacers run as fast as the event loop
        # allows. That makes wall-clock waiting both useless and unreliable —
        # instead the fake receiver sets an event on the Nth frame and we wait
        # on that. GUARD_TIMEOUT only bounds a hang; it is not a pacing knob.
        run_task = asyncio.create_task(sess.run())
        wait_frames = asyncio.ensure_future(
            receiver.video_server.wait_frames(
                REQUIRED_VIDEO_FRAMES, timeout=GUARD_TIMEOUT
            )
        )
        # If run() dies (e.g. a refused connection) surface that error rather
        # than waiting out the guard timeout on an event that can never fire.
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

        # Teardown must mean teardown: no sync packets after stop(). The
        # screen-audio sender runs on its own task, so this is the only
        # thing that catches it outliving the session. Twenty event-loop
        # turns is far more than the one-turn-per-frame a runaway sender
        # needs (asyncio.sleep is stubbed to a plain yield).
        settled = receiver.audio_control_server.frames_received
        for _ in range(20):
            await asyncio.sleep(0)
        assert (
            receiver.audio_control_server.frames_received == settled
        ), "screen-audio sender still running after stop()"

        # Assertions on the receiver state.
        # Every captured constant in the SETUP bodies still matches the wire
        # capture -- see fake_receiver.CAPTURED_* for the values and why the
        # receiver cares about each one.
        receiver.assert_protocol_ok()
        # Modern mirroring sends no ANNOUNCE/SDP.
        assert not receiver.announce_received, "ANNOUNCE must not be sent"
        # The reference sender opens with the type-96 audio SETUP (which
        # carries the eventPort) and has no metadata-only session init.
        assert receiver.audio_setup_received, "audio SETUP not received"
        assert not receiver.session_setup_received
        # The event channel is bidirectional RTSP with the receiver as the
        # client. A sender that leaves POST /command unanswered gets the
        # session torn down after ~30 s, so check we replied 200.
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
        # And we actually saw bytes
        assert receiver.video_server.bytes_received > 0
        assert receiver.audio_data_server.bytes_received > 0
        # The 0xD4 sync packet is what makes the receiver schedule audio
        # at all; it is a 20-byte RAOP SyncPacket with PT 84.
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
    """Genuine ``fairplay_sap`` output must survive transport into a session.

    The seam between the two halves of mirroring had no test. The FairPlay SAP
    handshake is verified in depth on its own (``test_fairplay_sap.py``: 256
    golden vectors, plus the exactness tier under ``examples/mirror_pyfply``),
    and the streaming path is verified on its own (the MVP test above). But the
    MVP test feeds the session ``\\x44``-filled constants where a handshake's
    ``ekey``/``raw16`` belong, so nothing ever checked that real handshake
    output is *shaped and placed* the way the session expects. A disagreement
    there -- an ``ekey`` of the wrong length, a context field written by one
    half and read differently by the other, a ``raw16`` that is fine in
    isolation and wrong once transported -- would leave both halves green.

    So: run the real handshake on a recorded receiver ``M2``, put its real
    outputs into a real :class:`MirrorSession`, and check they arrive intact on
    the wire and in the key derivation.

    What this deliberately does *not* check is whether the values are
    cryptographically *right*. The fake receiver has no FairPlay receiver half,
    so it cannot unwrap an ``ekey``; only a real Apple TV can say the key is
    correct. Value-correctness is what the golden vectors cover. This test
    covers placement and transport, which they do not.
    """
    with GOLDEN_VECTORS.open(encoding="utf-8") as fh:
        vector = json.loads(fh.readline())
    m2 = bytes.fromhex(vector["m2"])
    raw16 = bytes.fromhex(vector["raw16"])

    # The real FPLY v3 sender handshake: no emulator, no constants. `m2` is a
    # genuine receiver message, so `ekey`/`raw16` below are what a live session
    # against a real Apple TV would carry.
    sap36, tag, _context, ekey = fairplay_sap.handshake(m2, raw16)
    # Shapes are the seam's actual contract: the session transports `ekey`
    # whole and indexes the context at [8:44] (and raw16 at [8:24]), so a wrong
    # length here is exactly the class of bug this test exists to catch.
    assert len(sap36) == 36, len(sap36)
    assert len(tag) == 20, len(tag)
    assert len(ekey) == 72, len(ekey)
    # Cross-check against the recorded handshake, so a regression in
    # `fairplay_sap` fails here as a wrong value and not merely a wrong shape.
    assert ekey.hex() == vector["ekey"]

    pair32 = bytes.fromhex("66" * 32)

    # Record what the session's video-key derivation is actually handed. The
    # derived key never reaches the context (it stays a local in `_stream`), so
    # spying on the call is the only way to see the raw16 arrive. The wrapper
    # calls through, so the real derivation still runs.
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
        # The seam: real handshake outputs, in the fields the session reads.
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

        # Same deterministic wait as the MVP test: the fake signals the Nth
        # frame, so nothing here depends on wall-clock time.
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

        # 1. The real ekey reached the wire byte-for-byte, in both stream
        #    SETUPs. This is the transport half of the seam: 72 bytes of real
        #    FairPlay output, unmodified, in the field the receiver reads.
        receiver.assert_protocol_ok()
        assert receiver.video_setup_ekey == ekey, "video SETUP ekey altered in transit"
        assert receiver.video_setup_et == 32
        assert receiver.audio_setup_ekey == ekey, "audio SETUP ekey altered in transit"
        # The eiv beside it is sender-chosen random (the video IV itself comes
        # from raw16), so only its shape is fixed. The audio one is retained on
        # the context for the screen-audio sender, so that one can be matched.
        assert len(receiver.video_setup_eiv) == 16, receiver.video_setup_eiv
        assert receiver.audio_setup_eiv == ctx.audio_eiv

        # 2. The context the session carries really holds the SAP secret where
        #    the session's fallback path indexes for it ([8:44] -> raw16 at
        #    [8:24]). This is the field-placement half of the seam.
        assert len(ctx.sap_context) == 276
        assert ctx.sap_context[8:44] == sap36

        # 3. The real raw16 -- not a constant -- is what the video key was
        #    derived from, with the streamConnectionID actually negotiated.
        assert derivations, "video key derivation never ran"
        (d_raw16, d_pair32, d_sid), _kwargs, (key, iv) = derivations[0]
        assert d_raw16 == raw16, "session keyed video from something other than raw16"
        assert d_pair32 == pair32
        assert d_sid == ctx.stream_connection_id
        assert (key, iv) == real_derive(raw16, pair32, ctx.stream_connection_id)
        # The old constant would have produced a different key, so this test
        # would not have passed with the placeholder it replaces.
        assert key != real_derive(b"\x55" * 16, pair32, ctx.stream_connection_id)[0]

        # 4. And with all of that real material, the session still streams.
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
