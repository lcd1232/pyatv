"""The captured constants in the mirror SETUP bodies.

``session.py`` builds two SETUP plists whose values came off the wire from a
real sender talking to a real tvOS 26 receiver -- ``latencyMin``/``Max``
3750, ``redundantAudio`` 2, ``ct`` 8, ``audioFormat`` 0x1000000, ``et`` 32,
and the five ``timestampInfo`` probe names.
The receiver *interprets* every one of them, but
:class:`~tests.protocols.airplay.mirror.fake_receiver.FakeMirrorReceiver`
only dispatches on ``streams[0]["type"]`` and answers 200 to whatever else
arrives, so before ``fake_receiver.check_audio_setup`` /
``check_video_setup`` existed any of these could be changed with the whole
suite staying green.

Those checks run inside the fake on every SETUP it receives, which is what
makes a changed constant fail the tests that already drive a session. This
module is the guard on the guard. It pins:

  * that the checks actually ran against a live session's bodies, so they
    cannot rot into being skipped, and
  * that they reject each individual captured constant being changed --
    driving one real session and then mutating a copy of the body it sent,
    one key at a time. A check that compared nothing would pass silently.

The per-session values (``streamConnectionID``, ``sessionUUID``, ports,
``deviceID``) are deliberately *not* pinned to literals anywhere: they are
regenerated every run. They are checked for shape only, and the shape checks
are exercised here too.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import pathlib
import plistlib
import struct

import pytest

from pyatv.protocols.airplay.mirror import (
    fairplay,
    fply,
    framing,
    pacer,
    screen_audio,
)
from pyatv.protocols.airplay.mirror import (
    tcp_stream,
)
from pyatv.protocols.airplay.mirror import session as session_mod
from pyatv.protocols.raop.packets import TimingPacket
from pyatv.support import http

from tests.protocols.airplay.mirror import fake_receiver
from tests.protocols.airplay.mirror.test_session_error_paths import (
    GUARD_TIMEOUT,
    driven_session,
    stream_then_stop,
)

pytestmark = pytest.mark.asyncio


async def _captured_bodies(monkeypatch):
    """Run one real session to steady state and return its SETUP bodies."""
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        return receiver.audio_setup_body, receiver.video_setup_body


async def test_the_checks_run_against_a_live_session(monkeypatch):
    """A real session's SETUPs reach the checks and satisfy them.

    Recording the bodies is what proves the checks were reached at all: an
    empty ``protocol_violations`` list is equally consistent with the checks
    having been dropped from ``_dispatch_setup``.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

        assert receiver.audio_setup_body is not None, "audio SETUP never checked"
        assert receiver.video_setup_body is not None, "video SETUP never checked"
        assert receiver.protocol_violations == []


#: Every captured constant of the type-96 audio SETUP, with a value that is
#: wrong in the way a typo or a "tidied" magic number would be wrong. The
#: comment on each is why the receiver cares; see ``fake_receiver.CAPTURED_*``
#: for the provenance of the correct value.
AUDIO_CONSTANT_MUTATIONS = [
    # 85 ms of jitter buffer at 44.1 kHz. Off-by-one here is exactly the kind
    # of change nothing else would notice.
    (["streams", 0, "latencyMin"], 3751),
    (["streams", 0, "latencyMax"], 3751),
    # 2x redundancy; the receiver de-duplicates on this factor.
    (["streams", 0, "redundantAudio"], 3),
    # Compression type 8 == AAC-ELD, the codec we actually packetize.
    (["streams", 0, "ct"], 9),
    # Format bitfield naming the same AAC-ELD 44100/2 entry as ``ct``.
    (["streams", 0, "audioFormat"], 0x1000001),
    # Marks the stream as a mirroring soundtrack; the video SETUP depends on
    # the receiver having accepted it as one.
    (["streams", 0, "usingScreen"], False),
    # Screen audio, not screen video.
    (["streams", 0, "type"], 97),
    # Samples per AAC-ELD frame; also the RTP timestamp step.
    (["streams", 0, "spf"], 481),
    # FairPlay SAP v3, which is the keying the ekey beside it belongs to.
    (["et"], 33),
]

#: The per-session fields of the audio SETUP, replaced with a malformed value
#: rather than a different one. These must never be pinned to a literal.
AUDIO_SHAPE_MUTATIONS = [
    # The receiver stores this in a 32-bit field and rebuilds the video
    # key-derivation label from it, so a 63-bit value would silently
    # mis-key the stream.
    (["streams", 0, "streamConnectionID"], 2**40),
    # The receiver sends audio sync packets here; port 0 is not bound.
    (["streams", 0, "controlPort"], 0),
    # Real senders send an upper-case UUID and index the session by it.
    (["sessionUUID"], "not-a-uuid"),
    (["deviceID"], "nope"),
    (["macAddress"], "nope"),
    (["timingPort"], 0),
    (["name"], ""),
    (["model"], ""),
    (["osBuildVersion"], ""),
    (["sourceVersion"], ""),
    # et=32 promises a FairPlay-wrapped key and a 16-byte IV are present.
    (["eiv"], b"\x00" * 8),
]


def _with(body: dict, path: list, value) -> dict:
    """Return a copy of ``body`` with the value at ``path`` replaced."""
    mutated = copy.deepcopy(body)
    target = mutated
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return mutated


@pytest.mark.parametrize(
    "path,bad",
    AUDIO_CONSTANT_MUTATIONS + AUDIO_SHAPE_MUTATIONS,
    # repr() of a bytes value can contain spaces, which makes the generated
    # id impossible to pass back to pytest on a command line.
    ids=lambda p: (
        ".".join(str(s) for s in p)
        if isinstance(p, list)
        else repr(p).replace(" ", "_")
    ),
)
async def test_audio_setup_check_rejects_each_field(monkeypatch, path, bad):
    """Changing any one checked field of a real audio SETUP is reported.

    The body is the one a live session actually sent, so this also pins that
    the sender still sends every field the check looks for -- a field renamed
    in ``session.py`` would make the unmutated body fail first.
    """
    audio_body, _ = await _captured_bodies(monkeypatch)

    assert fake_receiver.check_audio_setup(audio_body) == []

    problems = fake_receiver.check_audio_setup(_with(audio_body, path, bad))
    assert problems, f"changing {'.'.join(str(s) for s in path)} was not noticed"
    assert path[-1] in " ".join(problems), problems


#: The type-110 video SETUP.
VIDEO_TCP_MUTATIONS = [
    (["streams", 0, "type"], 111),
    # FairPlay SAP v3 keying for the screen video.
    (["et"], 33),
    (["streams", 0, "streamConnectionID"], 2**40),
    (["sessionUUID"], "not-a-uuid"),
]


async def test_video_setup_check_rejects_each_field(monkeypatch):
    """Changing any one checked field of a real video SETUP is reported.

    One live session for all of them: running one per parametrized field
    would pay for a full handshake per assertion.
    """
    _, video_body = await _captured_bodies(monkeypatch)

    assert fake_receiver.check_video_setup(video_body) == []

    for path, bad in VIDEO_TCP_MUTATIONS:
        mutated = _with(video_body, path, bad)
        problems = fake_receiver.check_video_setup(mutated)
        assert problems, f"changing {'.'.join(str(s) for s in path)} was not noticed"
        assert path[-1] in " ".join(problems), (path, problems)


async def test_video_setup_check_rejects_a_changed_timestamp_probe(monkeypatch):
    """The five ``timestampInfo`` probe names are ordered and captured.

    They label the latency timestamps the receiver reports back, so a renamed
    or reordered probe is a protocol change, not a cosmetic one.
    """
    _, video_body = await _captured_bodies(monkeypatch)

    names = [entry["name"] for entry in video_body["streams"][0]["timestampInfo"]]
    assert names == fake_receiver.CAPTURED_TIMESTAMP_NAMES

    renamed = copy.deepcopy(video_body)
    renamed["streams"][0]["timestampInfo"][-1]["name"] = "XXXXX"
    assert fake_receiver.check_video_setup(renamed)

    reordered = copy.deepcopy(video_body)
    reordered["streams"][0]["timestampInfo"].reverse()
    assert fake_receiver.check_video_setup(reordered)


async def test_a_missing_captured_constant_is_reported_as_missing(monkeypatch):
    """A dropped key must not read as "nothing to compare, so fine"."""
    audio_body, _ = await _captured_bodies(monkeypatch)

    without_ct = copy.deepcopy(audio_body)
    del without_ct["streams"][0]["ct"]

    problems = fake_receiver.check_audio_setup(without_ct)
    assert any("ct missing" in problem for problem in problems), problems


async def test_the_inlined_audio_constants_still_match_the_tested_helper(monkeypatch):
    """`session.py` inlines what `screen_audio` already returns.

    `screen_audio.audio_setup_stream_params` is the documented source of
    the AAC-ELD stream parameters and is pinned by
    `test_screen_audio.py::test_setup_params_match_tcp`.  `session.py`
    does not call it -- it writes the same keys out by hand -- so the tested
    helper and the live path are free to drift, and mutation showed they had
    no shared guard: changing the inlined `ct` left the helper's test green.

    They agree today.  This is the check that says so, against the body an
    actual session put on the wire rather than against a re-typed copy, so it
    fails whichever of the two moves.  `controlPort` is per-session and
    rightly absent from a constants helper, so it is excluded.
    """
    audio_body, _ = await _captured_bodies(monkeypatch)
    sent = dict(audio_body["streams"][0])
    expected = screen_audio.audio_setup_stream_params(sent["streamConnectionID"])

    assert set(expected) <= set(sent), set(expected) - set(sent)
    assert set(sent) - set(expected) == {"controlPort"}, set(sent) - set(expected)
    for name, value in expected.items():
        assert sent[name] == value, name
        assert type(sent[name]) is type(value), name  # noqa: E721 - bool vs int


async def test_both_tcp_setups_agree_on_who_this_session_is(monkeypatch):
    """One session identity, repeated verbatim across both stream SETUPs.

    In the TCP dialect ``sessionUUID``/``deviceID``/``macAddress`` go out
    in the audio SETUP and again in the video SETUP, because the receiver ties
    both streams back to one session by them.  Nothing checked that the second
    copy matches the first.

    Both sites read the UUID as
    ``getattr(self, "_session_uuid", None) or str(uuid4()).upper()`` -- so if
    ``_session_uuid`` is ever unset, each SETUP mints a *different* identity
    and the two streams claim to belong to different sessions.  That shared
    fallback is what this test is aimed at.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        audio, video = receiver.audio_setup_body, receiver.video_setup_body

    assert audio is not None and video is not None

    for key in ("sessionUUID", "deviceID", "macAddress"):
        assert key in audio, f"audio SETUP lost {key}"
        assert key in video, f"video SETUP lost {key}"
        assert audio[key] == video[key], (key, audio[key], video[key])


async def test_a_caller_supplied_device_identity_is_what_goes_on_the_wire(monkeypatch):
    """``ctx.device_id``/``ctx.mac_address`` override the derived defaults.

    Both are read as ``self._ctx.device_id or _device_id_from_uuid(...)``, so
    the configured value is used only when it is truthy.  Every other test
    leaves them unset and gets the derived form, which means the left-hand
    side of both ``or``s was never exercised: dropping it entirely, and always
    deriving, passed.

    A sender that cannot present a chosen MAC is a real problem -- receivers
    remember paired devices by it.
    """
    device_id, mac_address = "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"
    async with driven_session(
        monkeypatch,
        ctx_overrides={"device_id": device_id, "mac_address": mac_address},
    ) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        audio, video = receiver.audio_setup_body, receiver.video_setup_body

    for name, body in (("audio", audio), ("video", video)):
        assert body["deviceID"] == device_id, (name, body["deviceID"])
        assert body["macAddress"] == mac_address, (name, body["macAddress"])


class _RecordingEncryptor:
    """Stands in for a caller-supplied video encryptor and counts its use."""

    key = b"\xaa" * 16
    iv = b"\xbb" * 16

    def __init__(self):
        self.calls = 0

    def encrypt(self, data: bytes) -> bytes:
        self.calls += 1
        return bytes(b ^ 0xFF for b in data)


@pytest.mark.parametrize("with_raw16", [True, False])
async def test_a_caller_supplied_video_encryptor_is_the_one_used(
    monkeypatch, with_raw16
):
    """``ctx.video_encryptor`` outranks the derived encryptor in every path.

    ``_stream_until_done`` promises ``self._ctx.video_encryptor or encryptor``
    and then, when a FairPlay keybuf encryptor could be built, reassigned over
    the top of it -- so in the *shipping* configuration (raw16 present) a
    caller-supplied encryptor was silently dropped.

    Both parametrisations run because the bug lived in exactly one of them; a
    test that happened to pick the other would have passed against it.
    """
    encryptor = _RecordingEncryptor()
    async with driven_session(
        monkeypatch,
        with_raw16=with_raw16,
        ctx_overrides={"video_encryptor": encryptor},
    ) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    assert encryptor.calls > 0, "the caller's encryptor never encrypted a frame"


async def test_one_session_presents_exactly_two_airplay_versions(monkeypatch):
    """The handshake and the session identify the sender differently.

    Measured on one session of the reference sender: ``/fp-setup`` and ``/auth-setup``
    go out as ``AirPlay/550.10`` and every RTSP request as ``AirPlay/870.14.1``, on the
    same connection. ``session.py`` explains its half --

        The Apple TV only offers screen mirroring to senders advertising a
        recent AirPlay version. pyatv's default (AirPlay/550.10) is iOS-12
        era

    -- which makes the handshake's half the older, gated one.  Mirroring does
    work on tvOS 26, so the receiver evidently does not gate on the handshake
    requests; this test records that the split is real and deliberate rather
    than pinning it as correct.  If the two are ever unified, this test is
    where to say so.

    What it does guard is ``fairplay.USER_AGENT == fply.USER_AGENT``.  Those
    are two implementations of the same handshake step -- MFiSAP and FPLY v3
    -- and each defines the constant itself, so bumping one and not the other
    would have a session identify itself differently depending on which
    handshake it ran, with nothing to catch it.
    """
    assert (
        fairplay.USER_AGENT == fply.USER_AGENT
    ), "the two handshake modules disagree on how to identify this sender"

    seen: list[tuple[str, str | None]] = []
    real = http.HttpConnection.send_and_receive

    async def spy(self, method, uri, *args, **kwargs):
        seen.append((uri, kwargs.get("user_agent")))
        return await real(self, method, uri, *args, **kwargs)

    monkeypatch.setattr(http.HttpConnection, "send_and_receive", spy)
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    handshake = {ua for uri, ua in seen if not uri.startswith("rtsp://")}
    rtsp = {ua for uri, ua in seen if uri.startswith("rtsp://")}
    assert handshake, "no handshake request was observed"
    assert rtsp, "no RTSP request was observed"

    assert handshake == {fairplay.USER_AGENT}, handshake
    assert rtsp == {session_mod.MIRROR_USER_AGENT}, rtsp


async def _sockets_at_stop(monkeypatch):
    """Run a session and return the raw sockets it held when stop() ran.

    stop() drops the references as it closes them, and it is called twice --
    once by stream_then_stop and again by driven_session on the way out --
    so only the first call sees anything. Reading the attributes afterwards
    finds None and proves nothing.

    There is a second reason not to look later, and it is the more dangerous
    one: by the time the session's context manager has exited, the loop and
    the transports have reclaimed those descriptors anyway. A version of this
    check written after the ``async with`` reports zero open sockets whether
    the fix is present or not -- measured, by removing the fix and watching it
    still pass. The leak is only observable at the moment stop() returns,
    which is exactly the moment that matters to a process holding sessions
    open.
    """
    captured = {}

    async with driven_session(monkeypatch) as (receiver, sess):
        real_stop = sess.stop

        async def capturing_stop():
            if not captured:
                captured["_audio_control_sock"] = (
                    sess._audio_control_sock  # noqa: SLF001
                )
            await real_stop()

        sess.stop = capturing_stop
        await stream_then_stop(receiver, sess)

    assert captured, "stop() was never called"
    return captured


async def test_stop_closes_the_raw_sockets_it_opened(monkeypatch):
    """No file descriptor outlives a session.

    One of the session's sockets is not a transport: ``_audio_control_sock``
    is never wrapped at all; it is used for bare ``sendto``.

    A leaked UDP descriptor per session only shows up after a long-running
    process has mirrored a few thousand times.
    """
    captured = await _sockets_at_stop(monkeypatch)

    raw = {k: captured[k] for k in ("_audio_control_sock",)}
    assert all(
        sock is not None for sock in raw.values()
    ), f"expected the raw socket to be open at stop(): {raw}"

    still_open = [name for name, sock in raw.items() if sock.fileno() != -1]
    assert not still_open, f"still open after stop(): {still_open}"


async def test_stop_returns_only_once_every_task_is_finished(monkeypatch):
    """``stop()`` must not return while a task it started is still running.

    ``stop()`` cancels and awaits ``self._tasks``.  ``_stream_until_done``
    adds the producers and pacers to that list, which ``run()`` and
    ``_open_event_channel()`` have already put the screen-audio sender and
    the event-channel responder in.  The code carries a comment saying to
    EXTEND the list and never replace it, because assigning drops the earlier
    two -- ``stop()`` then never awaits them and they wind down off the
    ``_stopped`` flag instead, which the comment itself calls luck.

    Checking for pending tasks *after* ``stop()`` is too weak to see that:
    the orphans do finish, a loop turn or two later, so a check that sleeps
    first passes either way.  The property with teeth is that they are done
    the moment ``stop()`` returns -- that is the difference between awaited
    and merely lucky.

    What this does NOT pin is the ``await`` in ``stop()``'s cancel loop.
    Removing it still passes, because the TEARDOWN request that follows
    yields to the loop and lets the cancellations settle anyway.  That is a
    real near-equivalence, not a gap this test can close: the two versions
    differ only if TEARDOWN stops awaiting.  Removing the ``cancel()``
    instead deadlocks ``stop()``, which CI's ``--timeout=30`` catches.
    """
    before = set(asyncio.all_tasks())
    outcome = {}

    async with driven_session(monkeypatch) as (receiver, sess):
        real_stop = sess.stop

        def _is_the_sessions(task):
            # The fake receiver runs connection handlers of its own; this is
            # about what MirrorSession started, so match on where the
            # coroutine is defined rather than on when the task appeared.
            coro = task.get_coro()
            code = getattr(coro, "cr_code", None) or getattr(coro, "gi_code", None)
            return code is not None and "airplay/mirror/session.py" in code.co_filename

        async def capturing_stop():
            started = {
                t
                for t in asyncio.all_tasks() - before - {asyncio.current_task()}
                if _is_the_sessions(t)
            }
            await real_stop()
            if "unfinished" not in outcome:
                outcome["started"] = started
                outcome["unfinished"] = [t for t in started if not t.done()]

        sess.stop = capturing_stop
        await stream_then_stop(receiver, sess)

    assert "unfinished" in outcome, "stop() was never called"
    assert outcome["started"], "no session task was running -- nothing was checked"
    assert not outcome[
        "unfinished"
    ], "still running when stop() returned: " + ", ".join(
        f"{t.get_name()} ({t.get_coro().__qualname__})" for t in outcome["unfinished"]
    )


async def test_which_requests_still_carry_the_raop_remote_control_headers(
    monkeypatch,
):
    """``_SUPPRESS_RAOP_HEADERS`` is applied to SETUP but not RECORD/TEARDOWN.

    ``RtspSession`` adds ``DACP-ID``/``Active-Remote``/``Client-Instance`` to
    every request, and ``session.py`` suppresses them by passing each as
    ``None``.  The constant's comment says why: *the macOS sender captured in
    Phase 28 sends none of them on a mirroring session*.

    It is passed to both SETUPs and to neither RECORD nor TEARDOWN, so
    those two still carry all three -- narrower than the stated ground truth.
    Mirroring works on tvOS 26 regardless, so this pins what is actually sent
    rather than asserting what ought to be; closing the gap changes what a
    real device receives, and that wants hardware to confirm.

    ``record()`` already takes a ``headers`` argument, so it is one line.
    ``teardown()`` hardcodes ``{"Session": ...}`` and would need an
    ``rtsp.py`` signature change.  If either is fixed, this test is where to
    say so.
    """
    raop_headers = {"DACP-ID", "Active-Remote", "Client-Instance"}
    seen: dict = {}
    real = http.HttpConnection.send_and_receive

    async def spy(self, method, uri, *args, **kwargs):
        seen.setdefault(method, set()).update(
            raop_headers & set(kwargs.get("headers") or {})
        )
        return await real(self, method, uri, *args, **kwargs)

    monkeypatch.setattr(http.HttpConnection, "send_and_receive", spy)
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    assert seen.get("SETUP") == set(), f"SETUP leaked RAOP headers: {seen.get('SETUP')}"
    assert (
        seen.get("POST") == set()
    ), f"/fp-setup leaked RAOP headers: {seen.get('POST')}"

    # Documented gap, not an endorsement: these two still send all three.
    assert seen.get("RECORD") == raop_headers, seen.get("RECORD")
    assert seen.get("TEARDOWN") == raop_headers, seen.get("TEARDOWN")


async def test_the_config_frame_carries_the_sources_own_sps_and_pps(monkeypatch):
    """The plaintext avcC must describe the H.264 actually being streamed.

    ``tcp_video_producer`` picks the SPS and PPS out of the source file
    by NAL type -- ``nal_type(n) == 7`` and ``== 8`` -- and hands them to
    ``build_avcc_config``. That record is the first thing on the data channel
    and is what the receiver initialises its decoder from; a wrong one is a
    black screen with a healthy-looking session, which is the failure mode
    this project has already been bitten by.

    ``build_avcc_config`` is unit-tested, but nothing checked that the
    producer feeds it the right NALs: inverting either selector to ``!= 7``
    picked some other NAL and no test noticed, because the fake counted the
    bytes on the data port without keeping them.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        head = receiver.video_server.head
        source = pathlib.Path(sess._h264_path).read_bytes()  # noqa: SLF001

    assert head, "nothing was retained from the data channel"

    # First message: 128-byte TCP-dialect header, then the avcC record.
    avcc = head[128:]
    assert avcc[0] == 0x01, f"not an avcC record: {avcc[:8].hex()}"

    nalus = pacer.split_nalus(source)
    want_sps = next(n for n in nalus if pacer.nal_type(n) == 7)
    want_pps = next(n for n in nalus if pacer.nal_type(n) == 8)

    sps_len = int.from_bytes(avcc[6:8], "big")
    sent_sps = avcc[8 : 8 + sps_len]
    rest = avcc[8 + sps_len :]
    pps_len = int.from_bytes(rest[1:3], "big")
    sent_pps = rest[3 : 3 + pps_len]

    assert sent_sps == want_sps, "config frame carries the wrong SPS"
    assert sent_pps == want_pps, "config frame carries the wrong PPS"
    # The profile bytes are lifted out of the SPS, so they must agree with it.
    assert avcc[1:4] == want_sps[1:4], "avcC profile/level disagrees with the SPS"


async def test_encrypted_frames_carry_no_sps_or_pps(monkeypatch):
    """The reference sender's video frames are [SEI][slice]; the parameter sets are not.

    ``tcp_video_producer`` strips NAL types 7 and 8 from every frame
    because the reference sender transports them only once, plaintext, in the avcC
    config.  Not stripping them sends the parameter sets inside the encrypted
    frames too, giving the receiver's decoder a structure no real sender
    produces, and nothing noticed.

    The frames are encrypted, but AES-CTR preserves length, so the payload
    size on the wire settles it without needing the key: a stripped access
    unit is exactly SPS + PPS + their two length prefixes shorter than an
    unstripped one.  Asserting both -- equal to one, different from the other
    -- is what makes it a real check rather than an arithmetic coincidence.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess, video_frames=3)
        head = receiver.video_server.head
        source = pathlib.Path(sess._h264_path).read_bytes()  # noqa: SLF001

    messages = []
    offset = 0
    while offset + 128 <= len(head):
        length = struct.unpack_from("<I", head, offset)[0]
        messages.append((head[offset + 4 : offset + 8].hex(), length))
        offset += 128 + length

    assert len(messages) >= 2, f"expected a config frame and a video frame: {messages}"
    assert messages[0][0] == "01000600", "first message is not the avcC config"
    frame_type, frame_len = messages[1]
    assert (
        frame_type == "00000600"
    ), f"second message is not a video frame: {frame_type}"

    nalus = pacer.split_nalus(source)
    without = [n for n in nalus if pacer.nal_type(n) not in (7, 8)]
    stripped = len(
        tcp_stream.to_avcc(tcp_stream.group_access_units(without, pacer.nal_type)[0])
    )
    unstripped = len(
        tcp_stream.to_avcc(tcp_stream.group_access_units(nalus, pacer.nal_type)[0])
    )
    assert stripped != unstripped, "this source has no SPS/PPS to strip"

    assert frame_len == stripped, (
        f"frame is {frame_len} bytes; a stripped access unit is {stripped} "
        f"and one still carrying SPS/PPS would be {unstripped}"
    )


@pytest.mark.parametrize("fps", [30, 15])
async def test_frame_timestamps_advance_at_the_frame_rate(monkeypatch, fps):
    """Consecutive frames are stamped exactly one frame interval apart.

    ``tcp_video_producer`` stamps frame *n* at
    ``ts_base + n * (1_000_000_000 // fps)`` nanoseconds, in the header's
    little-endian u64 at offset 8.  The receiver plays back off those
    timestamps, so an interval in the wrong unit -- microseconds, or a
    hard-coded 30 against a different ``fps`` -- is a stream that plays at
    the wrong speed while every byte of it decodes.

    Nothing asserted them.  This reads the stamps off the wire rather than
    timing anything, so it says nothing about how fast frames were actually
    sent; the schedule is what the receiver acts on, and it is exactly
    checkable.

    Two rates run because the default is 30: a hard-coded 30 in place of
    ``self._ctx.fps`` is indistinguishable at the default and obvious at 15.
    """
    async with driven_session(monkeypatch, ctx_overrides={"fps": fps}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=4)
        head = receiver.video_server.head
        assert sess._ctx.fps == fps  # noqa: SLF001

    stamps = []
    offset = 0
    while offset + 128 <= len(head):
        length = struct.unpack_from("<I", head, offset)[0]
        if head[offset + 4 : offset + 8].hex() == "00000600":  # video, not config
            stamps.append(struct.unpack_from("<Q", head, offset + 8)[0])
        offset += 128 + length

    assert len(stamps) >= 3, f"need several video frames to compare: {len(stamps)}"

    expected = 1_000_000_000 // fps
    deltas = [b - a for a, b in zip(stamps, stamps[1:])]
    assert set(deltas) == {
        expected
    }, f"frame interval should be {expected} ns at {fps} fps; saw {sorted(set(deltas))}"


async def test_screen_audio_sends_rtp_packets_for_each_eld_frame(monkeypatch, tmp_path):
    """The screen-audio sender end to end, from an ELD file.

    One assertion here earns its place, and it is not the RTP framing.
    ``test_screen_audio`` already unit-tests the packetiser, so the
    payload-type, sequence and timestamp checks below are caught there too --
    measured, by running those mutations against the suite with this test
    deselected.  They stay because they describe what the packets should look
    like at the point they actually reach a socket, but they are not why this
    exists.

    The sync's *source port* is.  ``_stream_screen_audio``'s docstring calls
    it the detail that decides whether audio plays at all: the packet has to
    leave from the socket whose port was advertised as ``controlPort``, or the
    receiver never opens its audio control channel.  Disabling that send still
    delivers a sync here, because the code falls through to a second socket --
    so nothing but the source port distinguishes the two, and nothing else in
    the suite catches it.

    AES-CBC encrypts whole blocks and passes the remainder through, so payload
    length is preserved and each packet is its source frame's length.
    """
    frames = [bytes([0x20 + i]) * (48 + i) for i in range(5)]
    eld = tmp_path / "frames.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))

    async with driven_session(monkeypatch, session_kwargs={"eld_path": eld}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=3)
        packets = list(receiver.audio_data_server.datagrams)
        syncs = list(receiver.audio_control_server.datagrams)
        sync_sources = list(receiver.audio_control_server.sources)
        spf = receiver.audio_setup_body["streams"][0]["spf"]
        advertised = receiver.audio_setup_body["streams"][0]["controlPort"]

    assert packets, "no screen audio reached the type-96 data port"
    assert syncs, "no sync packet reached the audio control port"

    # The method's docstring calls this the detail that decides whether audio
    # plays at all: the sync has to leave from the socket whose port was
    # advertised as controlPort, or the receiver never opens its audio control
    # channel. Sending it from any other socket still delivers a packet here,
    # so only the source port tells the two apart.
    assert sync_sources[0][1] == advertised, (
        f"sync came from port {sync_sources[0][1]}, but controlPort "
        f"{advertised} was advertised"
    )

    for index, packet in enumerate(packets):
        version_pt = packet[0]
        payload_type = packet[1]
        assert version_pt == 0x80, f"packet {index}: RTP version byte {version_pt:#04x}"
        assert payload_type == 0x60, f"packet {index}: payload type {payload_type:#04x}"

    seqs = [struct.unpack_from(">H", p, 2)[0] for p in packets]
    assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), seqs

    stamps = [struct.unpack_from(">I", p, 4)[0] for p in packets]
    deltas = {b - a for a, b in zip(stamps, stamps[1:])}
    assert deltas == {spf}, f"timestamps advance by {deltas}, SETUP announced {spf}"

    # One packet per source frame, in order, with lengths preserved.
    sent = [len(p) - 12 for p in packets]
    assert sent == [len(f) for f in frames][: len(sent)], sent


async def test_the_announced_timing_port_is_actually_served(monkeypatch):
    """A timing request sent to the advertised port must get an answer.

    Advertising a port nothing listens on is this project's most expensive
    historical bug: the Apple TV stalls silently at SETUP, with no error and
    no ICMP to explain it, which is what made it take five phases to find.
    The fix was to run a real ``TimingServer`` and announce *its* port.

    Nothing checked the announcement against the server. The fake's guard
    says "timingPort is not a bound UDP port" but only tests ``0 < port <
    65536``, so any non-zero number passes -- including one nothing is
    listening on, which is precisely the failing case.

    This sends a real timing request to the advertised port and waits for the
    reply, so it fails for a wrong port, a closed server, or a server that
    stops answering. It runs against a live session because ``stop()`` closes
    the timing server; querying afterwards raises instead of failing.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            await asyncio.wait_for(
                receiver.video_server.wait_frames(2, timeout=GUARD_TIMEOUT),
                timeout=GUARD_TIMEOUT,
            )

            announced = receiver.video_setup_body["timingPort"]
            assert announced == sess._timing_server.port, (  # noqa: SLF001
                f"announced timingPort {announced} is not the server's "
                f"{sess._timing_server.port}"  # noqa: SLF001
            )

            loop = asyncio.get_running_loop()
            answered: asyncio.Future = loop.create_future()

            class _Listener(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not answered.done():
                        answered.set_result(data)

            transport, _ = await loop.create_datagram_endpoint(
                _Listener, remote_addr=("127.0.0.1", announced)
            )
            try:
                transport.sendto(
                    TimingPacket.encode(0x80, 0x52 | 0x80, 7, 0, 0, 0, 0, 0, 1, 2)
                )
                reply = await asyncio.wait_for(answered, timeout=GUARD_TIMEOUT)
            finally:
                transport.close()

            assert len(reply) == 32, f"unexpected timing reply: {reply.hex()}"
        finally:
            task.cancel()
            with contextlib.suppress(BaseException):
                await task


async def test_the_announced_stream_id_is_the_one_the_key_is_derived_from(monkeypatch):
    """The receiver keys from the id we announce, so it must be the id we use.

    ``derive_tcp_stream_key_iv`` folds the streamConnectionID into the
    video key, and the Apple TV does the same with the value it read from the
    SETUP.  Announce one id and key from another and every byte still flows:
    the session looks healthy and the screen stays black, which is the failure
    mode this project has spent the most time chasing.

    The two currently come from the same attribute, so they cannot drift by
    accident -- but nothing held them together.  Adding ``+ 1`` to the
    announced id passes the entire suite; the same change on the key side
    fails three tests.  That asymmetry is what this closes.
    """
    used: list = []
    real_derive = framing.derive_tcp_stream_key_iv

    def spy(raw16, pair32, stream_connection_id, *args, **kwargs):
        used.append(stream_connection_id)
        return real_derive(raw16, pair32, stream_connection_id, *args, **kwargs)

    monkeypatch.setattr(framing, "derive_tcp_stream_key_iv", spy)

    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        announced = receiver.video_setup_body["streams"][0]["streamConnectionID"]

    assert used, "the video key was never derived -- nothing was compared"
    assert set(used) == {announced}, (
        f"SETUP announced streamConnectionID {announced}, but the key was "
        f"derived from {sorted(set(used))}"
    )


async def test_the_tcp_request_order_is_the_captured_one(monkeypatch):
    """The TCP flow is a sequence, and the receiver depends on it.

    ``session.py`` records it from an LLDB socket capture: SETUP(audio 96),
    connect the eventPort the audio SETUP returned, RECORD, SETUP(video 110),
    connect the video dataPort.  It also notes that RECORD is only answered
    once the event channel is up -- so the order is not a stylistic choice,
    it is what the receiver waits for.

    Nothing pinned it.  The bodies of each SETUP are checked in detail, and
    the sequence they arrive in was not checked at all, so moving RECORD
    ahead of the audio SETUP -- or sending the video SETUP first -- would
    have gone unnoticed here and failed on a device.

    The audio SETUP is identified by its type-96 stream and the video one by
    type 110, rather than by position, so this fails with a useful message
    rather than an index error if the order changes.
    """
    seen: list = []
    real = http.HttpConnection.send_and_receive

    async def spy(self, method, uri, *args, **kwargs):
        body = kwargs.get("body")
        label = method
        if method == "SETUP":
            # RtspSession has already turned the dict into a binary plist by
            # the time it reaches this layer, so decode it back to tell the
            # audio SETUP from the video one.
            if isinstance(body, (bytes, bytearray)):
                with contextlib.suppress(Exception):
                    body = plistlib.loads(bytes(body))
        if method == "SETUP" and isinstance(body, dict):
            types = {s.get("type") for s in body.get("streams", [])}
            if 96 in types:
                label = "SETUP(audio)"
            elif 110 in types:
                label = "SETUP(video)"
        seen.append(label)
        return await real(self, method, uri, *args, **kwargs)

    monkeypatch.setattr(http.HttpConnection, "send_and_receive", spy)
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    rtsp = [label for label in seen if label != "POST"]
    assert rtsp == ["SETUP(audio)", "RECORD", "SETUP(video)", "TEARDOWN"], rtsp

    # The FairPlay handshake precedes all of it, on the same connection.
    assert seen[:2] == ["POST", "POST"], seen[:4]


async def test_the_handshake_requests_carry_the_apple_headers(monkeypatch):
    """``/fp-setup`` and ``/auth-setup`` must identify themselves as a real
    sender does.

    ``X-Apple-HKP: 3`` selects the HAP pairing generation, and pyatv's own
    server side refuses anything else -- ``server_auth`` checks it explicitly
    -- so a receiver plausibly does too.  Dropping it from either handshake
    request passed the whole suite.

    Like the captured ``/info``, these headers have no effect on anything the
    tests observe: the fake answers regardless.  A structural assertion is the
    only kind that can notice them going missing.
    """
    seen: dict = {}
    real = http.HttpConnection.send_and_receive

    async def spy(self, method, uri, *args, **kwargs):
        if method == "POST":
            seen[uri] = dict(kwargs.get("headers") or {})
        return await real(self, method, uri, *args, **kwargs)

    monkeypatch.setattr(http.HttpConnection, "send_and_receive", spy)
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

    assert set(seen) == {"/fp-setup", "/auth-setup"}, sorted(seen)
    for uri, headers in seen.items():
        assert headers.get("X-Apple-HKP") == "3", f"{uri} sent {headers}"


@pytest.mark.asyncio
async def test_the_periodic_audio_sync_goes_out_once_every_sync_every_frames(
    monkeypatch, tmp_path
):
    """The sync cadence, which the five-frame test above never reaches.

    ``sync_every`` defaults to about a second of audio -- 46 frames at the
    shipped 1024-sample size -- and the test above sends five, so the only
    sync it sees is the opening one and the periodic branch never runs.
    Inverting that branch makes a sync follow nearly every frame instead of
    every 46th, roughly fortyfold the control traffic, and nothing failed.

    ``AUDIO_SYNC_EVERY`` is patched for exactly this, so the cadence
    is checked at three rather than by sending a hundred frames. The count is
    exact rather than approximate: ``idx`` advances once per audio packet and
    the sync fires when it divides, so a run that emitted *n* packets must
    show ``n // 3`` periodic syncs, on top of the opening one.
    """
    frames = [bytes([0x20 + i]) * (48 + i) for i in range(5)]
    eld = tmp_path / "frames.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))

    monkeypatch.setattr(session_mod, "AUDIO_SYNC_EVERY", 3)

    async with driven_session(monkeypatch, session_kwargs={"eld_path": eld}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=3)
        packets = list(receiver.audio_data_server.datagrams)
        syncs = list(receiver.audio_control_server.datagrams)

    assert (
        len(packets) >= 3
    ), "only %d audio packets: too few to reach a periodic sync" % len(packets)
    assert (
        len(syncs) == 1 + len(packets) // 3
    ), "%d packets should give %d periodic syncs plus the opening one, got %d" % (
        len(packets),
        len(packets) // 3,
        len(syncs) - 1,
    )


@pytest.mark.asyncio
async def test_screen_audio_stays_silent_when_half_its_key_is_missing(
    monkeypatch, tmp_path
):
    """Both halves, or nothing. Not either half.

    The audio key is ``sha512(raw16 || pair32)[:16]`` and the guard is
    ``len(raw16) == 16 and pair32``. Written ``or`` it accepts a raw16
    with no pair32 and hashes ``raw16 + b""``, which is a perfectly
    well-formed 16-byte key -- long enough to clear the length check below
    it, and wrong. The receiver would decrypt noise and play it.

    Nothing caught that because every test that sends audio has both halves.
    This one withholds the pair32 and asks for silence: the sender is
    supposed to notice it cannot key the stream and send nothing at all.
    """
    frames = [bytes([0x40 + i]) * (32 + i) for i in range(3)]
    eld = tmp_path / "half.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))

    async with driven_session(
        monkeypatch, with_pair32=False, session_kwargs={"eld_path": eld}
    ) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=3)
        packets = list(receiver.audio_data_server.datagrams)
        syncs = list(receiver.audio_control_server.datagrams)

    assert not packets, "audio was sent under a key derived from half its input"
    assert not syncs, "a sync went out for a stream that cannot be keyed"
