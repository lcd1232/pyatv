"""Tests that pin the constant values in the mirror SETUP bodies.

``fake_receiver.check_audio_setup`` and ``check_video_setup`` validate every
SETUP the fake receiver gets.  These tests make sure the checks run against a
live session and that each checked field, changed on its own, is reported.
Per-session values (``streamConnectionID``, ``sessionUUID``, ports,
``deviceID``) are checked for shape only.
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

    The recorded bodies prove the checks ran; an empty violation list alone
    would not.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)

        assert receiver.audio_setup_body is not None, "audio SETUP never checked"
        assert receiver.video_setup_body is not None, "video SETUP never checked"
        assert receiver.protocol_violations == []


#: Every constant of the type-96 audio SETUP, paired with a slightly wrong value.
#: The comment on each says why the receiver cares.
AUDIO_CONSTANT_MUTATIONS = [
    # 85 ms of jitter buffer at 44.1 kHz.
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
    # The receiver stores this in a 32-bit field and derives the video key
    # from it, so a larger value would mis-key the stream.
    (["streams", 0, "streamConnectionID"], 2**40),
    # The receiver sends audio sync packets here; port 0 is not bound.
    (["streams", 0, "controlPort"], 0),
    # The receiver indexes the session by an upper-case UUID.
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

    The unmutated body must pass first, so a field the sender stopped sending
    is caught too.
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

    One live session is shared by all fields to avoid a handshake per field.
    """
    _, video_body = await _captured_bodies(monkeypatch)

    assert fake_receiver.check_video_setup(video_body) == []

    for path, bad in VIDEO_TCP_MUTATIONS:
        mutated = _with(video_body, path, bad)
        problems = fake_receiver.check_video_setup(mutated)
        assert problems, f"changing {'.'.join(str(s) for s in path)} was not noticed"
        assert path[-1] in " ".join(problems), (path, problems)


async def test_video_setup_check_rejects_a_changed_timestamp_probe(monkeypatch):
    """The five ``timestampInfo`` probe names are fixed, in a fixed order.

    They label the latency timestamps the receiver reports back.
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
    """The audio SETUP sent agrees with `screen_audio.audio_setup_stream_params`.

    `session.py` writes the same keys out by hand, so the two could drift.
    `controlPort` is per-session and so not part of the helper.
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

    The receiver ties both streams to one session by ``sessionUUID``,
    ``deviceID`` and ``macAddress``, so the two copies must match.
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

    Receivers remember paired devices by these, so a configured value must
    reach the wire.
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

    Runs with and without raw16, since a FairPlay-derived encryptor is only
    built when raw16 is present.
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

    ``/fp-setup`` and ``/auth-setup`` use the handshake user agent and every
    RTSP request uses ``MIRROR_USER_AGENT``, matching what real senders do.
    The MFiSAP and FPLY handshake modules must agree on their user agent.
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

    The sockets are captured on the first stop() call: stop() clears the
    references, and once the session has exited the loop has reclaimed the
    descriptors anyway, so a later check could not see a leak.
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

    ``_audio_control_sock`` is a bare socket rather than a transport, so it
    must be closed explicitly.
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

    Tasks not awaited by ``stop()`` would still finish a loop turn or two
    later, so the check is made at the moment ``stop()`` returns.
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
    every request; a mirroring sender should not send them.  RECORD and
    TEARDOWN still do, and this pins the current behaviour.
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

    # Current behaviour, not a requirement: these two still send all three.
    assert seen.get("RECORD") == raop_headers, seen.get("RECORD")
    assert seen.get("TEARDOWN") == raop_headers, seen.get("TEARDOWN")


async def test_the_config_frame_carries_the_sources_own_sps_and_pps(monkeypatch):
    """The plaintext avcC must describe the H.264 actually being streamed.

    The receiver initialises its decoder from this first message on the data
    channel; a wrong SPS or PPS gives a black screen on a healthy session.
    """
    async with driven_session(monkeypatch) as (receiver, sess):
        await stream_then_stop(receiver, sess)
        head = receiver.video_server.head
        source = pathlib.Path(sess._h264_path).read_bytes()  # noqa: SLF001

    assert head, "nothing was retained from the data channel"

    # First message: 128-byte data header, then the avcC record.
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
    """Video frames omit SPS/PPS; those are sent once, in the avcC config.

    AES-CTR preserves length, so the frame size on the wire shows whether the
    parameter sets were stripped without needing the key.
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

    Stamps are nanoseconds in the header's little-endian u64 at offset 8; the
    receiver plays back off them.  A non-default rate is included so a
    hard-coded 30 fps would be caught.
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

    The key check is the sync's source port: it must be the advertised
    ``controlPort`` or the receiver never opens its audio control channel.
    AES-CBC leaves a partial final block in the clear, so each packet's
    payload is its source frame's length.
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

    # A sync sent from any other socket would still arrive here, so only the
    # source port tells the two apart.
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

    An Apple TV stalls silently at SETUP if the advertised timing port is not
    served.  The query runs while the session is live because ``stop()``
    closes the timing server.
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

    ``derive_tcp_stream_key_iv`` folds the streamConnectionID into the video
    key; a mismatch gives a healthy-looking session with a black screen.
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
    """Requests go SETUP(audio 96), RECORD, SETUP(video 110), TEARDOWN.

    The receiver only answers RECORD once the event channel from the audio
    SETUP is up, so the order matters.
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
    """``/fp-setup`` and ``/auth-setup`` carry ``X-Apple-HKP: 3``.

    The header selects the HAP pairing generation; the fake receiver ignores
    it, so only this check notices it going missing.
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
    """One opening sync, then one sync every ``AUDIO_SYNC_EVERY`` packets.

    The interval is patched down to three so a few frames exercise the
    periodic branch: *n* packets must give ``n // 3`` periodic syncs.
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
    """Without pair32 the audio stream cannot be keyed, so nothing is sent.

    The audio key is ``sha512(raw16 || pair32)[:16]``; hashing raw16 alone
    would still give a well-formed but wrong 16-byte key.
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
