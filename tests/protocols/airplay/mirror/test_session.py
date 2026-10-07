"""Tests for pyatv.protocols.airplay.mirror.session orchestration."""

import asyncio
import contextlib
import hashlib
from pathlib import Path
import struct
import sys
from unittest.mock import AsyncMock, MagicMock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from pyatv.protocols.airplay.mirror import context, framing, screen_audio, session
from pyatv.protocols.raop.packets import SyncPacket

from tests.protocols.airplay.mirror.test_session_error_paths import (
    GUARD_TIMEOUT,
    driven_session,
    stream_then_stop,
)

TEST_FILE = Path(__file__).parent / "test_pattern.h264"

pytestmark = pytest.mark.asyncio


def _fake_rtsp(setup_responses, record_response):
    rtsp = MagicMock()
    rtsp.connection = MagicMock()
    rtsp.connection.local_ip = "127.0.0.1"
    rtsp.connection.remote_ip = "10.0.0.1"
    rtsp.session_id = 12345
    rtsp.exchange = AsyncMock(return_value=_ok())
    rtsp.setup = AsyncMock(side_effect=setup_responses)
    rtsp.record = AsyncMock(return_value=record_response)
    rtsp.teardown = AsyncMock()
    rtsp.feedback = AsyncMock()
    return rtsp


def _ok(body=b""):
    r = MagicMock()
    r.code = 200
    r.body = body
    r.headers = {}
    return r


async def test_session_never_sends_announce():
    """The mirror flow sends no ANNOUNCE/SDP."""
    import plistlib

    session_ok = _ok(plistlib.dumps({"eventPort": 1}, fmt=plistlib.FMT_BINARY))
    rtsp = _fake_rtsp([session_ok], _ok())

    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    s = session.MirrorSession(
        rtsp=rtsp,
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
    )

    await s._setup_session()

    announce_calls = [
        c for c in rtsp.exchange.call_args_list if c.args and c.args[0] == "ANNOUNCE"
    ]
    assert announce_calls == []
    rtsp.announce.assert_not_called()


async def test_session_stop_calls_teardown():
    rtsp = _fake_rtsp([], _ok())
    rtsp.session_id = 999
    s = session.MirrorSession(
        rtsp=rtsp,
        verifier=MagicMock(),
        ctx=context.MirrorContext(),
        h264_path=TEST_FILE,
    )
    await s.stop()
    rtsp.teardown.assert_awaited_once_with(999)


async def test_session_run_requires_stream_encryptor():
    """Without a stream_encryptor, _stream_until_done can't encrypt frames."""
    ctx = context.MirrorContext(stream_encryptor=None)
    rtsp = _fake_rtsp([], _ok())
    s = session.MirrorSession(
        rtsp=rtsp,
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
    )
    s._video_channel = MagicMock()
    with pytest.raises(RuntimeError):
        await asyncio.wait_for(s._stream_until_done(), timeout=1.0)


# --- Keying and timing values that are only observable on the wire ----------
#
# These values are locals inside streaming coroutines, so the tests check the
# bytes that left the sender or spy on the key derivation.


async def test_video_key_falls_back_to_a_16_byte_sap_context_slice(monkeypatch):
    """Without raw16, the video key comes from SAP context bytes ``[8:24]``.

    The derivation only accepts 16 bytes, so a wrong-length slice would yield
    no key at all rather than a different one.
    """
    expected_off = 8

    # Distinctive bytes, so only the right slice matches.
    sap_context = bytes((i * 7 + 3) & 0xFF for i in range(276))
    pair32 = bytes.fromhex("66" * 32)

    real_derive = framing.derive_tcp_stream_key_iv
    derivations = []

    def recording_derive(*args, **kwargs):
        result = real_derive(*args, **kwargs)
        derivations.append((args, kwargs, result))
        return result

    monkeypatch.setattr(framing, "derive_tcp_stream_key_iv", recording_derive)

    async with driven_session(monkeypatch, with_raw16=False) as (receiver, sess):
        sess._ctx.sap_context = sap_context
        await stream_then_stop(receiver, sess)

    assert derivations, "the video key was never derived from the SAP context"
    (used_raw16, used_pair32, used_sid), kwargs, (key, _iv) = derivations[0]

    assert used_raw16 == sap_context[expected_off : expected_off + 16]
    assert len(used_raw16) == 16, f"keyed from {len(used_raw16)} bytes, not 16"
    assert used_pair32 == pair32
    assert used_sid == sess._ctx.stream_connection_id
    assert key == real_derive(used_raw16, pair32, used_sid, **kwargs)[0]
    # The derivation itself rejects any other length.
    with pytest.raises(ValueError, match="16 bytes"):
        real_derive(
            sap_context[expected_off : expected_off + 17], pair32, used_sid, **kwargs
        )


async def test_audio_sync_packet_reports_a_50ms_latency(monkeypatch, tmp_path):
    """The screen-audio sync packet advertises 50 ms of latency.

    The receiver schedules playback against the gap between ``now`` and
    ``now_without_latency``, so a wrong value skews audio timing.
    """
    loop = asyncio.get_event_loop()
    received: asyncio.Queue = asyncio.Queue()

    class _Sink(asyncio.DatagramProtocol):
        def datagram_received(self, data, addr):
            received.put_nowait(data)

    ctrl_transport, _ = await loop.create_datagram_endpoint(
        _Sink, local_addr=("127.0.0.1", 0)
    )
    data_transport, _ = await loop.create_datagram_endpoint(
        _Sink, local_addr=("127.0.0.1", 0)
    )

    eld_file = tmp_path / "audio.eld"
    frame = b"\xde\xad\xbe\xef"
    eld_file.write_bytes(len(frame).to_bytes(4, "big") + frame)

    rtsp = _fake_rtsp([], _ok())
    rtsp.connection.remote_ip = "127.0.0.1"
    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    ctx.stream_raw16 = b"\x55" * 16
    ctx.audio_eiv = b"\x77" * 16
    ctx.audio_data_port = data_transport.get_extra_info("socket").getsockname()[1]
    ctx.audio_control_port = ctrl_transport.get_extra_info("socket").getsockname()[1]

    sess = session.MirrorSession(
        rtsp=rtsp,
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
        eld_path=eld_file,
        pair_secret=b"\x66" * 32,
    )
    # The first sync goes out before the first stop check, so an already
    # stopped session emits exactly one and returns.
    sess._stopped = True
    try:
        await asyncio.wait_for(sess._stream_screen_audio(), timeout=5.0)
        sync = await asyncio.wait_for(received.get(), timeout=5.0)
    finally:
        if sess._audio_udp is not None:
            sess._audio_udp.close()
        ctrl_transport.close()
        data_transport.close()

    packet = SyncPacket.decode(sync)
    latency_samples = (packet.now - packet.now_without_latency) & 0xFFFFFFFF
    assert latency_samples / screen_audio.AUDIO_SAMPLE_RATE == pytest.approx(
        0.050
    ), f"sync advertised {latency_samples} samples of latency"


@pytest.mark.asyncio
async def test_a_wrong_length_raw16_falls_back_instead_of_being_used(monkeypatch):
    """A raw16 that is present but not 16 bytes is ignored, not used.

    The video key then falls back to the SAP context slice instead of
    feeding a short key into the derivation.
    """
    context = bytes(range(0x40, 0x80))
    seen: list = []
    real = framing.derive_tcp_stream_key_iv

    def spy(raw16, *args, **kwargs):
        seen.append(bytes(raw16))
        return real(raw16, *args, **kwargs)

    monkeypatch.setattr(framing, "derive_tcp_stream_key_iv", spy)

    async with driven_session(monkeypatch) as (receiver, sess):
        sess._ctx.stream_raw16 = b"\xc0" * 8  # noqa: SLF001  truthy, too short
        sess._ctx.sap_context = context  # noqa: SLF001
        await stream_then_stop(receiver, sess)

    assert seen, "the proven key path never derived anything"
    assert b"\xc0" * 8 not in seen, "an 8-byte raw16 was used as if it were 16"
    assert all(
        len(r) == 16 for r in seen
    ), "raw16 lengths reaching the derivation: %s" % [len(r) for r in seen]


@pytest.mark.asyncio
async def test_the_screen_audio_key_hashes_raw16_before_pair32(monkeypatch, tmp_path):
    """Screen audio is keyed with ``sha512(raw16 || pair32)[:16]``.

    Checked by decrypting a sent packet (AES-CBC over whole blocks, tail
    passed through), since swapped halves still give a valid-looking key.
    """
    frames = [bytes([0x51 + i]) * 48 for i in range(2)]
    eld = tmp_path / "keyed.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))

    async with driven_session(monkeypatch, session_kwargs={"eld_path": eld}) as (
        receiver,
        sess,
    ):
        await stream_then_stop(receiver, sess, video_frames=3)
        packets = list(receiver.audio_data_server.datagrams)
        raw16 = sess._ctx.stream_raw16  # noqa: SLF001
        eiv = sess._ctx.audio_eiv  # noqa: SLF001

    assert packets, "no screen audio was sent"
    pair32 = bytes.fromhex("66" * 32)
    key = hashlib.sha512(raw16 + pair32).digest()[:16]

    payload = packets[0][12:]  # past the RTP header
    whole = (len(payload) // 16) * 16
    dec = Cipher(algorithms.AES(key), modes.CBC(eiv)).decryptor()
    plain = dec.update(payload[:whole]) + dec.finalize() + payload[whole:]

    assert plain == frames[0], (
        "decrypted %s, expected the first frame -- the key's halves are "
        "hashed in the wrong order" % plain[:8].hex()
    )


@pytest.mark.asyncio
async def test_a_full_live_audio_queue_drops_the_oldest_frame(monkeypatch, tmp_path):
    """A full live audio queue drops its oldest frame to bound latency.

    The reader fills the queue during the sender's pre-buffer wait. The first
    packet is decrypted: it must be one of the later frames, not the first.
    """
    frames = [bytes([0x61 + i]) * 48 for i in range(6)]
    eld = tmp_path / "many.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))
    feeder = tmp_path / "audio_feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(eld),
        encoding="utf-8",
    )

    monkeypatch.setattr(session, "AUDIO_LIVE_BUFFER", 2)
    monkeypatch.setattr(session, "AUDIO_PREBUFFER", 2)
    audio_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"audio_command": audio_cmd}
    ) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while not receiver.audio_data_server.datagrams:
                if task.done():
                    task.result()
                    break
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            packets = list(receiver.audio_data_server.datagrams)
            raw16 = sess._ctx.stream_raw16  # noqa: SLF001
            eiv = sess._ctx.audio_eiv  # noqa: SLF001
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    assert packets, "no screen audio was sent"
    key = hashlib.sha512(raw16 + bytes.fromhex("66" * 32)).digest()[:16]
    payload = packets[0][12:]
    whole = (len(payload) // 16) * 16
    dec = Cipher(algorithms.AES(key), modes.CBC(eiv)).decryptor()
    first = dec.update(payload[:whole]) + dec.finalize() + payload[whole:]

    assert first != frames[0], "the first frame sent was the oldest one queued"
    assert first in frames[2:], "sent %s, not one of the later frames" % first[:4].hex()


@pytest.mark.asyncio
async def test_the_live_audio_reader_accepts_a_frame_of_exactly_the_cap(
    monkeypatch, tmp_path
):
    """The live audio reader accepts 8192-byte frames and rejects 8193.

    A larger length prefix is treated as lost sync and skipped byte by byte,
    so all three real frames must come back intact and in order.
    """
    frames = [b"\x71" * 48, b"\x72" * 8192, b"\x73" * 64]
    # A bare 8193 prefix that the reader must resync past.
    body = b"".join(struct.pack(">I", len(f)) + f for f in frames[:2])
    body += struct.pack(">I", 8193)
    body += struct.pack(">I", len(frames[2])) + frames[2]
    eld = tmp_path / "cap.eld"
    eld.write_bytes(body)
    feeder = tmp_path / "cap_feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(eld),
        encoding="utf-8",
    )

    monkeypatch.setattr(session, "AUDIO_PREBUFFER", 3)
    audio_cmd = '"%s" "%s"' % (sys.executable, feeder)

    async with driven_session(
        monkeypatch, session_kwargs={"audio_command": audio_cmd}
    ) as (receiver, sess):
        task = asyncio.ensure_future(sess.run())
        try:
            deadline = asyncio.get_event_loop().time() + GUARD_TIMEOUT
            while len(receiver.audio_data_server.datagrams) < len(frames):
                if task.done():
                    task.result()
                    break
                if asyncio.get_event_loop().time() > deadline:
                    break
                await asyncio.sleep(0.01)
            packets = list(receiver.audio_data_server.datagrams)
            raw16 = sess._ctx.stream_raw16  # noqa: SLF001
            eiv = sess._ctx.audio_eiv  # noqa: SLF001
        finally:
            await sess.stop()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task

    assert len(packets) >= len(frames), "only %d of %d frames arrived" % (
        len(packets),
        len(frames),
    )
    key = hashlib.sha512(raw16 + bytes.fromhex("66" * 32)).digest()[:16]
    got = []
    for packet in packets[: len(frames)]:
        payload = packet[12:]
        whole = (len(payload) // 16) * 16
        dec = Cipher(algorithms.AES(key), modes.CBC(eiv)).decryptor()
        got.append(dec.update(payload[:whole]) + dec.finalize() + payload[whole:])

    assert [len(g) for g in got] == [len(f) for f in frames], [len(g) for g in got]
    assert got == frames, "frames came back altered or out of order"
