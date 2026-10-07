"""Tests for pyatv.protocols.airplay.mirror.session orchestration."""

import asyncio
import contextlib
import hashlib
from pathlib import Path
import re
import socket
import struct
import sys
from unittest.mock import AsyncMock, MagicMock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pytest

from pyatv.protocols.airplay.mirror import (
    airparrot_audio,
    context,
    framing,
    rtp,
    session,
    srtp,
    streams,
)
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


async def test_session_init_setup_matches_captured_shape(monkeypatch):
    """Session-init SETUP must match the real macOS sender captured in Phase 28.

    Ground truth: docs/superpowers/specs/airplay_capture/proxy_captures/
    capture-20260822-091057.jsonl (seq 35). The receiver drops the connection
    outright if ekey/eiv/et appear here, and 400s if the mirror marker is
    missing, so both are asserted.
    """
    import plistlib

    # These assert the macOS-AVConference dialect (non-default). AirParrot mode
    # skips the session-init SETUP, so force the AVConference path here.
    monkeypatch.setenv("MIRROR_AIRPARROT", "0")

    session_ok = _ok(plistlib.dumps({"eventPort": 49641}, fmt=plistlib.FMT_BINARY))
    rtsp = _fake_rtsp([session_ok], _ok())

    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    s = session.MirrorSession(
        rtsp=rtsp,
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
        channel_opener=AsyncMock(return_value=(MagicMock(), MagicMock())),
    )

    await s._setup_session()

    body = rtsp.setup.call_args.kwargs["body"]
    assert body["isScreenMirroringSession"] is True
    assert body["timingProtocol"] == "NTP"
    assert body["isMultiSelectAirPlay"] is False
    assert body["statsCollectionEnabled"] is False
    assert body["updateSessionRequest"] is False
    assert isinstance(body["timingPort"], int) and body["timingPort"] > 0
    assert "streams" not in body

    # Both identifiers are fresh upper-case UUIDs. Shape only: whether
    # sessionCorrelationUUID is meant to equal sessionUUID, or to correlate
    # something else entirely, is not established by any capture we have --
    # so this pins that it is a well-formed UUID and not, say, None or
    # lower-cased, without asserting a relationship nobody has verified.
    for key in ("sessionUUID", "sessionCorrelationUUID"):
        assert re.fullmatch(r"[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}", body[key]), (
            key,
            body[key],
        )
    # These caused a silent connection drop in Phase 27 — FPLY v3 already
    # established keying and the receiver treats a re-send as a downgrade.
    for forbidden in ("ekey", "eiv", "et"):
        assert forbidden not in body

    assert ctx.event_port == 49641


async def test_session_stream_setup_matches_captured_shape(monkeypatch):
    """Stream SETUP must carry the AVConf/Viceroy fields, not AirPlay-1 ones."""
    import plistlib

    # AVConference dialect (non-default); AirParrot mode uses the type-110
    # simple body, so force the AVConference path for this shape assertion.
    monkeypatch.setenv("MIRROR_AIRPARROT", "0")

    stream_ok = _ok(
        plistlib.dumps(
            {
                "streams": [
                    {
                        "type": 110,
                        "dataPort": 54595,
                        "streamConnections": {
                            "streamConnectionTypeMediaDataControl": {
                                "streamConnectionKeyPort": 49642
                            }
                        },
                    }
                ]
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    rtsp = _fake_rtsp([stream_ok], _ok())

    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    # The screen-video key is derived via verifier.encryption_keys (DataStream
    # HKDF over the pair-verify secret); it must return a pair of 32-byte keys.
    verifier = MagicMock()
    verifier.encryption_keys.return_value = (b"\x11" * 32, b"\x22" * 32)
    s = session.MirrorSession(
        rtsp=rtsp,
        verifier=verifier,
        ctx=ctx,
        h264_path=TEST_FILE,
        channel_opener=AsyncMock(return_value=(MagicMock(), MagicMock())),
    )

    await s._setup_streams()

    stream = rtsp.setup.call_args.kwargs["body"]["streams"][0]
    assert stream["type"] == 110
    assert stream["useAVConfMirroring"] is True
    assert isinstance(stream["encryptionSeed"], int)
    assert isinstance(stream["negotiationData"], bytes)
    control = stream["streamConnections"]["streamConnectionTypeMediaDataControl"]
    assert isinstance(control["streamConnectionKeyEncryptionSeed"], int)
    # AirPlay-1 fields the modern receiver rejects.
    for forbidden in ("latencyMs", "wantsDedicatedSocket", "ekey", "eiv"):
        assert forbidden not in stream

    assert ctx.video_data_port == 54595
    assert ctx.stream_control_port == 49642


async def test_session_never_sends_announce():
    """The modern mirror flow has no ANNOUNCE/SDP at all (Phase 28 capture)."""
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
        channel_opener=AsyncMock(return_value=(MagicMock(), MagicMock())),
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
        channel_opener=AsyncMock(),
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
        channel_opener=AsyncMock(),
    )
    # Call the streaming phase directly with no channels — it must check
    # the encryptor before doing anything that would NPE later.
    s._video_channel = MagicMock()
    s._audio_channel = MagicMock()
    with pytest.raises(RuntimeError):
        # Wrap with timeout so a stuck producer doesn't hang the test
        await asyncio.wait_for(s._stream_until_done(), timeout=1.0)


# --- Keying and timing constants that only exist on the wire ----------------
#
# Each test below pins a value that lives and dies as a local inside a
# streaming coroutine -- a session key, a slice of the SAP context, a latency
# offset. None of them reach the context or any return value, so none can be
# read back afterwards. Two of the three therefore assert on the bytes that
# actually left the sender, and the third watches the derivation being called,
# which is the same seam ``test_mvp_integration`` uses for its half of it.
#
# All three were written against mutants that the rest of the suite could not
# tell apart from the original.


def _srtp_decrypt(datagram: bytes, session_key: bytes, session_salt: bytes) -> bytes:
    """Decrypt one mirror RTP datagram's payload as the receiver would.

    ``roc`` is 0 because only the first datagram of a session is ever passed
    here, and the roll-over counter cannot have advanced by then.
    """
    parsed = rtp.parse_header(datagram)
    iv = srtp.srtp_iv(session_salt, parsed["ssrc"], 0, parsed["sequence"])
    return (
        Cipher(algorithms.AES(session_key), modes.CTR(iv))
        .decryptor()
        .update(parsed["payload"])
    )


def _is_avcc_access_unit(plaintext: bytes) -> bool:
    """True if *plaintext* is a well-formed AVCC unit (4-byte BE length + NAL).

    This is the decrypt oracle. The sender packetizes ``len(nal)`` big-endian
    followed by the NAL itself, so a correct key yields a length prefix that
    agrees with the payload it precedes and a NAL header in range. A wrong key
    yields uniformly random bytes, which satisfy that by chance with
    probability ~2**-32.
    """
    if len(plaintext) < 5:
        return False
    if int.from_bytes(plaintext[:4], "big") != len(plaintext) - 4:
        return False
    return 1 <= (plaintext[4] & 0x1F) <= 12


@pytest.mark.parametrize(
    "kdf_env,expect_kdf",
    [(None, True), ("1", True), ("2", True), ("0", False)],
    ids=["unset", "one", "two", "zero"],
)
async def test_srtp_kdf_env_selects_the_derivation_that_encrypts_the_wire(
    monkeypatch, kdf_env, expect_kdf
):
    """``MIRROR_SRTP_KDF`` must pick the session key the sender really uses.

    The switch chooses between two *different* derivations of the SRTP session
    key from the same master material -- the SP800-108 counter-mode KDF, and
    the master key/salt taken verbatim. ``test_srtp.py`` pins both derivations
    at the ``srtp`` layer, where they are arguments; what nothing pinned was
    that session.py reads the flag the right way round. Inverting the
    comparison therefore swapped one derivation for the other with the whole
    suite still green, which is a silently unplayable stream.

    Only "0" disables the KDF ("1" is the default and any other value is not
    "0"), so the parametrization covers both sides of that comparison.

    session.py reads this variable in two places; this covers the one on the
    default ``MIRROR_SRTP_SECRET="fply"`` path. The other guards the
    ``"pairverify"`` A/B path, whose derivation is macOS-only.
    """
    if kdf_env is None:
        monkeypatch.delenv("MIRROR_SRTP_KDF", raising=False)
    else:
        monkeypatch.setenv("MIRROR_SRTP_KDF", kdf_env)

    # The AVConference dialect is the one whose UDP producer encrypts through
    # the SRTP encryptors; the AirParrot dialect uses a continuous keystream
    # instead and would never exercise this switch.
    async with driven_session(monkeypatch, airparrot=False) as (receiver, sess):
        # The default MIRROR_SRTP_SECRET="fply" path builds the SRTP master
        # material out of the FairPlay stream key/iv, and only when both are
        # long enough. The handshake against the fake yields an encryptor that
        # remembers neither, so give it a key and iv -- without them the
        # session never reaches the switch under test at all.
        sess._ctx.stream_encryptor = framing.MirrorEncryptor.from_key_iv(
            bytes(range(0x10, 0x20)), bytes(range(0x30, 0x40))
        )
        await stream_then_stop(receiver, sess)

    datagrams = receiver.video_server.datagrams
    assert datagrams, "no video datagram reached the receiver"
    first = datagrams[0]
    assert rtp.parse_header(first)["fragment_count"] == 1, "frame was fragmented"

    # The master material is the FairPlay stream key/iv, which the session
    # reached by the default MIRROR_SRTP_SECRET="fply" path.
    stream_encryptor = sess._ctx.stream_encryptor
    master_key, master_salt = srtp.derive_master_key_salt(
        stream_encryptor.key[:16] + stream_encryptor.iv[:14]
    )
    ssrc = rtp.parse_header(first)["ssrc"]

    with_kdf = srtp.derive_session_key_salt(master_key, master_salt, ssrc, use_kdf=True)
    without_kdf = (master_key[:16], master_salt[:14])
    # If these agreed the test below could not tell the settings apart.
    assert with_kdf != without_kdf, "the two derivations produced the same key"

    decrypts_with_kdf = _is_avcc_access_unit(_srtp_decrypt(first, *with_kdf))
    decrypts_without_kdf = _is_avcc_access_unit(_srtp_decrypt(first, *without_kdf))

    assert decrypts_with_kdf is expect_kdf, (
        f"MIRROR_SRTP_KDF={kdf_env!r}: the wire "
        f"{'did not decrypt' if expect_kdf else 'decrypted'} under the "
        "SP800-108 session KDF"
    )
    assert decrypts_without_kdf is (not expect_kdf), (
        f"MIRROR_SRTP_KDF={kdf_env!r}: the wire "
        f"{'decrypted' if expect_kdf else 'did not decrypt'} under the raw "
        "master material"
    )


@pytest.mark.parametrize(
    "raw16_off_env,expected_off", [(None, 8), ("12", 12)], ids=["default", "override"]
)
async def test_video_key_falls_back_to_a_16_byte_sap_context_slice(
    monkeypatch, raw16_off_env, expected_off
):
    """Without an ekey raw16, the video key comes from 16 bytes of SAP context.

    ``stream_raw16`` is the value the sender packaged into ``ekey``, and is
    what a real session keys from; the slice is the fallback for the no-ekey
    experiments. Its length is load-bearing rather than cosmetic: the
    derivation sits behind a ``len(raw16) == 16`` guard, so a slice of any
    other length does not produce a different key -- it produces no key at
    all, and the session silently drops back to an unrelated cipher.

    ``test_mvp_integration`` covers the ``stream_raw16`` branch and asserts
    the context holds the secret at ``[8:24]``; this covers the branch that
    actually does that indexing.
    """
    if raw16_off_env is None:
        monkeypatch.delenv("MIRROR_RAW16_OFF", raising=False)
    else:
        monkeypatch.setenv("MIRROR_RAW16_OFF", raw16_off_env)

    # Distinctive bytes, so "the right 16" is a real claim and not satisfied
    # by any slice of the same length.
    sap_context = bytes((i * 7 + 3) & 0xFF for i in range(276))
    pair32 = bytes.fromhex("66" * 32)

    real_derive = framing.derive_airparrot_stream_key_iv
    derivations = []

    def recording_derive(*args, **kwargs):
        result = real_derive(*args, **kwargs)
        derivations.append((args, kwargs, result))
        return result

    monkeypatch.setattr(framing, "derive_airparrot_stream_key_iv", recording_derive)

    async with driven_session(monkeypatch, with_raw16=False) as (receiver, sess):
        sess._ctx.sap_context = sap_context
        await stream_then_stop(receiver, sess)

    # With a slice of any length but 16 the guard rejects it and this list is
    # empty -- the session logs "PROVEN video key unavailable" and streams
    # under a different key instead.
    assert derivations, "the video key was never derived from the SAP context"
    (used_raw16, used_pair32, used_sid), kwargs, (key, _iv) = derivations[0]

    assert used_raw16 == sap_context[expected_off : expected_off + 16]
    assert len(used_raw16) == 16, f"keyed from {len(used_raw16)} bytes, not 16"
    assert used_pair32 == pair32
    assert used_sid == sess._ctx.stream_connection_id
    assert key == real_derive(used_raw16, pair32, used_sid, **kwargs)[0]
    # A slice one byte longer is not a near-miss key, it is not a key at all:
    # the derivation refuses it outright, which is why the caller's length
    # guard is what stands between a wrong slice and a dead video stream.
    with pytest.raises(ValueError, match="16 bytes"):
        real_derive(
            sap_context[expected_off : expected_off + 17], pair32, used_sid, **kwargs
        )


async def test_audio_sync_packet_reports_a_50ms_latency(monkeypatch, tmp_path):
    """The screen-audio sync must offset ``now`` by exactly 50 ms of audio.

    The receiver locks its audio clock from the gap between the sync packet's
    ``now`` and ``now_without_latency``: that difference *is* the latency it
    schedules playback against, so the constant is not decorative -- it goes
    out on the wire ~1/s and a wrong value skews playback by the error.

    2205 is a sample count at the 44.1 kHz audio clock, and asserting what it
    means (50 ms) rather than its digits is what makes the test able to say a
    changed value is wrong.
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
    monkeypatch.setenv("MIRROR_AUDIO_ELD_FILE", str(eld_file))
    monkeypatch.setenv("MIRROR_PAIR32", "66" * 32)

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
        channel_opener=AsyncMock(),
    )
    # The first sync is sent before the send loop's first stop check, so a
    # session that is already stopped still emits exactly one and then
    # returns -- no pacing, no spinning, nothing to cancel.
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
    assert latency_samples / airparrot_audio.AUDIO_SAMPLE_RATE == pytest.approx(
        0.050
    ), f"sync advertised {latency_samples} samples of latency"


async def test_srtp_secret_datastream_keys_the_wire_from_the_setup_time_key(
    monkeypatch,
):
    """``MIRROR_SRTP_SECRET="datastream"`` streams under the DataStream HKDF key.

    ``ctx.datastream_video_key`` is derived once, at SETUP time, from the
    pair-verify HKDF that the AVConference receiver uses
    (``derive_datastream_video_key``).  It is read back in exactly one place:
    the last arm of the SRTP master-material chain.

    That arm never executed.  The default ``MIRROR_SRTP_SECRET="fply"`` arm
    sits directly above it and wins whenever a stream encryptor carries a key
    and iv, so the whole write/read pair -- a key derived in one method and
    consumed in another, several hundred lines apart -- was unverified: the
    field could have been derived from the wrong arguments, or never read.

    Selecting the datastream source and decrypting the wire under it proves
    both halves agree.  The negative half matters just as much: if the stream
    still decrypted under the fply material, the switch would not have
    selected anything.
    """
    monkeypatch.setenv("MIRROR_SRTP_SECRET", "datastream")

    async with driven_session(monkeypatch, airparrot=False) as (receiver, sess):
        # Give the fply arm above the material it needs, so this test fails if
        # the chain ever prefers it again rather than passing by default.
        sess._ctx.stream_encryptor = framing.MirrorEncryptor.from_key_iv(
            bytes(range(0x10, 0x20)), bytes(range(0x30, 0x40))
        )
        # The shared verifier double returns one fixed pair whatever it is
        # asked for, which makes the salt -- and so the streamConnectionID
        # inside it -- invisible: deriving the key from the wrong id would
        # produce the same bytes. A real HKDF is argument-sensitive, so make
        # this one depend on the salt it is given.
        sess._verifier.encryption_keys.side_effect = lambda salt, out, inp: (
            hashlib.sha512(f"{salt}|{out}".encode()).digest()[:32],
            hashlib.sha512(f"{salt}|{inp}".encode()).digest()[:32],
        )
        await stream_then_stop(receiver, sess)
        datastream_key = sess._ctx.datastream_video_key
        fply = sess._ctx.stream_encryptor
        verifier = sess._verifier
        stream_id = sess._ctx.stream_connection_id

    assert datastream_key is not None, "the DataStream key was never derived"

    # Recomputed independently rather than read back off the context: taking
    # the session's own value would verify only that the write and the read
    # agree, and would still pass if the key were derived from the wrong
    # stream id.
    assert datastream_key == framing.derive_datastream_video_key(
        verifier, stream_id
    ), "the DataStream key was not derived from this session's stream id"

    # ...and the salt it asked for, spelled out. The comparison above calls
    # the same function the session did, so anything wrong INSIDE that
    # function cancels on both sides -- swapping the two halves of
    # "DataStream-Salt" + str(id) changes every key it derives and leaves
    # that assertion true. The id is formatted unsigned (%llu).
    salts = [
        call.args[0]
        for call in verifier.encryption_keys.call_args_list
        if call.args and str(call.args[0]).startswith("DataStream")
    ]
    assert salts, "the DataStream key was never asked of the verifier"
    wanted = "DataStream-Salt" + str(stream_id & 0xFFFFFFFFFFFFFFFF)
    assert salts[0] == wanted, "asked for salt %r, wanted %r" % (salts[0], wanted)

    datagrams = receiver.video_server.datagrams
    assert datagrams, "no video datagram reached the receiver"
    first = datagrams[0]
    ssrc = rtp.parse_header(first)["ssrc"]

    def session_keys(material: bytes):
        master_key, master_salt = srtp.derive_master_key_salt(material)
        return srtp.derive_session_key_salt(master_key, master_salt, ssrc, use_kdf=True)

    from_datastream = session_keys(datastream_key)
    from_fply = session_keys(fply.key[:16] + fply.iv[:14])
    assert from_datastream != from_fply, "the two sources produced the same key"

    assert _is_avcc_access_unit(
        _srtp_decrypt(first, *from_datastream)
    ), "the wire did not decrypt under the DataStream HKDF key"
    assert not _is_avcc_access_unit(
        _srtp_decrypt(first, *from_fply)
    ), "the wire decrypted under the fply material, so the switch selected nothing"


@pytest.mark.parametrize("deriv", [None, "direct"])
@pytest.mark.asyncio
async def test_keybuf_deriv_chooses_where_the_window_key_comes_from(monkeypatch, deriv):
    """``MIRROR_KEYBUF_DERIV``, in the arm the note called untested.

    The reason recorded there was that these sweeps need a receiver that
    decrypts. They do, to say whether a derivation is *right*; they do not
    to say which one the session picked, and picking the wrong one is what
    the switch can get wrong. ``"direct"`` takes the window's first 16 bytes
    as the key verbatim; anything else runs them through
    ``stream_key_iv_from_secret``. Inverting the comparison swaps the two.

    The spy has to look at the argument rather than the call. The proven
    key path reaches the same function through
    ``derive_airparrot_stream_key_iv``, so it is called either way -- what
    only happens on the non-direct branch is being called with the window.
    """
    context = bytes(range(64))
    window = context[8:24]

    seen: list = []
    real = framing.stream_key_iv_from_secret

    def spy(secret, stream_id, *args, **kwargs):
        seen.append(bytes(secret))
        return real(secret, stream_id, *args, **kwargs)

    monkeypatch.setattr(framing, "stream_key_iv_from_secret", spy)
    monkeypatch.setenv("MIRROR_KEYBUF_WINDOW", "8:24")
    if deriv is not None:
        monkeypatch.setenv("MIRROR_KEYBUF_DERIV", deriv)

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
        sess._ctx.sap_context = context  # noqa: SLF001
        await stream_then_stop(receiver, sess)

    if deriv == "direct":
        assert window not in seen, "direct should not derive from the window"
    else:
        assert window in seen, "the window was never run through the derivation"


@pytest.mark.parametrize("mode, expect_used", [("continuous", True), ("srtp", False)])
@pytest.mark.asyncio
async def test_keybuf_mode_decides_whether_the_window_key_becomes_a_cipher(
    monkeypatch, mode, expect_used
):
    """``MIRROR_KEYBUF_MODE``, and with it the width of the direct slice.

    ``"continuous"`` turns the window key into a ``MirrorEncryptor``;
    anything else parks it as an SRTP key/salt pair that the AirParrot
    dialect never reaches. So the same wrong key is inert under the default
    and live under the switch, which is why the slice width is checked here
    rather than alongside the derivation: taking 15 bytes instead of 16
    leaves an unusable key that nothing objects to until it has to encrypt.

    As before the spy reads its argument. The proven key path builds an
    encryptor of its own, so ``from_key_iv`` is called whichever way the
    switch goes; only one of them passes the window.
    """
    context = bytes(range(64))
    window = context[8:24]

    keys: list = []
    real = framing.MirrorEncryptor.from_key_iv

    def spy(key, iv, *args, **kwargs):
        keys.append(bytes(key))
        return real(key, iv, *args, **kwargs)

    monkeypatch.setattr(framing.MirrorEncryptor, "from_key_iv", spy)
    monkeypatch.setenv("MIRROR_KEYBUF_WINDOW", "8:24")
    monkeypatch.setenv("MIRROR_KEYBUF_DERIV", "direct")
    monkeypatch.setenv("MIRROR_KEYBUF_MODE", mode)

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
        sess._ctx.sap_context = context  # noqa: SLF001
        await stream_then_stop(receiver, sess)

    if expect_used:
        assert (
            window in keys
        ), "continuous mode should encrypt with the window's 16 bytes; got %s" % [
            k.hex() for k in keys
        ]
    else:
        assert window not in keys, "srtp mode should not build a cipher from it"


@pytest.mark.parametrize(
    "kdf",
    [
        "direct",
        "aescm",
        # AVConference's KDF is CommonCrypto, loaded from
        # /usr/lib/system/libcommonCrypto.dylib, so the branch that calls it
        # cannot run anywhere else -- `test_srtp` guards its own cc cases the
        # same way. Without this the case fails on two of CI's three
        # platforms, which is how it was found: in a Linux container.
        pytest.param(
            "cc",
            marks=pytest.mark.skipif(
                sys.platform != "darwin",
                reason="CCKeyDerivationHMac is macOS-only",
            ),
        ),
    ],
)
@pytest.mark.asyncio
async def test_keybuf_srtp_kdf_picks_one_of_three_session_derivations(monkeypatch, kdf):
    """``MIRROR_KEYBUF_SRTP_KDF``, in the ``srtp`` half of the keybuf path.

    Three derivations of a session key from the same keybuf pair: taken
    verbatim, through the RFC 3711 AES-CM KDF, or through AVConference's
    HMAC construction. Each is pinned at the ``srtp`` layer already; what
    was not pinned is that session.py dispatches on the name correctly, and
    two of the three comparisons could be inverted without a failure.

    Exactly one of the two derivations runs, and "direct" runs neither --
    which is the whole content of the switch, and is visible without
    knowing what any of them should produce.
    """
    context = bytes(range(64))
    called: list = []

    real_aescm = srtp.derive_srtp_session_aescm
    real_cc = srtp._cc_key_derivation_hmac  # noqa: SLF001

    def spy_aescm(*args, **kwargs):
        called.append("aescm")
        return real_aescm(*args, **kwargs)

    contexts: list = []

    def spy_cc(*args, **kwargs):
        called.append("cc")
        contexts.append(bytes(args[3]) if len(args) > 3 else b"")
        return real_cc(*args, **kwargs)

    built: list = []
    real_enc = srtp.SrtpVideoEncryptor

    def spy_enc(key, salt, *args, **kwargs):
        built.append((len(key), len(salt)))
        return real_enc(key, salt, *args, **kwargs)

    monkeypatch.setattr(srtp, "derive_srtp_session_aescm", spy_aescm)
    monkeypatch.setattr(srtp, "_cc_key_derivation_hmac", spy_cc)
    monkeypatch.setattr(srtp, "SrtpVideoEncryptor", spy_enc)
    monkeypatch.setenv("MIRROR_KEYBUF_WINDOW", "8:24")
    monkeypatch.setenv("MIRROR_KEYBUF_DERIV", "direct")
    monkeypatch.setenv("MIRROR_KEYBUF_MODE", "srtp")
    monkeypatch.setenv("MIRROR_KEYBUF_SRTP_KDF", kdf)

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
        sess._ctx.sap_context = context  # noqa: SLF001
        await stream_then_stop(receiver, sess)

    if kdf == "direct":
        assert not called, "direct should derive nothing, ran %s" % called
    else:
        assert kdf in called, "%s was selected but %s ran" % (kdf, called or "nothing")
        assert set(called) == {kdf}, "both derivations ran: %s" % called

    if kdf == "cc":
        # MIRROR_KEYBUF_CC_CONTEXT defaults to "derived", which feeds the
        # first four bytes of the media key as the derivation context. The
        # alternative is no context at all, and the two produce different
        # session keys from identical inputs.
        assert contexts and all(
            len(c) == 4 for c in contexts
        ), "derived context should be 4 bytes, got %s" % [c.hex() for c in contexts]
        # The 30-byte output splits 16/14 into key and salt, both sliced out
        # by hand. A slice that runs short still looks like a key to SRTP and
        # nothing downstream objects, so the widths are asserted here.
        assert built and set(built) == {(16, 14)}, (
            "cc derivation produced key/salt widths %s, wanted (16, 14)" % built
        )


@pytest.mark.asyncio
async def test_a_wrong_length_raw16_falls_back_instead_of_being_used(monkeypatch):
    """``stream_raw16 and len(stream_raw16) == 16``, not ``or``.

    The proven video key prefers the raw16 the sender packaged into ekey and
    falls back to a slice of the SAP context when it does not have one. The
    guard has to mean "present AND the right length": written ``or`` a
    present-but-short raw16 satisfies it, and an 8-byte key goes into the
    derivation where 16 belong.

    Only a value that is truthy and the wrong size tells the two apart, and
    nothing produced one -- the fixture's raw16 is always 16 bytes and the
    absent case is empty, which both spellings reject.
    """
    context = bytes(range(0x40, 0x80))
    seen: list = []
    real = framing.derive_airparrot_stream_key_iv

    def spy(raw16, *args, **kwargs):
        seen.append(bytes(raw16))
        return real(raw16, *args, **kwargs)

    monkeypatch.setattr(framing, "derive_airparrot_stream_key_iv", spy)

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
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
    """The order of the two halves, checked by decrypting what was sent.

    The audio key is ``sha512(raw16 || pair32)[:16]``. Swapping the halves
    produces a perfectly good 16-byte key that the receiver does not share,
    and every assertion the suite had about screen audio -- that packets
    arrive, that their payload lengths match the source frames, that the
    sync cadence is right -- holds exactly as well under the wrong key,
    because none of them looks at the bytes.

    So this one looks at the bytes. AES-CBC over whole blocks with the tail
    passed through, which is what the sender does, run backwards.
    """
    frames = [bytes([0x51 + i]) * 48 for i in range(2)]
    eld = tmp_path / "keyed.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))
    monkeypatch.setenv("MIRROR_AUDIO_SEND", "1")
    monkeypatch.setenv("MIRROR_AUDIO_ELD_FILE", str(eld))

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
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
async def test_the_control_channel_salt_names_the_encryption_seed(monkeypatch):
    """``MIRROR_CONTROL_SALT + str(seed)``, in that order.

    The control channel's HAP keys come from a salt the receiver builds the
    same way. Swapping the halves, or reading a different field for the
    seed, yields a salt of the same shape and a channel neither side can
    decrypt -- and the opener is a double in every test that reaches this
    line, so nothing was looking at what it was handed.

    ``_open_channels`` is driven directly rather than through a session run:
    the argument is the whole subject, and a mock records it.
    """
    monkeypatch.setenv("MIRROR_AIRPARROT", "0")
    opener = AsyncMock(return_value=(MagicMock(), MagicMock()))

    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    ctx.control_encryption_seed = 1234567890123456789
    ctx.stream_control_port = 7001
    ctx.audio_data_port = 0  # keep the audio channel out of this

    sess = session.MirrorSession(
        rtsp=_fake_rtsp([_ok()], _ok()),
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
        channel_opener=opener,
    )

    # The control channel is opened first; what follows it builds a real
    # datagram endpoint to a port this session has not negotiated, and fails.
    # That is past the subject -- the assertion below fails if the control
    # channel was never opened at all, which is the only ordering that matters.
    with contextlib.suppress(Exception):
        await sess._open_channels()  # noqa: SLF001

    salts = [
        call.args[3]
        for call in opener.call_args_list
        if len(call.args) > 3 and isinstance(call.args[3], str)
    ]
    assert salts, "no channel was opened with a salt"
    assert salts[0] == "DataStream-Salt1234567890123456789", salts[0]


@pytest.mark.asyncio
async def test_a_full_live_audio_queue_drops_the_oldest_frame(monkeypatch, tmp_path):
    """The audio queue's copy of the bounded-latency rule.

    Same branch as the video one, same failure if it goes: ``put_nowait``
    raises ``QueueFull``, the handler logs, the reader ends, and the stream
    plays whatever was queued first -- the stale frames -- instead of
    discarding them for the fresh ones.

    The reader's head start here is the sender's pre-buffer loop, which
    sleeps in 50ms steps until the queue reaches ``MIRROR_AUDIO_PREBUFFER``.
    That is long enough for a reader with the whole source already in hand.
    Which frame arrives first is the question, so the packet is decrypted:
    dropping keeps the tail, dying keeps the head.
    """
    frames = [bytes([0x61 + i]) * 48 for i in range(6)]
    eld = tmp_path / "many.eld"
    eld.write_bytes(b"".join(struct.pack(">I", len(f)) + f for f in frames))
    feeder = tmp_path / "audio_feeder.py"
    feeder.write_text(
        "import sys\nsys.stdout.buffer.write(open(%r, 'rb').read())\n" % str(eld),
        encoding="utf-8",
    )

    monkeypatch.setenv("MIRROR_AUDIO_SEND", "1")
    monkeypatch.setenv("MIRROR_AUDIO_LIVE_CMD", '"%s" "%s"' % (sys.executable, feeder))
    monkeypatch.setenv("MIRROR_AUDIO_LIVE_BUFFER", "2")
    monkeypatch.setenv("MIRROR_AUDIO_PREBUFFER", "2")

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
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
    """8192 is a length, not a length limit to fall short of.

    The reader treats a prefix over 8192 as a lost sync and walks forward a
    byte at a time. That makes the number a boundary in both directions:
    8192 has to be accepted, because an AAC frame may be that long, and
    8193 has to be refused, because a run of data misread as a length
    usually is enormous.

    Every audio fixture in this package is a few dozen bytes, so the cap
    could be moved either way without a test noticing. This one sends a
    frame of exactly 8192 between two small ones and requires all three
    back, in order: lowering the cap turns the middle frame's prefix into a
    resync, and everything after it is read from the wrong offset.
    """
    frames = [b"\x71" * 48, b"\x72" * 8192, b"\x73" * 64]
    # ...and one byte over the cap, as a bare prefix with nothing behind it.
    # Accepted, the reader waits for 8193 bytes that never come and the frame
    # after it never ships; refused, it walks forward until the lengths make
    # sense again and delivers it. Four shifts, because the bogus prefix is
    # four bytes.
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

    monkeypatch.setenv("MIRROR_AUDIO_SEND", "1")
    monkeypatch.setenv("MIRROR_AUDIO_LIVE_CMD", '"%s" "%s"' % (sys.executable, feeder))
    monkeypatch.setenv("MIRROR_AUDIO_PREBUFFER", "3")

    async with driven_session(monkeypatch, airparrot=True) as (receiver, sess):
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


@pytest.mark.asyncio
async def test_the_avconference_audio_channel_uses_the_audio_salt(monkeypatch):
    """The one media channel the suite never opened.

    Audio is not part of the modern mirror SETUP, so this branch wants both
    a negotiated ``audioDataPort`` and the AVConference dialect. Every test
    has had one or the other and none has had both, which left the body
    unexecuted: opening it, and which salt and channel class it opens with.

    Those are worth pinning because they are a copy-paste apart from the
    control channel's, three lines up, and getting them wrong yields a
    channel that opens, encrypts under keys the receiver did not derive,
    and carries audio nobody can decode. ``MirrorAudio-Salt`` is a bare
    constant -- no stream id appended, unlike the control channel's -- so
    it is the pairing of salt, info strings and channel class that matters.
    """
    monkeypatch.setenv("MIRROR_AIRPARROT", "0")
    opener = AsyncMock(return_value=(MagicMock(), MagicMock()))

    ctx = context.MirrorContext(
        stream_encryptor=framing.MirrorEncryptor.from_key_iv(b"\x00" * 16, b"\x01" * 16)
    )
    ctx.stream_control_port = 7001
    ctx.audio_data_port = 7002
    ctx.video_data_port = 7003

    sess = session.MirrorSession(
        rtsp=_fake_rtsp([_ok()], _ok()),
        verifier=MagicMock(),
        ctx=ctx,
        h264_path=TEST_FILE,
        channel_opener=opener,
    )

    # `_setup_streams` normally binds this, and the datagram endpoint is
    # handed the socket rather than an address so the announced
    # networkInfo.Port is the one datagrams leave from. Without it the video
    # step raises and the audio channel below is never reached.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sess._video_sock = sock  # noqa: SLF001
    try:
        await sess._open_channels()  # noqa: SLF001
    finally:
        await sess.stop()

    audio_calls = [
        call
        for call in opener.call_args_list
        if call.args and call.args[0] is streams.AudioStreamChannel
    ]
    assert audio_calls, "the audio channel was never opened: %s" % [
        c.args[0].__name__ for c in opener.call_args_list if c.args
    ]
    _cls, _addr, port, salt, out_info, in_info = audio_calls[0].args[:6]
    assert port == 7002, "opened on port %s, not the negotiated audioDataPort" % port
    assert salt == "MirrorAudio-Salt", salt
    assert out_info == "MirrorAudio-Output-Encryption-Key", out_info
    assert in_info == "MirrorAudio-Input-Encryption-Key", in_info
