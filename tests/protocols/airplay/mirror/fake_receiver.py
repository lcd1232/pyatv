"""In-process mock AirPlay 2 mirror receiver for integration testing.

Speaks just enough of the wire protocol to drive a MirrorSession start to
finish without requiring a real Apple TV:
  - HTTP/RTSP control on a randomly-allocated TCP port
  - /fp-setup: real X25519 ephemeral ECDH + fixed cert + fixed sig
  - /auth-setup: 200 OK
  - ANNOUNCE / SETUP / RECORD / TEARDOWN: respond 200 (with bplist body for SETUP)
  - Data sockets that count received bytes / "frames"

Both mirror dialects are modelled, selected by the ``airparrot`` flag:

  - AVConference: metadata-only session-init SETUP returning ``eventPort``,
    then a stream SETUP whose ``dataPort`` is UDP-only and which also
    negotiates a TCP media-data-control channel.
  - AirParrot (the dialect that renders on tvOS 26): no session init; a
    type-96 audio SETUP carries the ``eventPort``, RECORD follows, and the
    type-110 video SETUP returns a plain TCP ``dataPort``. The event channel
    is bidirectional RTSP driven by the receiver.

The fake is symmetric enough with the real receiver that a real
MirrorSession run against it derives the same AES-CTR keystream. It does
NOT decrypt the mirror frames it receives — for the integration test we
only assert that bytes/frames flowed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import plistlib
import re
import struct
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

_LOGGER = logging.getLogger(__name__)

#: Reason phrases for the status codes tests actually ask the fake to send.
#: 250 is RTSP's "Low on Storage Space" -- a *successful* 2xx that is
#: nonetheless not 200, which is the only way a receiver can trip the
#: ``resp.code != 200`` guards in session.py (pyatv's HTTP layer raises
#: HttpError for anything outside 2xx before those guards ever run).
_REASONS = {
    200: "OK",
    250: "Low on Storage Space",
    455: "Method Not Valid In This State",
    500: "Internal Server Error",
}


# ---------------------------------------------------------------------------
# What a real receiver reads out of a SETUP body
# ---------------------------------------------------------------------------
#
# The fake dispatches on ``streams[0]["type"]`` and answers 200 regardless of
# everything else in the body, so without the checks below any captured
# constant in session.py could be changed and every test would stay green --
# while a real tvOS 26 receiver would reject the SETUP or mis-configure the
# stream. These tables are an independent second copy of the captured values,
# deliberately *not* imported from the production module: the whole point is
# that the sender and the expectation can disagree.
#
# Three kinds of field live in a SETUP body and only the first is pinned:
#
#   * captured protocol constants -- the receiver interprets them, they came
#     off the wire from a real sender, and any other value is a bug. Pinned.
#   * per-session values -- IDs, ports, UUIDs. Checked for presence and shape
#     only; pinning them would pin randomness.
#   * environment-tunable values -- ``spf``/``et`` have MIRROR_* overrides, so
#     they are checked against "the override, or the captured default".

#: ``streams[0]`` of the AirParrot screen-audio SETUP. RE'd from AirParrot's
#: negotiation callback (@0x10008e1a4) and seen on the wire in the Phase 28
#: capture against tvOS 26.
CAPTURED_AUDIO_STREAM: Dict[str, Any] = {
    # 96 is the screen-audio stream type (the soundtrack of a mirroring
    # session); 110 below is the screen video. The receiver keys its whole
    # stream-configuration branch off this number.
    "type": 96,
    # Jitter-buffer bounds, in 44.1 kHz sample frames: 3750 / 44100 = 85 ms.
    # The sender pins min == max, which asks the receiver for a fixed-latency
    # buffer instead of an adaptive one.
    "latencyMin": 3750,
    "latencyMax": 3750,
    # Each audio packet is transmitted twice; the receiver de-duplicates by
    # RTP sequence number. Sending a different factor than the one the
    # receiver is told to expect desynchronises that de-duplication.
    "redundantAudio": 2,
    # Compression type 8 == AAC-ELD, which is what
    # ``airparrot_audio.AirParrotAudioPacketizer`` actually produces. A
    # mismatch here points the receiver's decoder at the wrong codec.
    "ct": 8,
    # Format bitfield: 0x1000000 is the single AAC-ELD 44100/2 entry. It must
    # agree with ``ct`` -- both name the same codec, in two encodings.
    "audioFormat": 0x1000000,
    # Marks this as mirroring audio rather than a standalone AirPlay audio
    # stream, which is what makes the receiver accept the type-110 video
    # SETUP that follows.
    "usingScreen": True,
}

#: Top-level (outside ``streams``) constants of the audio SETUP.
CAPTURED_AUDIO_TOP: Dict[str, Any] = {
    # Encryption type 32 == FairPlay SAP v3, the keying the ekey/eiv beside it
    # belong to. Unlike the video SETUP's ``et`` this one has no MIRROR_ET
    # override -- the audio stream is always FairPlay-keyed.
    "et": 32,
}

#: ``streams[0]`` of the AirParrot screen-video SETUP.
CAPTURED_VIDEO_STREAM_AIRPARROT: Dict[str, Any] = {
    # AirParrot's screen-video stream type. The AVConference dialect uses the
    # same number, reached via framing.STREAM_TYPE_VIDEO.
    "type": 110,
}

#: ``streams[0]`` of the AVConference (macOS-sender) screen-video SETUP.
CAPTURED_VIDEO_STREAM_AVCONF: Dict[str, Any] = {
    "type": 110,
    # Selects the AVConference mirroring pipeline. Without it the receiver
    # falls back to the legacy AirPlay-1 path and never renders.
    "useAVConfMirroring": True,
    # The captured macOS sender advertises an SDR pipeline and no HDR support;
    # claiming HDR commits the sender to colour metadata it does not send.
    "displayHDRMode": "SDR",
    "hdrMirroringSupported": False,
    # 0 == plain mirroring (as opposed to the extended-display modes).
    "streamMode": 0,
    # Receiver-side logging/HUD debug switches. The capture has them off, and
    # turning either on changes what the receiver does with the stream.
    "remoteLogLevel": 0,
    "remoteShouldShowHUD": False,
}

#: The ``timestampInfo`` probe names, in order, as the capture sends them.
#: They label the timestamps the receiver reports back for latency
#: accounting: submission, before/after pixel transfer, before encode, and
#: encode-emitted. Both dialects send the same five.
CAPTURED_TIMESTAMP_NAMES = ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"]

#: Captured default for ``spf`` -- samples per AAC-ELD frame. Overridable via
#: MIRROR_AUDIO_SPF, so it is checked against the override when one is set.
CAPTURED_AUDIO_SPF = 480

#: Captured default for the video SETUP's ``et``. Overridable via MIRROR_ET
#: (0 selects an unencrypted stream for experiments).
CAPTURED_VIDEO_ET = 32

#: A synthesized MAC-shaped device ID, e.g. ``0A:1B:2C:3D:4E:5F``.
_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
#: An upper-case RFC-4122 UUID, which is the shape real senders send.
_UUID_RE = re.compile(r"^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$")


def _check_constants(where: str, actual: dict, expected: Dict[str, Any]) -> List[str]:
    """Report every captured constant that is missing or has been changed."""
    problems = []
    for key, want in expected.items():
        if key not in actual:
            problems.append(f"{where}: {key} missing (captured senders send {want!r})")
        elif actual[key] != want or type(actual[key]) is not type(want):
            problems.append(f"{where}: {key} is {actual[key]!r}, captured is {want!r}")
    return problems


def _check_session_fields(where: str, body: dict) -> List[str]:
    """Check the per-session identity block for presence and shape only.

    These values are freshly generated per run, so pinning them would pin
    randomness. A real receiver still depends on them being well-formed: it
    indexes sessions by ``sessionUUID`` and senders by ``deviceID``.
    """
    problems = []
    uuid = body.get("sessionUUID")
    if not isinstance(uuid, str) or not _UUID_RE.match(uuid):
        problems.append(f"{where}: sessionUUID {uuid!r} is not an upper-case UUID")
    for key in ("deviceID", "macAddress"):
        value = body.get(key)
        if not isinstance(value, str) or not _MAC_RE.match(value):
            problems.append(f"{where}: {key} {value!r} is not a MAC-shaped ID")
    for key in ("osBuildVersion", "sourceVersion", "name", "model"):
        if not isinstance(body.get(key), str) or not body.get(key):
            problems.append(f"{where}: {key} missing or empty")
    port = body.get("timingPort")
    if not isinstance(port, int) or not 0 < port < 65536:
        problems.append(f"{where}: timingPort {port!r} is not a bound UDP port")
    return problems


def _check_stream_connection_id(where: str, stream: dict, bits: int) -> List[str]:
    """``streamConnectionID`` is per-session but must fit the receiver's field.

    The receiver rebuilds the key-derivation label from this id, so it has to
    fit whatever width that dialect's receiver stores it in: AirParrot's
    receiver uses a 32-bit field, while the AVConference one takes the 63-bit
    value the macOS sender generates.
    """
    sid = stream.get("streamConnectionID")
    if not isinstance(sid, int) or not 0 < sid < 2**bits:
        return [f"{where}: streamConnectionID {sid!r} is not a {bits}-bit id"]
    return []


def check_audio_setup(body: dict) -> List[str]:
    """Return every way this type-96 SETUP differs from the capture."""
    stream = body["streams"][0]
    problems = _check_constants("audio stream", stream, CAPTURED_AUDIO_STREAM)
    problems += _check_constants("audio SETUP", body, CAPTURED_AUDIO_TOP)
    problems += _check_session_fields("audio SETUP", body)
    # Screen audio is AirParrot-dialect only, so always the 32-bit form.
    problems += _check_stream_connection_id("audio stream", stream, 32)

    want_spf = int(os.environ.get("MIRROR_AUDIO_SPF", str(CAPTURED_AUDIO_SPF)))
    if stream.get("spf") != want_spf:
        problems.append(
            f"audio stream: spf is {stream.get('spf')!r}, "
            f"expected {want_spf} (MIRROR_AUDIO_SPF or the captured default)"
        )
    # The UDP port the sender will receive audio sync packets on. Per-session,
    # but the receiver sends to it, so it must be a real bound port.
    control_port = stream.get("controlPort")
    if not isinstance(control_port, int) or not 0 < control_port < 65536:
        problems.append(f"audio stream: controlPort {control_port!r} is not bound")
    # FairPlay key transport. et=32 above promises these are here.
    if not isinstance(body.get("ekey"), bytes) or not body["ekey"]:
        problems.append("audio SETUP: et=32 but no ekey")
    if not isinstance(body.get("eiv"), bytes) or len(body["eiv"]) != 16:
        problems.append(f"audio SETUP: eiv {body.get('eiv')!r} is not 16 bytes")
    return problems


def check_video_setup(body: dict, airparrot: bool) -> List[str]:
    """Return every way this type-110 SETUP differs from the capture."""
    stream = body["streams"][0]
    expected = (
        CAPTURED_VIDEO_STREAM_AIRPARROT if airparrot else CAPTURED_VIDEO_STREAM_AVCONF
    )
    problems = _check_constants("video stream", stream, expected)
    problems += _check_stream_connection_id(
        "video stream", stream, 32 if airparrot else 63
    )

    names = [entry.get("name") for entry in stream.get("timestampInfo") or []]
    if names != CAPTURED_TIMESTAMP_NAMES:
        problems.append(
            f"video stream: timestampInfo names {names!r}, "
            f"captured is {CAPTURED_TIMESTAMP_NAMES!r}"
        )

    if airparrot:
        problems += _check_session_fields("video SETUP", body)
        want_et = int(os.environ.get("MIRROR_ET", str(CAPTURED_VIDEO_ET)))
        if body.get("et") != want_et:
            problems.append(
                f"video SETUP: et is {body.get('et')!r}, "
                f"expected {want_et} (MIRROR_ET or the captured default)"
            )
    else:
        # The AVConference dialect keys from seeds it generates per session
        # rather than transporting a FairPlay ekey.
        for key in ("encryptionSeed",):
            if not isinstance(stream.get(key), int):
                problems.append(f"video stream: {key} missing or not an int")
        control = (stream.get("streamConnections") or {}).get(
            "streamConnectionTypeMediaDataControl", {}
        )
        if not isinstance(control.get("streamConnectionKeyEncryptionSeed"), int):
            problems.append("video stream: control-channel encryption seed missing")
        port = (stream.get("networkInfo") or {}).get("Port")
        if not isinstance(port, int) or not 0 < port < 65536:
            problems.append(f"video stream: networkInfo.Port {port!r} is not bound")
        if not isinstance(stream.get("negotiationData"), bytes):
            problems.append("video stream: negotiationData missing")
    return problems


def _abort_writers(writers: list[asyncio.StreamWriter]) -> None:
    """Force-drop every tracked connection so wait_closed() can complete."""
    while writers:
        writer = writers.pop()
        try:
            writer.transport.abort()
        except Exception:  # pragma: no cover - best effort teardown
            pass


class RawChannelOpener:
    """Channel opener for tests: opens raw TCP and returns a fake channel.

    Forwards ``send(bytes)`` to the writer and returns a fake transport whose
    ``close()`` closes the writer. Bypasses HAP per-channel encryption -- the
    fake receiver counts bytes on the wire directly.
    """

    def __init__(self):
        self.connections = []  # (salt, writer, reader)

    async def __call__(self, factory, addr, port, salt, out_info, in_info):
        reader, writer = await asyncio.open_connection(addr, port)
        self.connections.append((salt, writer, reader))

        channel = MagicMock()
        channel.send = writer.write

        transport = MagicMock()

        def _close() -> None:
            try:
                writer.transport.abort()
            except Exception:
                pass

        transport.close = _close
        return transport, channel

    def close_all(self) -> None:
        """Drop every connection we opened, so the fake's servers can close."""
        for _salt, writer, _reader in self.connections:
            try:
                writer.transport.abort()
            except Exception:
                pass
        self.connections.clear()


class _FrameCounter:
    """Byte/frame tallies plus a "reached N frames" event.

    ``wait_frames`` is what makes the integration test deterministic: instead
    of sleeping for a guessed duration and hoping enough frames arrived, the
    test blocks until the Nth frame has actually been counted. The timeout is
    only a failure guard, never a pacing device.
    """

    def __init__(self) -> None:
        self.bytes_received = 0
        self.frames_received = 0
        self.first_byte_event = asyncio.Event()
        self._target = 0
        self._target_event = asyncio.Event()

    def _count(self, size: int) -> None:
        self.bytes_received += size
        self.frames_received += 1
        if not self.first_byte_event.is_set():
            self.first_byte_event.set()
        if self._target and self.frames_received >= self._target:
            self._target_event.set()

    async def wait_frames(self, count: int, timeout: float = 30.0) -> None:
        """Block until ``count`` frames have been received."""
        self._target = count
        if self.frames_received >= count:
            return
        self._target_event.clear()
        await asyncio.wait_for(self._target_event.wait(), timeout=timeout)


class _MirrorDataServer(_FrameCounter):
    """Counts bytes/frame-bursts received on the video or audio data port."""

    #: Bytes retained from the head of the stream, for tests that need to see
    #: what was sent rather than only how much. Bounded because a session
    #: streams indefinitely; the first message is the plaintext avcC config,
    #: which is what anything checking content cares about.
    RETAIN_BYTES = 64 * 1024

    def __init__(self) -> None:
        super().__init__()
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self.head: bytes = b""

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        sock = self._server.sockets[0]
        return sock.getsockname()[1]

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        _LOGGER.debug("data server: new connection handler started")
        self._writers.append(writer)
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    _LOGGER.debug(
                        "data server: EOF, done. bytes=%d frames=%d",
                        self.bytes_received,
                        self.frames_received,
                    )
                    return
                if len(self.head) < self.RETAIN_BYTES:
                    self.head += chunk[: self.RETAIN_BYTES - len(self.head)]
                self._count(len(chunk))
        except (ConnectionResetError, asyncio.CancelledError):
            return
        except Exception:
            _LOGGER.exception("data server handler crashed")
        finally:
            # Always close the writer so asyncio.Server.wait_closed() can
            # detect that the connection has been fully dropped.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def close(self) -> None:
        # Python 3.12's Server.wait_closed() waits for every live connection
        # handler to finish, so a peer that never hung up would block teardown
        # forever. Drop our side of each connection first.
        _abort_writers(self._writers)
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class _MirrorEventServer(_MirrorDataServer):
    """The receiver's end of the AirParrot event channel.

    The event channel is bidirectional RTSP with the *receiver* as the client:
    it POSTs ``/command`` to the sender and tears the whole mirror session down
    if the sender never answers. Model that by issuing one request as soon as
    the sender connects and recording its reply.
    """

    def __init__(
        self,
        split_request: bool = False,
        command_bodies: Optional[List[bytes]] = None,
        hang_up_after_reply: bool = False,
    ) -> None:
        super().__init__()
        self.command_response = b""
        self.command_answered = asyncio.Event()
        #: Close the event connection once the sender has answered, so its
        #: reader sees EOF rather than a live idle socket.
        self.hang_up_after_reply = hang_up_after_reply
        #: Bodies to send, one POST /command each, CSeq counting from 7.
        #: The default is a single session-active update. Supplying several --
        #: especially with ``\r\n\r\n`` inside one -- is what tells a reader
        #: that frames on Content-Length from one that hunts for a blank line.
        self.command_bodies = command_bodies
        #: Deliver POST /command as headers-then-body in two separate writes.
        #: A real receiver's request can arrive split across TCP segments, and
        #: the sender must buffer rather than answer a half-read request.
        self.split_request = split_request

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._writers.append(writer)
        try:
            bodies = self.command_bodies
            if bodies is None:
                bodies = [
                    plistlib.dumps(
                        {"updateInfo": {"sessionActive": True}},
                        fmt=plistlib.FMT_BINARY,
                    )
                ]
            for index, body in enumerate(bodies):
                head = (
                    b"POST /command RTSP/1.0\r\n"
                    b"CSeq: " + str(7 + index).encode() + b"\r\n"
                    b"Content-Type: application/x-apple-binary-plist\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                )
                if self.split_request:
                    # Headers first; the body follows only after the sender has
                    # had a chance to read (and must buffer) the partial request.
                    writer.write(head)
                    await writer.drain()
                    for _ in range(5):
                        await asyncio.sleep(0)
                    writer.write(body)
                else:
                    writer.write(head + body)
            await writer.drain()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                self._count(len(chunk))
                self.command_response += chunk
                if b"\r\n\r\n" in self.command_response:
                    self.command_answered.set()
                    if self.hang_up_after_reply:
                        # Half-close, as a receiver that has finished with the
                        # channel does: the sender's next read returns b"".
                        writer.close()
                        return
        except (ConnectionResetError, asyncio.CancelledError):
            return
        except Exception:
            _LOGGER.exception("event server handler crashed")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class _MirrorDatagramServer(_FrameCounter):
    """Counts mirror video datagrams, as a real receiver's dataPort does.

    The Apple TV's ``dataPort`` accepts UDP only in the AVConference dialect
    (TCP to it is refused), so the video stream arrives here as datagrams
    rather than a byte stream.
    """

    def __init__(self) -> None:
        super().__init__()
        self._transport: asyncio.DatagramTransport | None = None
        #: Every datagram received, in arrival order. Retained (not just
        #: counted) so a test can inspect the RTP framing and decrypt the
        #: payload -- the only way to see which key actually encrypted the
        #: wire, since the sender's SRTP encryptors never leave ``session.py``.
        self.datagrams: list[bytes] = []
        #: Source ``(host, port)`` of each datagram, in the same order. The
        #: screen-audio sync must leave from the socket whose port was
        #: advertised as ``controlPort``, or the receiver never opens its
        #: audio control channel -- so which socket sent it is part of the
        #: protocol, not an implementation detail.
        self.sources: list[tuple] = []

    class _Protocol(asyncio.DatagramProtocol):
        def __init__(self, owner: "_MirrorDatagramServer") -> None:
            self._owner = owner

        def datagram_received(self, data: bytes, addr) -> None:
            self._owner.datagrams.append(data)
            self._owner.sources.append(addr)
            self._owner._count(len(data))

    async def start(self) -> int:
        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self._Protocol(self), local_addr=("127.0.0.1", 0)
        )
        self._transport = transport
        return transport.get_extra_info("socket").getsockname()[1]

    async def close(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None


class FakeMirrorReceiver:
    """Listens on a TCP port and serves the minimal RTSP+MFiSAP protocol."""

    def __init__(
        self,
        airparrot: bool = False,
        status_overrides: dict | None = None,
        omit_event_port: bool = False,
        command_bodies: Optional[List[bytes]] = None,
        omit_audio_control_port: bool = False,
        split_event_request: bool = False,
        dead_control_port: bool = False,
        dead_audio_data_port: bool = False,
        hang_up_event_channel: bool = False,
    ) -> None:
        # Dialect split, taken from probing a real tvOS 26 receiver: the
        # AVConference dataPort is UDP-only, while the AirParrot type-110
        # dataPort is a plain TCP socket.
        self.airparrot = airparrot
        # Misbehaviour knobs. A cooperative receiver is the default; these let
        # a test make the fake answer the way a confused or older receiver
        # does, so the sender's error handling runs on real wire bytes rather
        # than on a monkeypatched internal.
        #
        # ``status_overrides`` maps a phase name -- "setup_session",
        # "setup_audio", "setup_video", "record", "info" -- to the status code
        # to answer it with.
        self.status_overrides = dict(status_overrides or {})
        #: Answer SETUP without the ``eventPort`` the sender needs.
        self.omit_event_port = omit_event_port
        #: Answer the type-96 audio SETUP without a ``controlPort``.
        self.omit_audio_control_port = omit_audio_control_port
        #: Advertise a media-data-control port that nothing is listening on.
        #: A receiver that answers SETUP before it opens the socket -- or that
        #: never opens it -- looks exactly like this to the sender. Port 1 is
        #: used because a connection there is refused immediately and
        #: deterministically, with no bind/close race.
        self.dead_control_port = dead_control_port
        #: Advertise a screen-audio dataPort nothing is bound to, so the
        #: sender's connected UDP socket gets ICMP port-unreachable back.
        self.dead_audio_data_port = dead_audio_data_port
        self.video_server = (
            _MirrorDataServer() if airparrot else _MirrorDatagramServer()
        )
        # The AVConference media-data-control channel (TCP). No mirror media
        # is ever written here, so its tally is expected to stay at zero.
        self.control_server = _MirrorDataServer()
        # AirParrot screen audio: RTP data and sync packets, both UDP.
        self.audio_data_server = _MirrorDatagramServer()
        self.audio_control_server = _MirrorDatagramServer()
        # The sender connects to the eventPort we report from SETUP.
        self.event_server = _MirrorEventServer(
            split_request=split_event_request,
            command_bodies=command_bodies,
            hang_up_after_reply=hang_up_event_channel,
        )
        self._control_writers: list[asyncio.StreamWriter] = []
        self.fp_setup_received = False
        self.auth_setup_received = False
        self.announce_received = False
        self.info_requests = 0
        self.setup_count = 0
        self.session_setup_received = False
        self.audio_setup_received = False
        self.stream_setup_received = False
        #: FairPlay key-transport fields as they arrived in each stream SETUP.
        #: The fake cannot unwrap an ``ekey`` (that needs the receiver half of
        #: FairPlay), but recording the bytes lets a test assert that whatever
        #: the sender derived is what actually reached the wire.
        self.video_setup_ekey: bytes | None = None
        self.video_setup_eiv: bytes | None = None
        self.video_setup_et = None
        self.audio_setup_ekey: bytes | None = None
        self.audio_setup_eiv: bytes | None = None
        #: The decoded SETUP bodies as they arrived, for tests that want to
        #: assert something beyond the standing protocol checks.
        self.session_setup_body: dict | None = None
        self.audio_setup_body: dict | None = None
        self.video_setup_body: dict | None = None
        #: Every way an arriving SETUP disagreed with the captured tvOS 26
        #: protocol. A real receiver interprets these fields; this fake would
        #: otherwise answer 200 to anything, so the checks are what makes a
        #: changed constant visible. Tests read this via
        #: ``assert_protocol_ok()``.
        self.protocol_violations: List[str] = []
        self._event_port = 49641
        self.record_received = False
        self.teardown_received = False
        self._server: asyncio.AbstractServer | None = None
        self._video_port = 0
        self._audio_port = 0
        self._control_port = 0
        self._audio_control_port = 0

        # Ephemeral X25519 keypair for the fake server side
        self._server_sk = x25519.X25519PrivateKey.generate()
        self._server_pk_bytes = self._server_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # Fixed cert + sig (any bytes — client doesn't validate)
        self._cert = b"FAKE-CERT-DER-BYTES-" + b"\x42" * 16
        self._sig = b"FAKE-SIGNATURE-BYTES-" + b"\x99" * 12

    @property
    def server_pubkey(self) -> bytes:
        return self._server_pk_bytes

    def assert_protocol_ok(self) -> None:
        """Fail if any SETUP disagreed with the captured tvOS 26 protocol.

        Raising from inside ``_dispatch_setup`` would be swallowed by the
        control handler's catch-all and surface as a hang, so violations are
        accumulated there and asserted here, from the test's own task.
        """
        assert not self.protocol_violations, (
            "SETUP body disagrees with the captured tvOS 26 protocol:\n  "
            + "\n  ".join(self.protocol_violations)
        )

    async def start(self) -> Tuple[str, int]:
        """Start listening; return (host, port) for the control connection."""
        self._video_port = await self.video_server.start()
        self._control_port = await self.control_server.start()
        self._audio_port = await self.audio_data_server.start()
        self._audio_control_port = await self.audio_control_server.start()
        self._event_port = await self.event_server.start()
        self._server = await asyncio.start_server(self._handle_control, "127.0.0.1", 0)
        sock = self._server.sockets[0]
        host, port = sock.getsockname()[:2]
        return host, port

    async def _handle_control(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self._control_writers.append(writer)
        try:
            while True:
                _LOGGER.debug("control handler: waiting for next request line")
                line = await reader.readline()
                if not line:
                    _LOGGER.debug("control handler: EOF (empty line), returning")
                    return
                request_line = line.decode("latin-1").strip()
                _LOGGER.debug("control handler: got request line %r", request_line)
                headers = {}
                while True:
                    hl = await reader.readline()
                    if hl in (b"\r\n", b"\n", b""):
                        break
                    text = hl.decode("latin-1").strip()
                    if ":" in text:
                        k, _, v = text.partition(":")
                        headers[k.strip().lower()] = v.strip()
                content_length = int(headers.get("content-length", "0"))
                body = (
                    await reader.readexactly(content_length) if content_length else b""
                )

                method = request_line.split(" ", 1)[0]
                cseq = headers.get("cseq", "0")
                proto = "RTSP/1.0" if "RTSP" in request_line else "HTTP/1.1"
                resp_body, ctype, status = self._dispatch(method, request_line, body)
                reason = _REASONS.get(status, "Error" if status >= 300 else "OK")
                resp_lines = [f"{proto} {status} {reason}", f"CSeq: {cseq}"]
                if ctype:
                    resp_lines.append(f"Content-Type: {ctype}")
                resp_lines.append(f"Content-Length: {len(resp_body)}")
                resp = ("\r\n".join(resp_lines) + "\r\n\r\n").encode() + resp_body
                writer.write(resp)
                await writer.drain()
                if self.teardown_received:
                    return
        except (
            asyncio.IncompleteReadError,
            ConnectionResetError,
            asyncio.CancelledError,
        ):
            return
        except Exception:
            _LOGGER.exception("control handler crashed")
        finally:
            # Always close the writer so asyncio.Server.wait_closed() can
            # detect that the connection has been fully dropped.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _dispatch_setup(self, body: bytes) -> Tuple[bytes, str | None, int]:
        """Answer a SETUP, distinguishing session-init / audio / video.

        Modern AirPlay 2 mirroring uses a two-phase SETUP (Phase 28 capture):
        a metadata-only session init that answers with ``eventPort``, then a
        ``streams`` request answered with the negotiated data/control ports.
        The AirParrot dialect drops the session init and instead opens with a
        type-96 audio stream SETUP (which carries the ``eventPort``), then
        sends the type-110 video stream SETUP after RECORD.
        """
        decoded = {}
        if body:
            try:
                decoded = plistlib.loads(bytes(body))
            except Exception:  # pragma: no cover - malformed body
                decoded = {}
        streams = decoded.get("streams") if isinstance(decoded, dict) else None
        if not streams:
            self.session_setup_received = True
            self.session_setup_body = decoded
            payload = {}
            if not self.omit_event_port:
                payload["eventPort"] = self._event_port
            return (
                plistlib.dumps(payload, fmt=plistlib.FMT_BINARY),
                "application/x-apple-binary-plist",
                self.status_overrides.get("setup_session", 200),
            )

        stream_type = streams[0].get("type")
        if stream_type == 96:
            # AirParrot's screen-audio stream. Its response is where the
            # sender learns the eventPort in that dialect.
            self.audio_setup_received = True
            # ekey/eiv/et sit at the top level of the SETUP body, alongside
            # "streams" -- not inside the stream dict.
            self.audio_setup_ekey = decoded.get("ekey")
            self.audio_setup_eiv = decoded.get("eiv")
            self.audio_setup_body = decoded
            self.protocol_violations += check_audio_setup(decoded)
            audio_stream = {
                "type": 96,
                "dataPort": 1 if self.dead_audio_data_port else self._audio_port,
            }
            if not self.omit_audio_control_port:
                audio_stream["controlPort"] = self._audio_control_port
            payload = {"streams": [audio_stream]}
            if not self.omit_event_port:
                payload["eventPort"] = self._event_port
            return (
                plistlib.dumps(payload, fmt=plistlib.FMT_BINARY),
                "application/x-apple-binary-plist",
                self.status_overrides.get("setup_audio", 200),
            )

        self.stream_setup_received = True
        self.video_setup_ekey = decoded.get("ekey")
        self.video_setup_eiv = decoded.get("eiv")
        self.video_setup_et = decoded.get("et")
        self.video_setup_body = decoded
        self.protocol_violations += check_video_setup(decoded, self.airparrot)
        video_stream = {"type": 110, "dataPort": self._video_port}
        if not self.airparrot:
            # Only the AVConference dialect negotiates a separate HAP-encrypted
            # media-data-control channel.
            video_stream["streamConnections"] = {
                "streamConnectionTypeMediaDataControl": {
                    "streamConnectionKeyPort": (
                        1 if self.dead_control_port else self._control_port
                    ),
                }
            }
        return (
            plistlib.dumps({"streams": [video_stream]}, fmt=plistlib.FMT_BINARY),
            "application/x-apple-binary-plist",
            self.status_overrides.get("setup_video", 200),
        )

    def _dispatch(
        self, method: str, request_line: str, body: bytes
    ) -> Tuple[bytes, str | None, int]:
        if (
            method == "POST"
            and "/fp-setup" in request_line
            and "/fp-setup2" not in request_line
        ):
            self.fp_setup_received = True
            # M2 = server_pubkey || BE32(cert_len) || BE32(sig_len) || cert || sig
            m2 = (
                self._server_pk_bytes
                + struct.pack(">II", len(self._cert), len(self._sig))
                + self._cert
                + self._sig
            )
            return m2, "application/octet-stream", 200
        if method == "POST" and "/auth-setup" in request_line:
            self.auth_setup_received = True
            return b"", None, 200
        if method == "GET" and "/info" in request_line:
            self.info_requests += 1
            payload = plistlib.dumps(
                {
                    "model": "AppleTV11,1",
                    "sourceVersion": "960.13.1",
                    "hasUDPMirroringSupport": True,
                    "deviceID": "AA:BB:CC:DD:EE:FF",
                },
                fmt=plistlib.FMT_BINARY,
            )
            return (
                payload,
                "application/x-apple-binary-plist",
                self.status_overrides.get("info", 200),
            )
        if method == "ANNOUNCE":
            self.announce_received = True
            return b"", None, 200
        if method == "SETUP":
            self.setup_count += 1
            return self._dispatch_setup(body)
        if method == "RECORD":
            self.record_received = True
            return b"", None, self.status_overrides.get("record", 200)
        if method == "TEARDOWN":
            self.teardown_received = True
            return b"", None, 200
        # OPTIONS / heartbeat / anything else
        return b"", None, 200

    async def close(self) -> None:
        _abort_writers(self._control_writers)
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        await self.video_server.close()
        await self.control_server.close()
        await self.audio_data_server.close()
        await self.audio_control_server.close()
        await self.event_server.close()
