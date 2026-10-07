"""In-process AirPlay 2 mirror receiver for driving a MirrorSession in tests.

It serves RTSP/HTTP control on a random local port and answers /fp-setup,
/auth-setup, /info, SETUP, RECORD and TEARDOWN. A type-96 audio SETUP returns
the ``eventPort``, RECORD follows, and the type-110 video SETUP returns a TCP
``dataPort``. The event channel is RTSP driven by the receiver. Data sockets
count (and partly retain) what arrives; the fake does not decrypt video.
"""

from __future__ import annotations

import asyncio
import logging
import plistlib
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

_LOGGER = logging.getLogger(__name__)

#: Reason phrases for the status codes tests ask the fake to send. 250 is a
#: 2xx other than 200: the only way to reach session.py's ``resp.code != 200``
#: guards, since pyatv's HTTP layer raises for anything outside 2xx.
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
# The fake answers 200 to any SETUP, so these checks are what make a changed
# protocol constant in session.py fail a test. They are a second copy of the
# captured values, deliberately not imported from the production module.
# Protocol constants are pinned; per-session values (IDs, ports, UUIDs) are
# checked for presence and shape only.

#: ``streams[0]`` of the screen-audio SETUP, as captured against tvOS 26.
CAPTURED_AUDIO_STREAM: Dict[str, Any] = {
    # Screen-audio stream type (110 is screen video).
    "type": 96,
    # Jitter buffer in 44.1 kHz sample frames (85 ms); min == max asks for a
    # fixed-latency buffer.
    "latencyMin": 3750,
    "latencyMax": 3750,
    # Each audio packet is sent twice; the receiver de-duplicates by sequence.
    "redundantAudio": 2,
    # Compression type 8 is AAC-ELD, what ``ScreenAudioPacketizer`` produces.
    "ct": 8,
    # Format bit for AAC-ELD 44100/2; must agree with ``ct``.
    "audioFormat": 0x1000000,
    # Mirroring audio rather than a standalone AirPlay audio stream.
    "usingScreen": True,
}

#: Top-level (outside ``streams``) constants of the audio SETUP.
CAPTURED_AUDIO_TOP: Dict[str, Any] = {
    # Encryption type 32 is FairPlay SAP v3 (the ekey/eiv beside it).
    "et": 32,
}

#: ``streams[0]`` of the screen-video SETUP.
CAPTURED_VIDEO_STREAM_TCP: Dict[str, Any] = {
    "type": 110,
}

#: The ``timestampInfo`` probe names, in order, used for latency reporting.
CAPTURED_TIMESTAMP_NAMES = ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"]

#: Captured ``spf`` -- samples per AAC-ELD frame.
CAPTURED_AUDIO_SPF = 480

#: Captured ``et`` of the video SETUP.
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
    """Check the per-session identity fields for presence and shape only."""
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
    """Check that ``streamConnectionID`` fits the receiver's ``bits``-bit field."""
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
    problems += _check_stream_connection_id("audio stream", stream, 32)

    if stream.get("spf") != CAPTURED_AUDIO_SPF:
        problems.append(
            f"audio stream: spf is {stream.get('spf')!r}, "
            f"captured is {CAPTURED_AUDIO_SPF}"
        )
    # Sender's UDP port for audio sync; the receiver sends to it.
    control_port = stream.get("controlPort")
    if not isinstance(control_port, int) or not 0 < control_port < 65536:
        problems.append(f"audio stream: controlPort {control_port!r} is not bound")
    # et=32 requires the FairPlay ekey/eiv.
    if not isinstance(body.get("ekey"), bytes) or not body["ekey"]:
        problems.append("audio SETUP: et=32 but no ekey")
    if not isinstance(body.get("eiv"), bytes) or len(body["eiv"]) != 16:
        problems.append(f"audio SETUP: eiv {body.get('eiv')!r} is not 16 bytes")
    return problems


def check_video_setup(body: dict) -> List[str]:
    """Return every way this type-110 SETUP differs from the capture."""
    stream = body["streams"][0]
    problems = _check_constants("video stream", stream, CAPTURED_VIDEO_STREAM_TCP)
    problems += _check_stream_connection_id("video stream", stream, 32)

    names = [entry.get("name") for entry in stream.get("timestampInfo") or []]
    if names != CAPTURED_TIMESTAMP_NAMES:
        problems.append(
            f"video stream: timestampInfo names {names!r}, "
            f"captured is {CAPTURED_TIMESTAMP_NAMES!r}"
        )

    problems += _check_session_fields("video SETUP", body)
    if body.get("et") != CAPTURED_VIDEO_ET:
        problems.append(
            f"video SETUP: et is {body.get('et')!r}, captured is {CAPTURED_VIDEO_ET}"
        )
    return problems


def _abort_writers(writers: list[asyncio.StreamWriter]) -> None:
    """Force-drop every tracked connection so wait_closed() can complete."""
    while writers:
        writer = writers.pop()
        try:
            writer.transport.abort()
        except Exception:  # pragma: no cover - best effort teardown
            pass


class _FrameCounter:
    """Byte/frame tallies plus a "reached N frames" event.

    A "frame" is one read or datagram. ``wait_frames`` lets a test block until
    enough data arrived instead of sleeping; the timeout is only a guard.
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

    #: Bytes retained from the head of the stream (which starts with the
    #: plaintext avcC config) for tests that check content.
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
    """The receiver's end of the event channel.

    The receiver is the RTSP client here: it POSTs ``/command`` to the sender
    and ends the session if the sender never answers. The fake sends its
    requests as soon as the sender connects and records the reply.
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
        #: Defaults to a single session-active update.
        self.command_bodies = command_bodies
        #: Deliver POST /command as headers then body in two writes, as a
        #: request split across TCP segments would arrive.
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
    """Counts screen-audio datagrams (RTP data or sync packets)."""

    def __init__(self) -> None:
        super().__init__()
        self._transport: asyncio.DatagramTransport | None = None
        #: Every datagram received, in order, so tests can decrypt payloads.
        self.datagrams: list[bytes] = []
        #: Source ``(host, port)`` of each datagram. Sync packets must come
        #: from the port advertised as ``controlPort``.
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
        status_overrides: dict | None = None,
        omit_event_port: bool = False,
        command_bodies: Optional[List[bytes]] = None,
        omit_audio_control_port: bool = False,
        split_event_request: bool = False,
        dead_audio_data_port: bool = False,
        hang_up_event_channel: bool = False,
    ) -> None:
        # The keyword arguments make the fake misbehave so the sender's error
        # handling runs on real wire bytes. ``status_overrides`` maps a phase
        # ("setup_session", "setup_audio", "setup_video", "record", "info") to
        # the status code to answer it with.
        self.status_overrides = dict(status_overrides or {})
        #: Answer SETUP without the ``eventPort`` the sender needs.
        self.omit_event_port = omit_event_port
        #: Answer the type-96 audio SETUP without a ``controlPort``.
        self.omit_audio_control_port = omit_audio_control_port
        #: Advertise a screen-audio dataPort nothing is bound to, so the
        #: sender's connected UDP socket gets ICMP port-unreachable back.
        self.dead_audio_data_port = dead_audio_data_port
        # The type-110 dataPort is a plain TCP socket.
        self.video_server = _MirrorDataServer()
        # Screen audio: RTP data and sync packets, both UDP.
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
        #: Every way an arriving SETUP disagreed with the captured protocol;
        #: checked by ``assert_protocol_ok()``.
        self.protocol_violations: List[str] = []
        self._event_port = 49641
        self.record_received = False
        self.teardown_received = False
        self._server: asyncio.AbstractServer | None = None
        self._video_port = 0
        self._audio_port = 0
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

        The sender opens with a type-96 audio SETUP (answered with the
        ``eventPort``) and sends the type-110 video SETUP after RECORD. A
        SETUP without ``streams`` is recorded so tests can assert it is not
        sent.
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
        self.protocol_violations += check_video_setup(decoded)
        video_stream = {"type": 110, "dataPort": self._video_port}
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
        await self.audio_data_server.close()
        await self.audio_control_server.close()
        await self.event_server.close()
