"""MirrorSession: orchestrates the AirPlay 2 mirror MVP.

Phases:
  A. Setup: SETUP (audio, type 96) → connect eventPort → RECORD → SETUP
     (video, type 110) → connect the raw-TCP video dataPort. There is no
     ANNOUNCE/SDP.
  B. Streaming: spawn the video producer + drain task (and, when a source is
     given, the screen-audio sender).
  C. Teardown: cancel tasks, send TEARDOWN, close channels.

The HTTP / pair-verify / MFiSAP setup happens before this class is
constructed — the caller passes in a connected RtspSession, a
PairVerifyProcedure, and a MirrorContext containing the MFiSAP-derived
stream_encryptor.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from pathlib import Path
import secrets
import socket
import time
from typing import Optional, cast
from uuid import uuid4

from pyatv import exceptions
from pyatv.auth.hap_pairing import PairVerifyProcedure
from pyatv.core.protocol import heartbeater
from pyatv.protocols.airplay.mirror import (
    framing,
    pacer,
    screen_audio,
    streams,
    tcp_stream,
)
from pyatv.protocols.airplay.mirror.context import MirrorContext
from pyatv.protocols.raop import timing as raop_timing
from pyatv.protocols.raop.protocols import TimingServer
from pyatv.support.http import decode_bplist_from_body
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

FEEDBACK_INTERVAL = 2.0  # seconds, matches AP2Session.start_keep_alive

QUEUE_HIGH_WATERMARK = 256

# RtspSession adds these RAOP remote-control headers to every request. The
# macOS sender captured in Phase 28 sends none of them on a mirroring session,
# so they are suppressed (RtspSession drops headers whose value is None).
_SUPPRESS_RAOP_HEADERS = {
    "DACP-ID": None,
    "Active-Remote": None,
    "Client-Instance": None,
}

# The Apple TV only offers screen mirroring to senders advertising a recent
# AirPlay version. pyatv's default (AirPlay/550.10) is iOS-12 era; the macOS
# sender captured in Phase 28 reports this and is accepted.
MIRROR_USER_AGENT = "AirPlay/870.14.1"

#: Seconds to wait for the stream SETUP response.
STREAM_SETUP_TIMEOUT = 30.0

#: Encryption type of both stream SETUPs: FairPlay SAP v3, with the stream
#: key transported in ``ekey``/``eiv``.
STREAM_ET = 32

#: Offset of the 16-byte FairPlay SAP secret inside the SAP context, used when
#: no chosen ``stream_raw16`` is available.
SAP_SECRET_OFFSET = 8

#: Seconds between the plaintext avcC config message and the first encrypted
#: frame, so the receiver can initialise its decoder first.
CONFIG_DELAY = 0.3

#: Access units buffered from a live video source (oldest dropped when full).
LIVE_VIDEO_BUFFER = 90
#: Seconds to let a live video source buffer before the first frame is sent.
LIVE_VIDEO_PREBUFFER = 0.5

#: AAC-ELD frames buffered from a live audio source (oldest dropped when full).
AUDIO_LIVE_BUFFER = 1200
#: Frames a live audio source must buffer (~2 s) before sending starts.
AUDIO_PREBUFFER = 180
#: Send one screen-audio sync packet every this many frames (~1/s).
AUDIO_SYNC_EVERY = max(
    1, int(screen_audio.AUDIO_SAMPLE_RATE / screen_audio.AUDIO_SAMPLES_PER_FRAME)
)


def _device_id_from_uuid(uuid_str: str) -> str:
    """Derive a stable MAC-address-shaped device ID from a session UUID.

    Real AirPlay senders pass their hardware MAC; we synthesize a stable
    pseudo-MAC from the session UUID's last 12 hex chars formatted as
    ``XX:XX:XX:XX:XX:XX`` (upper-case, as real senders send it). Apple TV
    accepts this — Phase 22's reference-sender
    helper also used a synthesized ID (not its real WiFi MAC) and was
    accepted on /fp-setup.
    """
    hex12 = uuid_str.replace("-", "")[-12:].upper()
    return ":".join(hex12[i : i + 2] for i in range(0, 12, 2))


class MirrorSession:
    """Orchestrates the mirror MVP: setup → stream → teardown."""

    def __init__(
        self,
        rtsp: RtspSession,
        verifier: PairVerifyProcedure,
        ctx: MirrorContext,
        h264_path: Path,
        *,
        video_command: Optional[str] = None,
        eld_path: Optional[Path] = None,
        audio_command: Optional[str] = None,
        pair_secret: Optional[bytes] = None,
    ) -> None:
        """Bind the session to one RTSP connection and one H.264 file.

        ``video_command`` is a shell command writing Annex-B H.264 to stdout;
        when given it is streamed live instead of looping ``h264_path``.
        Screen audio is sent only when a source is given: ``audio_command``
        (a shell command writing length-prefixed AAC-ELD frames to stdout)
        or, failing that, ``eld_path`` (a file of such frames, looped).
        ``pair_secret`` is the 32-byte X25519 shared secret of the media
        connection's pair-verify; it replaces the verifier's for the video
        key, and the screen-audio key needs it.
        """
        self._rtsp = rtsp
        self._verifier = verifier
        self._ctx = ctx
        self._h264_path = h264_path
        self._video_command = video_command
        self._eld_path = eld_path
        self._audio_command = audio_command
        self._pair_secret = pair_secret
        self._video_channel: Optional[streams.SendChannel] = None
        self._audio_udp: Optional[asyncio.BaseTransport] = None
        self._event_transport: Optional[asyncio.BaseTransport] = None
        self._audio_control_sock: Optional[socket.socket] = None
        self._video_transport: Optional[asyncio.BaseTransport] = None
        self._timing_server: Optional[TimingServer] = None
        self._tasks: list[asyncio.Task] = []
        self._stopped = False
        # Set once the session is under way, but declared here so the
        # object's full shape is visible in one place.
        self._session_uuid: str = ""
        self._device_id: str = ""
        self._mac_address: str = ""
        self._event_reader: Optional[asyncio.StreamReader] = None
        self._event_writer: Optional[asyncio.StreamWriter] = None
        self._audio_setup_done = False
        self._audio_proc: Optional[asyncio.subprocess.Process] = None
        self._live_proc: Optional[asyncio.subprocess.Process] = None

    async def run(self) -> None:
        """Run the full session until cancelled or the receiver tears down.

        A stopped session cannot be restarted. ``stop()`` has already sent
        TEARDOWN and closed the transports, so the setup below would build on
        a dead connection -- and worse, every task it started would be
        appended to a session that believes it has already stopped, so
        ``stop()`` would never cancel them. Refusing here says which mistake
        was made; without it the failure surfaces further in as whatever the
        closed connection happens to raise.
        """
        if self._stopped:
            raise RuntimeError("session already stopped; construct a new one")
        await self._setup_session()
        # Exact flow (verified via LLDB socket capture 2026-08-24):
        #   SETUP(audio 96) -> connect eventPort -> RECORD -> SETUP(video 110)
        #   -> connect video dataPort -> stream. No session-init, and the
        #   eventPort is returned by the AUDIO SETUP (parsed in
        #   _setup_audio_stream). RECORD is only answered once the event
        #   channel is connected.
        await self._setup_audio_stream()
        await self._open_event_channel()
        await self._record()
        await self._setup_streams()
        await self._open_channels()
        if self._audio_command or self._eld_path:
            self._register(asyncio.ensure_future(self._stream_screen_audio()))
        await self._stream_until_done()

    async def _setup_session(self) -> None:
        """Prepare the session identity and serve the timing port.

        No request is sent here: the session-init SETUP of the macOS sender is
        not part of this flow. The ``eventPort`` comes from the audio SETUP.
        """
        if self._ctx.stream_encryptor is None:
            raise exceptions.ProtocolError(
                "MirrorContext.stream_encryptor not set — FPLY handshake must "
                "complete before _setup_session()."
            )

        # We advertise timingProtocol "NTP" plus a timingPort, so we must
        # actually answer timing requests on it. Binding a dead socket (what
        # this used to do) leaves the receiver waiting on a clock sync that
        # never completes. Reuses RAOP's TimingServer, which speaks the same
        # AirPlay timing protocol.
        loop = asyncio.get_event_loop()
        _, timing_server = await loop.create_datagram_endpoint(
            TimingServer, local_addr=(self._rtsp.connection.local_ip, 0)
        )
        self._timing_server = cast(TimingServer, timing_server)

        # Advertise the same AirPlay version we claim in ``sourceVersion``.
        self._rtsp.user_agent = MIRROR_USER_AGENT

        session_uuid = str(uuid4()).upper()
        # Retained so the stream SETUPs can echo the same session identity
        # (they repeat sessionUUID / deviceID / macAddress).
        self._session_uuid = session_uuid
        self._device_id = self._ctx.device_id or _device_id_from_uuid(session_uuid)
        self._mac_address = self._ctx.mac_address or _device_id_from_uuid(str(uuid4()))
        self._ctx.event_port = 0

    async def _open_event_channel(self) -> None:
        """Connect the event channel advertised by the audio SETUP.

        A PLAINTEXT TCP connection; the receiver only needs the socket up
        before it will answer RECORD.
        """
        if not self._ctx.event_port:
            _LOGGER.debug("No eventPort returned; skipping event channel")
            return
        addr = self._rtsp.connection.remote_ip
        reader, writer = await asyncio.open_connection(addr, self._ctx.event_port)
        self._event_reader = reader
        self._event_transport = writer.transport
        self._event_writer = writer

        async def _serve_events() -> None:
            # The event channel is bidirectional RTSP with the RECEIVER as
            # the client: it sends POST /command (updateInfo etc.) and waits
            # for an RTSP/1.0 200 response. If we never answer, the receiver
            # tears the whole mirror session down after ~30s. So parse each
            # request and reply 200 OK (echoing CSeq).
            buf = b""
            try:
                while not self._stopped:
                    chunk = await reader.read(4096)
                    if not chunk:
                        _LOGGER.info("EVENT channel: receiver EOF")
                        break
                    buf += chunk
                    while True:
                        hdr_end = buf.find(b"\r\n\r\n")
                        if hdr_end < 0:
                            break
                        head = buf[:hdr_end].decode("latin-1")
                        lines = head.split("\r\n")
                        req_line = lines[0] if lines else ""
                        cseq = "0"
                        clen = 0
                        for ln in lines[1:]:
                            k, _, v = ln.partition(":")
                            kl = k.strip().lower()
                            if kl == "cseq":
                                cseq = v.strip()
                            elif kl == "content-length":
                                clen = int(v.strip() or "0")
                        total = hdr_end + 4 + clen
                        if len(buf) < total:
                            break  # wait for full body
                        buf = buf[total:]
                        _LOGGER.info(
                            "EVENT req: %s (CSeq %s, body %dB)",
                            req_line,
                            cseq,
                            clen,
                        )
                        resp = (
                            f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n"
                            f"Content-Length: 0\r\n\r\n"
                        ).encode("latin-1")
                        writer.write(resp)
                        await writer.drain()
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                _LOGGER.debug("event channel handler ended: %s", exc)

        self._register(asyncio.ensure_future(_serve_events()))
        _LOGGER.debug(
            "Plaintext event channel connected on port %d",
            self._ctx.event_port,
        )

    def _build_ekey_eiv(self):
        """Return (ekey, eiv) for the video stream SETUP, or (None, None).

        The reference sender transports a FairPlay-wrapped stream key in
        ``ekey`` + a 16-byte ``eiv``. The ekey wraps our chosen raw16. eiv is
        a sender-chosen random 16B (the reference sender's sess[0xa8]); the
        video IV itself derives from raw16, so eiv's value is free unless the
        receiver validates it.
        """
        if self._ctx.ekey:
            return self._ctx.ekey, secrets.token_bytes(16)
        return None, None

    async def _setup_audio_stream(self) -> None:
        """Send the reference sender's type-96 AUDIO stream SETUP (before RECORD).

        The reference sender's real flow is SETUP(audio 96) -> RECORD -> SETUP(video
        110); the audio SETUP must come first or RECORD returns 455. The receiver also
        needs the audio (screen-audio) stream present to accept the video. Includes
        ``controlPort`` (a bound UDP port) as the reference sender does.
        """
        if self._audio_setup_done:
            return
        if not self._ctx.audio_ekey:
            return
        self._audio_setup_done = True
        timing_port = self._timing_server.port if self._timing_server else 0
        # Bind a UDP control port and advertise it, mirroring the reference sender.
        if self._audio_control_sock is None:
            self._audio_control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._audio_control_sock.bind((self._rtsp.connection.local_ip, 0))
        control_port = self._audio_control_sock.getsockname()[1]
        audio_id = secrets.randbits(32)
        audio_eiv = secrets.token_bytes(16)
        # The eiv is retained so the (optional) screen-audio sender can
        # AES-128-CBC encrypt AAC-ELD frames with (key=raw16, iv=eiv) — the
        # receiver derives the same from the audio ekey/eiv (see
        # screen_audio.py + audio spec). audio_id needs no such stash: it
        # goes straight into the SETUP below and, unlike the video stream's
        # id, takes no part in key derivation.
        self._ctx.audio_eiv = audio_eiv
        audio_body = {
            "streams": [
                {
                    "type": 96,
                    "streamConnectionID": audio_id,
                    "latencyMin": 3750,
                    "latencyMax": 3750,
                    "redundantAudio": 2,
                    "ct": 8,
                    "spf": screen_audio.AUDIO_SAMPLES_PER_FRAME,
                    "audioFormat": 16777216,
                    "controlPort": control_port,
                    "usingScreen": True,
                }
            ],
            "et": STREAM_ET,
            "timingPort": timing_port,
            "sessionUUID": self._session_uuid or str(uuid4()).upper(),
            "osBuildVersion": self._ctx.os_build_version,
            "sourceVersion": self._ctx.source_version,
            "deviceID": self._device_id,
            "macAddress": self._mac_address,
            "name": self._ctx.name,
            "model": self._ctx.model,
            "ekey": self._ctx.audio_ekey,
            "eiv": audio_eiv,
        }
        a_resp = await self._rtsp.setup(
            headers=dict(_SUPPRESS_RAOP_HEADERS),
            body=audio_body,
            timeout=STREAM_SETUP_TIMEOUT,
        )
        if a_resp.code != 200:
            raise exceptions.ProtocolError(
                f"AUDIO SETUP (type 96) failed: HTTP {a_resp.code}"
            )
        decoded = decode_bplist_from_body(a_resp)
        _LOGGER.debug("AUDIO SETUP full response: %r", decoded)
        # The eventPort the receiver expects us to connect to comes from THIS
        # response.
        self._ctx.event_port = decoded.get("eventPort", 0)
        astream = (decoded.get("streams") or [{}])[0]
        self._ctx.audio_data_port = astream.get("dataPort", 0)
        self._ctx.audio_control_port = astream.get("controlPort", 0)
        _LOGGER.info(
            "AUDIO stream SETUP (type 96) -> HTTP %d eventPort=%d "
            "audioDataPort=%d audioControlPort=%d",
            a_resp.code,
            self._ctx.event_port,
            self._ctx.audio_data_port,
            self._ctx.audio_control_port,
        )

    async def _setup_streams(self) -> None:
        """Send the type-110 video stream SETUP and record the data port.

        Sent AFTER ``RECORD``. A simple type-110 video stream plus session
        identity at the top level, and a FairPlay-wrapped key transported in
        ``ekey``/``eiv``. The receiver returns a *TCP* dataPort. See
        tcp_stream.py.
        """
        # The reference sender uses 32-bit streamConnectionIDs; the receiver
        # appears to store it in a 32-bit field, so a 63-bit value would make
        # the receiver's key-derivation label ("AirPlayStreamKey"+id) disagree
        # with ours.
        self._ctx.stream_connection_id = secrets.randbits(32)
        timing_port = self._timing_server.port if self._timing_server else 0
        # AUDIO stream SETUP already sent (before RECORD, from run()).
        body = {
            "streams": [
                {
                    "type": 110,
                    "streamConnectionID": self._ctx.stream_connection_id,
                    "timestampInfo": [
                        {"name": name}
                        for name in ("SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc")
                    ],
                }
            ],
            "et": STREAM_ET,
            "timingPort": timing_port,
            "sessionUUID": self._session_uuid or str(uuid4()).upper(),
            "osBuildVersion": self._ctx.os_build_version,
            "sourceVersion": self._ctx.source_version,
            "deviceID": self._device_id,
            "macAddress": self._mac_address,
            "name": self._ctx.name,
            "model": self._ctx.model,
        }
        ekey, eiv = self._build_ekey_eiv()
        if ekey is not None:
            body["ekey"] = ekey
            body["eiv"] = eiv
            _LOGGER.debug(
                "SETUP ekey(%d)=%s eiv=%s et=32 type=110 streamID=%s",
                len(ekey),
                ekey[:24].hex(),
                eiv.hex() if eiv else None,
                self._ctx.stream_connection_id,
            )
        # The receiver takes noticeably longer over the stream SETUP than the
        # session SETUP (it negotiates the video pipeline and probes the ports
        # we advertised), so allow more than the 4 s RTSP default.
        resp = await self._rtsp.setup(
            headers=dict(_SUPPRESS_RAOP_HEADERS),
            body=body,
            timeout=STREAM_SETUP_TIMEOUT,
        )
        if resp.code != 200:
            raise exceptions.ProtocolError(
                f"SETUP (video stream) failed: HTTP {resp.code}"
            )
        decoded = decode_bplist_from_body(resp)
        stream = decoded["streams"][0]
        self._ctx.video_data_port = stream["dataPort"]
        _LOGGER.debug(
            "Mirror stream established, dataPort=%d streamConnectionID %d",
            self._ctx.video_data_port,
            self._ctx.stream_connection_id,
        )

    async def _open_channels(self) -> None:
        """Open the raw TCP video connection to the negotiated ``dataPort``.

        No HAP/ChaCha layer: the AES-CTR on each frame is the only encryption.
        Verified by decrypting the reference sender's live TCP stream.
        """
        addr = self._rtsp.connection.remote_ip
        loop = asyncio.get_event_loop()
        v_transport, v_channel = await loop.create_connection(
            tcp_stream.RawVideoTCPChannel,
            addr,
            self._ctx.video_data_port,
        )
        self._video_transport, self._video_channel = v_transport, v_channel
        _LOGGER.debug(
            "Raw TCP video channel open to %s:%d",
            addr,
            self._ctx.video_data_port,
        )

    async def _stream_screen_audio(self) -> None:
        """Send screen audio as AAC-ELD over UDP/RTP.

        VERIFIED playing on tvOS 26 (mic-confirmed +15 dB, drops on stop). The
        key detail: the sync (0xD4) MUST be sent FROM the advertised controlPort
        socket, or the receiver never opens its audio control channel and refuses
        the sync (ICMP), leaving the audio unscheduled/silent.
        Only started when an audio source was given. Reads length-prefixed
        AAC-ELD frames (4-byte BE length + frame, repeated) from ``eld_path``
        or ``audio_command`` and sends them as RTP packets to the type-96 audio
        dataPort, AES-128-CBC encrypted with (key=raw16, iv=eiv). See
        screen_audio.py + the audio spec.
        """
        # One method because the sequence -- key derivation, two sockets,
        # the sync packet, then the send loop -- has to be read in order.
        # pylint: disable=too-many-locals,too-many-branches
        # pylint: disable=too-many-statements
        port = self._ctx.audio_data_port
        eld_file = self._eld_path
        audio_live_cmd = self._audio_command
        pair32 = self._pair_secret
        raw16 = self._ctx.stream_raw16
        iv = self._ctx.audio_eiv
        # Audio key = secret16 = sha512(raw16 || pair32)[:16] (DeriveAudioKeyAndIV
        # passes sess[0xa0] through PairingContextDeriveKey when the flag is set;
        # NO "AirPlayStreamKey" labeling, unlike video).
        if len(raw16) == 16 and pair32:
            key = hashlib.sha512(raw16 + pair32).digest()[:16]
        else:
            key = b""
        if not (
            port and (eld_file or audio_live_cmd) and len(key) == 16 and len(iv) == 16
        ):
            _LOGGER.info(
                "screen audio: not sending (port=%s src=%s key=%dB iv=%dB)",
                port,
                bool(eld_file or audio_live_cmd),
                len(key),
                len(iv),
            )
            return
        # Frame source: either a static file (looped) or a LIVE subprocess that
        # writes length-prefixed AAC-ELD frames to stdout (parsed incrementally).
        frames: list = []
        live_audio_q: "Optional[asyncio.Queue]" = None
        audio_proc = None
        if not audio_live_cmd:
            # The `eld_file or audio_live_cmd` guard above already returned
            # when both were unset, so eld_file is set on this branch.
            assert eld_file is not None
            raw = Path(eld_file).read_bytes()
            off = 0
            while off + 4 <= len(raw):
                ln = int.from_bytes(raw[off : off + 4], "big")
                off += 4
                if ln <= 0 or off + ln > len(raw):
                    break
                frames.append(raw[off : off + ln])
                off += ln
            if not frames:
                _LOGGER.warning("screen audio: no frames from %s", eld_file)
                return
        addr = self._rtsp.connection.remote_ip
        loop = asyncio.get_event_loop()

        class _AudioDP(asyncio.DatagramProtocol):
            """Log-only datagram protocol for the screen-audio sockets."""

            def __init__(self, tag):
                """Label this endpoint *tag* in the log."""
                self.tag = tag

            def error_received(self, exc):
                """Log an ICMP-style error on the socket."""
                _LOGGER.warning(
                    "screen audio[%s]: UDP error (ICMP?): %s", self.tag, exc
                )

            def connection_lost(self, exc):
                """Log an unexpected close."""
                if exc:
                    _LOGGER.warning("screen audio: UDP conn lost: %s", exc)

            def datagram_received(self, data, addr):
                """Log an inbound datagram; none is expected."""
                _LOGGER.debug("screen audio: RX %d bytes from %s", len(data), addr)

        self._audio_udp, _ = await loop.create_datagram_endpoint(
            lambda: _AudioDP("DATA"), remote_addr=(addr, port)
        )
        # Audio CONTROL/timing socket — the receiver needs sync packets here to
        # lock its audio clock before it will play (RE: PT-84/0xD4, 20 bytes,
        # ~1/s). Reuses RAOP's SyncPacket (same wire format).
        ctrl_udp = None
        ctrl_port = self._ctx.audio_control_port
        if ctrl_port:
            ctrl_udp, _ = await loop.create_datagram_endpoint(
                lambda: _AudioDP("CTRL"), remote_addr=(addr, ctrl_port)
            )
        spf = screen_audio.AUDIO_SAMPLES_PER_FRAME
        # matches the reference sender's captured sync (now - now_without_latency)
        latency = 2205
        base_ts = int(time.time()) & 0xFFFFFFFF
        pk = screen_audio.ScreenAudioPacketizer(
            key, iv, ssrc=0, spf=spf, base_ts=base_ts
        )
        interval = spf / screen_audio.AUDIO_SAMPLE_RATE
        sync_every = AUDIO_SYNC_EVERY

        adv_ctrl = self._audio_control_sock
        if adv_ctrl is not None:
            adv_ctrl.setblocking(False)

        def _send_sync(first: bool) -> None:
            if ctrl_port == 0:
                return
            # last_sync MUST be in the SAME clock domain as the TimingServer
            # (NTP-since-1900 via ntp_now), or the receiver correlates two
            # epochs 2.2e9 s apart and re-syncs the audio every sync packet
            # (~1/s) — an audible glitch each second.
            sync = screen_audio.build_audio_sync_packet(
                first, pk.timestamp, latency, raop_timing.ntp_now()
            )
            try:
                if adv_ctrl is not None:
                    adv_ctrl.sendto(sync, (addr, ctrl_port))
                elif ctrl_udp is not None:
                    ctrl_udp.sendto(sync)
            except OSError as _e:
                _LOGGER.warning("screen audio[CTRL-adv]: %s", _e)

        audio_reader_task = None
        if audio_live_cmd:
            live_audio_q = asyncio.Queue(maxsize=AUDIO_LIVE_BUFFER)
            audio_proc = await asyncio.create_subprocess_shell(
                audio_live_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            self._audio_proc = audio_proc

            async def _audio_reader() -> None:
                buf = b""
                assert audio_proc.stdout is not None
                while True:
                    chunk = await audio_proc.stdout.read(16384)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 4:
                        ln = int.from_bytes(buf[:4], "big")
                        if ln <= 0 or ln > 8192:
                            buf = buf[1:]
                            continue
                        if len(buf) < 4 + ln:
                            break
                        frame = buf[4 : 4 + ln]
                        buf = buf[4 + ln :]
                        if live_audio_q.full():
                            try:
                                live_audio_q.get_nowait()
                            except Exception:  # noqa: BLE001
                                pass
                        live_audio_q.put_nowait(frame)

            audio_reader_task = asyncio.ensure_future(_audio_reader())
            # Pre-buffer ~2s so bursty live delivery (HLS segments) doesn't
            # starve the sender and cause dropouts/glitches.
            for _ in range(300):
                if live_audio_q.qsize() >= AUDIO_PREBUFFER:
                    break
                await asyncio.sleep(0.05)

        _LOGGER.info(
            "screen audio: streaming %s AAC-ELD frames -> %s:%d (%.1f fps), "
            "sync -> :%s",
            "LIVE" if audio_live_cmd else len(frames),
            addr,
            port,
            1.0 / interval,
            ctrl_port,
        )
        idx = 0
        try:
            _send_sync(first=True)
            # Pace against a fixed wall-clock schedule (frame N due at
            # start + N*interval) rather than sleeping `interval` AFTER each
            # send. The latter accumulates the per-frame processing time, so
            # the true rate falls below 91.9 fps: the RTP timestamp (advancing
            # exactly +spf/frame) races ahead of real time, the receiver's
            # audio buffer starves, and every sync packet snaps the clock back
            # — an audible glitch ~1/s. A wall-clock deadline holds the rate
            # exact so timestamp and arrival stay locked.
            start = loop.time()
            while not self._stopped:
                if live_audio_q is not None:
                    if live_audio_q.empty():
                        # Underrun: wait for the next frame, reset the pace
                        # clock (the packetizer timestamp keeps advancing on
                        # its own, so it stays monotonic).
                        frame = await live_audio_q.get()
                        start = loop.time()
                        idx = 0
                    else:
                        frame = live_audio_q.get_nowait()
                else:
                    frame = frames[idx % len(frames)]
                self._audio_udp.sendto(pk.next_packet(frame))
                idx += 1
                if idx % sync_every == 0:
                    _send_sync(first=False)
                delay = start + idx * interval - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("screen audio sender ended: %s", exc)
        finally:
            if audio_reader_task is not None:
                audio_reader_task.cancel()
            if audio_proc is not None:
                try:
                    audio_proc.kill()
                except Exception:  # noqa: BLE001
                    pass
            if ctrl_udp is not None:
                ctrl_udp.close()

    async def _tcp_live_video(
        self, live_cmd: str, video_q: "asyncio.Queue", video_encryptor
    ) -> None:
        """Stream a LIVE H.264 source in real time.

        ``live_cmd`` is a shell command that writes an Annex-B H.264 elementary
        stream to stdout (e.g. ``yt-dlp -o - <url> | ffmpeg ... -f h264 -``).
        NAL units are parsed incrementally as they arrive, grouped into access
        units, buffered (dropping oldest to bound latency), and paced out at the
        configured fps. SPS/PPS go into the plaintext avcC config frame; VCL
        frames are sent as continuous-keystream AES-CTR messages, exactly like
        the file path. Used when the session was given ``video_command``.
        """
        # pylint: disable=too-many-locals,too-many-statements
        fps = max(self._ctx.fps, 1)
        frame_interval = 1.0 / fps
        w, h = float(self._ctx.width), float(self._ctx.height)
        geometry = tcp_stream.build_geometry(w, h, 0.0, 0.0, w, h)
        loop = asyncio.get_event_loop()

        proc = await asyncio.create_subprocess_shell(
            live_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._live_proc = proc
        live_q: asyncio.Queue = asyncio.Queue(maxsize=LIVE_VIDEO_BUFFER)
        state: dict[str, Optional[bytes]] = {"sps": None, "pps": None}
        config_ready = asyncio.Event()

        async def reader() -> None:
            buf = b""
            cur: list = []  # non-VCL NALs (SEI) accumulating for the next AU
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                scs = pacer.find_start_codes(buf)
                if len(scs) < 2:
                    continue
                for k in range(len(scs) - 1):
                    pos, cl = scs[k]
                    nxt = scs[k + 1][0]
                    nal = buf[pos + cl : nxt]
                    if not nal:
                        continue
                    t = nal[0] & 0x1F
                    if t == 7:
                        state["sps"] = nal
                    elif t == 8:
                        state["pps"] = nal
                    elif t == 6:
                        cur.append(nal)  # SEI belongs to the next AU
                    # VCL slice -> completes an access unit. Narrower than
                    # ``tcp_stream._VCL_TYPES`` (1..5), which is the same
                    # concept spelled a second way; see the note there. They
                    # agree on any real stream: 2/3/4 are Extended-profile data
                    # partitions that Baseline/Main/High forbid.
                    elif t in (1, 5):
                        au = cur + [nal]
                        cur = []
                        if live_q.full():
                            try:
                                live_q.get_nowait()  # drop oldest, bound latency
                            except Exception:  # noqa: BLE001
                                pass
                        live_q.put_nowait(au)
                        if state["sps"] and state["pps"]:
                            config_ready.set()
                buf = buf[scs[-1][0] :]  # keep partial trailing NAL
            config_ready.set()

        reader_task = asyncio.ensure_future(reader())
        try:
            try:
                await asyncio.wait_for(config_ready.wait(), timeout=25.0)
            except asyncio.TimeoutError:
                pass
            if not (state["sps"] and state["pps"]):
                _LOGGER.warning("live video: no SPS/PPS from source; aborting")
                return

            config = tcp_stream.build_avcc_config(state["sps"], state["pps"])
            config_hdr = tcp_stream.build_data_header(
                len(config),
                0,
                geometry,
                # pylint: disable-next=protected-access
                msg_type=tcp_stream._CONFIG_TYPE,
                dims=(w, h),
            )
            await video_q.put(config_hdr + config)
            _LOGGER.info(
                "live video: sent avcC config (%d B), streaming live @%dfps",
                len(config),
                fps,
            )
            await asyncio.sleep(LIVE_VIDEO_PREBUFFER)

            index = 0  # pacing counter only; reset on underrun is fine
            pace_start = loop.time()
            while not self._stopped:
                if live_q.empty():
                    # Underrun: wait for the next frame and reset the PACE
                    # clock so we don't burst to "catch up" afterwards. The
                    # header timestamp is the real wall clock (below), so it
                    # stays monotonic regardless — resetting a frame-counter
                    # timestamp here would send time backwards and freeze the
                    # receiver's picture.
                    au = await live_q.get()
                    pace_start = loop.time()
                    index = 0
                else:
                    au = live_q.get_nowait()
                au = [n for n in au if (n[0] & 0x1F) not in (7, 8)]
                avcc = tcp_stream.to_avcc(au)
                ciphertext = video_encryptor.encrypt(avcc)
                # Real monotonic clock at send time: always increasing, so the
                # receiver keeps advancing its display even across underruns.
                header = tcp_stream.build_data_header(
                    len(ciphertext), time.monotonic_ns(), geometry
                )
                await video_q.put(header + ciphertext)
                index += 1
                delay = pace_start + index * frame_interval - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
        finally:
            reader_task.cancel()
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass

    async def _record(self) -> None:
        resp = await self._rtsp.record()
        if resp.code != 200:
            raise exceptions.ProtocolError(f"RECORD failed: HTTP {resp.code}")

    async def _stream_until_done(self) -> None:
        # The method is long because the flow it drives is; splitting it
        # would scatter a sequence that has to be read in order.
        # pylint: disable=too-many-statements
        if self._ctx.stream_encryptor is None:
            raise RuntimeError(
                "MirrorContext.stream_encryptor not set — "
                "did the MFiSAP handshake complete?"
            )

        encryptor = self._ctx.stream_encryptor
        video_q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_HIGH_WATERMARK)

        # Refuse a source with no SPS/PPS or no IDR before anything streams.
        pacer._scan_file(self._h264_path)  # pylint: disable=protected-access

        video_encryptor = self._ctx.video_encryptor or encryptor

        # PROVEN video-key recipe.
        #
        # Reverse-engineered and byte-verified against the reference sender's live
        # derivation on a tvOS 26 receiver (LLDB, 2026-08-23 — see
        # docs/.../2026-08-23-mirror-video-key-handoff.md SESSION 3 and memory
        # note project-mirror-video-key-solved). The reference sender's
        # _SQAirPlayClientSessionDeriveKeyAndIV binds the FairPlay SAP secret
        # with the pair-verify X25519 shared secret, then hashes per stream:
        #
        #   raw16    = FairPlay SAP secret        = sap_context[0x08:0x18]
        #   pair32   = pair-verify X25519 secret  = verifier.srp._shared (pre-HKDF)
        #   secret16 = sha512(raw16 || pair32)[:16]        (session flag 0xb0 == 1)
        #   key      = sha512("AirPlayStreamKey"+id || secret16)[:16]
        #   iv       = sha512("AirPlayStreamIV" +id || secret16)[:16]
        #
        # used as a single continuous AES-128-CTR keystream (id = the
        # streamConnectionID we sent in SETUP).
        if self._ctx.sap_context or self._ctx.stream_raw16:
            # Prefer the raw16 we CHOSE and packaged into ekey (the receiver
            # unwraps ekey -> this raw16 and derives the same key). Fall back to
            # a sap_context slice for the no-ekey experiments.
            if self._ctx.stream_raw16 and len(self._ctx.stream_raw16) == 16:
                raw16 = self._ctx.stream_raw16
            else:
                raw16 = self._ctx.sap_context[
                    SAP_SECRET_OFFSET : SAP_SECRET_OFFSET + 16
                ]
            # The screen video key uses the MEDIA-connection pair-verify's X25519
            # shared secret (the reference sender's raw /pair-verify), NOT the main
            # HAP pair-verify. ``pair_secret`` supplies that media pair-verify
            # shared when the caller relays the raw pair-verify.
            pair32: Optional[bytes]
            if self._pair_secret:
                pair32 = self._pair_secret
            else:
                pair32 = getattr(getattr(self._verifier, "srp", None), "_shared", None)
            if len(raw16) == 16 and pair32 and len(pair32) == 32:
                secret16 = framing.stream_secret16(raw16, bytes(pair32))
                sid = self._ctx.stream_connection_id
                key, iv = framing.derive_tcp_stream_key_iv(raw16, bytes(pair32), sid)
                # An encryptor handed in on the context is an explicit caller
                # choice and outranks the derived one.
                if self._ctx.video_encryptor is None:
                    video_encryptor = framing.MirrorEncryptor.from_key_iv(key, iv)
                _LOGGER.debug(
                    "PROVEN video key: streamID=%s raw16=%s pair32=%s secret16=%s "
                    "key=%s iv=%s",
                    sid,
                    raw16.hex(),
                    bytes(pair32).hex(),
                    secret16.hex(),
                    key.hex(),
                    iv.hex(),
                )
            else:
                _LOGGER.warning(
                    "PROVEN video key unavailable: raw16=%dB pair32=%s — "
                    "falling back to the MFiSAP stream encryptor",
                    len(raw16),
                    "None" if not pair32 else f"{len(pair32)}B",
                )

        async def tcp_video_producer() -> None:  # pylint: disable=too-many-locals
            """Send one raw-TCP message per H.264 access unit.

            Each message = 128-byte header + AES-128-CTR ciphertext, where the
            ciphertext is a single CONTINUOUS keystream across the whole stream
            (no per-frame reset) and the plaintext is the access unit in AVCC
            form (4-byte BE length + NAL per unit). Verified against the reference
            sender's live stream — see tcp_stream.py.
            """
            if self._video_command:
                await self._tcp_live_video(
                    self._video_command, video_q, video_encryptor
                )
                return
            h264 = Path(self._h264_path).read_bytes()
            nalus = pacer.split_nalus(h264)
            # SPS/PPS are transported PLAINTEXT in the avcC config, NOT in the
            # encrypted frames (verified against the reference sender's stream), so
            # strip them from the frame NALs.
            sps = next((n for n in nalus if pacer.nal_type(n) == 7), None)
            pps = next((n for n in nalus if pacer.nal_type(n) == 8), None)
            # The reference sender's video frames carry only [SEI][slice]; SPS/PPS live
            # solely in the plaintext avcC config built below. Match that so
            # the receiver's screen decoder sees the same structure.
            frame_nalus = [n for n in nalus if pacer.nal_type(n) not in (7, 8)]
            units = tcp_stream.group_access_units(frame_nalus, pacer.nal_type)
            if not units or sps is None or pps is None:
                _LOGGER.warning(
                    "TCP video: missing SPS/PPS or no access units "
                    "(sps=%s pps=%s units=%d)",
                    sps is not None,
                    pps is not None,
                    len(units),
                )
                return
            frame_interval = 1.0 / max(self._ctx.fps, 1)
            ns_per_frame = 1_000_000_000 // max(self._ctx.fps, 1)
            w, h = float(self._ctx.width), float(self._ctx.height)
            geometry = tcp_stream.build_geometry(w, h, 0.0, 0.0, w, h)

            # 1) FIRST message: plaintext avcC decoder config (type 0x01000600),
            #    so the receiver can initialise its H.264 decoder. Not encrypted,
            #    so it does not advance the continuous AES-CTR keystream.
            config = tcp_stream.build_avcc_config(sps, pps)
            config_hdr = tcp_stream.build_data_header(
                len(config),
                0,
                geometry,
                # pylint: disable-next=protected-access
                msg_type=tcp_stream._CONFIG_TYPE,
                dims=(float(self._ctx.width), float(self._ctx.height)),
            )
            await video_q.put(config_hdr + config)
            _LOGGER.info(
                "TCP video: sent avcC config (%d B), %d access units, "
                "continuous AES-CTR",
                len(config),
                len(units),
            )

            # 2) Then encrypted frames (type 0x00000600), continuous keystream.
            # The header timestamp ([8:16]) is a large monotonic mach-style value
            # (the reference sender uses mach_absolute_time); a 0-based value can fail
            # the receiver's timing validation.
            ts_base = time.monotonic_ns()
            _LOGGER.debug(
                "producer video_encryptor key=%s iv=%s",
                getattr(video_encryptor, "key", b"").hex(),
                getattr(video_encryptor, "iv", b"").hex(),
            )
            # Give the receiver time to initialise its decoder from the config
            # before the first encrypted frame (avoid a race).
            await asyncio.sleep(CONFIG_DELAY)
            index = 0
            _loop_time = asyncio.get_event_loop().time
            _pace_start = _loop_time()
            while True:
                unit = units[index % len(units)]
                avcc = tcp_stream.to_avcc(unit)
                ciphertext = video_encryptor.encrypt(avcc)  # continuous keystream
                header = tcp_stream.build_data_header(
                    len(ciphertext), ts_base + index * ns_per_frame, geometry
                )
                await video_q.put(header + ciphertext)
                index += 1
                # Wall-clock schedule (frame N due at start + N*interval) so
                # the true frame rate stays at fps instead of drifting below it
                # from accumulated per-frame encrypt/queue time — the cause of
                # the periodic video hitch.
                _pace_delay = _pace_start + index * frame_interval - _loop_time()
                if _pace_delay > 0:
                    await asyncio.sleep(_pace_delay)

        assert self._video_channel is not None

        async def send_feedback(_msg) -> None:
            await self._rtsp.feedback(allow_error=True)

        # EXTEND, never replace: run() and _open_event_channel() have already
        # registered the screen-audio sender and the event-channel POST
        # /command responder here. Assigning drops them from the list, so
        # stop() never cancels or awaits them — today they still wind
        # themselves down off the ._stopped flag, but only by luck.
        self._register(
            asyncio.create_task(tcp_video_producer(), name="mirror-video-pacer"),
            asyncio.create_task(
                streams.drain_queue_to_channel(self._video_channel, video_q),
                name="mirror-video-drain",
            ),
        )
        self._register(
            asyncio.create_task(
                heartbeater(
                    name="mirror-heartbeat",
                    sender_func=send_feedback,
                    finish_func=lambda: None,
                    failure_func=lambda exc: _LOGGER.warning(
                        "heartbeat failed: %s", exc
                    ),
                    interval=FEEDBACK_INTERVAL,
                ),
                name="mirror-heartbeat",
            ),
        )
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            _LOGGER.debug("MirrorSession streaming cancelled")
            raise

    def _register(self, *tasks: asyncio.Task) -> None:
        """Track background tasks so ``stop()`` can cancel and await them.

        Refuses once the session has stopped. ``stop()`` cancels whatever is in
        ``self._tasks`` at the moment it runs, so anything appended afterwards
        would never be cancelled by it -- and ``run()`` can still be mid-setup
        when ``stop()`` lands, appending several. Today those wind down anyway,
        off the ``_stopped`` flag or because ``stop()`` closed the connection
        under them; this makes that a guarantee rather than a coincidence.
        """
        if self._stopped:
            for task in tasks:
                task.cancel()
            return
        self._tasks.extend(tasks)

    async def stop(self) -> None:
        """Stop streaming, send TEARDOWN, close transports."""
        if self._stopped:
            return
        self._stopped = True
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        try:
            await self._rtsp.teardown(self._rtsp.session_id)
        except Exception:
            _LOGGER.exception("TEARDOWN failed")
        self._close_endpoints()

    def _close_endpoints(self) -> None:
        """Close every transport and socket the session opened.

        Split out of ``stop()`` so the teardown reads as one list rather than
        as a dozen branches inside the shutdown sequence.

        The raw socket is the part worth knowing about. ``_audio_control_sock``
        is used for bare ``sendto`` -- it is not a transport, so nothing else
        closes it.
        """
        for transport in (
            self._event_transport,
            self._video_transport,
            self._audio_udp,
            self._timing_server,
        ):
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()

        if self._audio_control_sock is not None:
            with contextlib.suppress(OSError):
                self._audio_control_sock.close()
        self._audio_control_sock = None

        # The live sources, which each producer also kills in its own
        # `finally`. This covers a producer cancelled before it reaches that
        # `finally`. A real source is ffmpeg or yt-dlp, so it would keep
        # encoding and downloading for as long as it feels like. Killing an
        # already-dead process is a no-op.
        for proc in (self._live_proc, self._audio_proc):
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
        self._live_proc = None
        self._audio_proc = None
