"""MirrorSession: orchestrates the AirPlay 2 mirror MVP.

Phases:
  A. Setup: SETUP (session init) → RECORD → SETUP (streams) → open data
     channels. This order is the modern AirPlay 2 mirror flow captured
     from a real macOS sender in Phase 28; there is no ANNOUNCE/SDP.
  B. Streaming: spawn pacer + drain tasks for video and audio.
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
import os
from pathlib import Path
import plistlib
import secrets
import socket
import struct
import time
from typing import Awaitable, Callable, Optional, Tuple, cast
from uuid import uuid4

from pyatv import exceptions
from pyatv.auth.hap_channel import AbstractHAPChannel
from pyatv.auth.hap_pairing import PairVerifyProcedure
from pyatv.core.protocol import heartbeater
from pyatv.protocols.airplay import channels
from pyatv.protocols.airplay.mirror import (
    airparrot_audio,
    airparrot_stream,
    framing,
    negotiation,
    pacer,
    rtp,
    srtp,
    streams,
)
from pyatv.protocols.airplay.mirror.context import MirrorContext
from pyatv.protocols.raop import timing as raop_timing
from pyatv.protocols.raop.protocols import TimingServer
from pyatv.support.http import decode_bplist_from_body
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

FEEDBACK_INTERVAL = 2.0  # seconds, matches AP2Session.start_keep_alive

# Salt/info strings for HKDF derivation on the per-channel HAP encryption.
# These names follow the AP2 convention used elsewhere in pyatv (DataStream-Salt
# etc.); the exact strings the receiver expects will be confirmed during
# hardware integration.
#
# The MirrorVideo-* trio that used to sit here is gone: the video key turned
# out not to be HAP-derived at all. It is the FairPlay one built in
# framing.derive_airparrot_stream_key_iv, so those three labels had no reader.
MIRROR_AUDIO_SALT = "MirrorAudio-Salt"
MIRROR_AUDIO_OUTPUT_INFO = "MirrorAudio-Output-Encryption-Key"
MIRROR_AUDIO_INPUT_INFO = "MirrorAudio-Input-Encryption-Key"
# Media-data-control channel. Follows pyatv's data-stream convention from
# ap2_session.py, where the salt carries the seed the sender chose.
MIRROR_CONTROL_SALT = "DataStream-Salt"  # seed appended
MIRROR_CONTROL_OUTPUT_INFO = "DataStream-Output-Encryption-Key"
MIRROR_CONTROL_INPUT_INFO = "DataStream-Input-Encryption-Key"

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

#: The receiver may not be listening on the control port the instant it
#: answers the stream SETUP, so the connection is retried briefly.
CONTROL_CHANNEL_ATTEMPTS = 6
CONTROL_CHANNEL_RETRY_DELAY = 0.4

# Event channel, shared with pyatv's AirPlay 2 remote-control session.
# NB: read/write are reversed for the event channel.
EVENTS_SALT = "Events-Salt"
EVENTS_WRITE_INFO = "Events-Write-Encryption-Key"
EVENTS_READ_INFO = "Events-Read-Encryption-Key"


class _NetworkInfoProtocol(asyncio.Protocol):
    """Listener for the port advertised as ``networkInfo.Port``.

    It is not yet established whether the receiver dials this port for the
    mirroring media/control connection or whether the sender is expected to
    connect outward to the ``dataPort`` it returns (which currently refuses
    TCP). Log whatever arrives so the next live run answers that.
    """

    def connection_made(self, transport) -> None:
        """Log an inbound connection from the receiver."""
        _LOGGER.debug(
            "networkInfo port: inbound connection from %s",
            transport.get_extra_info("peername"),
        )

    def data_received(self, data: bytes) -> None:
        """Log data arriving on the advertised networkInfo port."""
        _LOGGER.debug(
            "networkInfo port: received %d bytes: %s", len(data), data[:64].hex()
        )


def _device_id_from_uuid(uuid_str: str) -> str:
    """Derive a stable MAC-address-shaped device ID from a session UUID.

    Real AirPlay senders pass their hardware MAC; we synthesize a stable
    pseudo-MAC from the session UUID's last 12 hex chars formatted as
    ``XX:XX:XX:XX:XX:XX`` (upper-case, as real senders send it). Apple TV
    accepts this — Phase 22's AirParrot
    helper also used a synthesized ID (not its real WiFi MAC) and was
    accepted on /fp-setup.
    """
    hex12 = uuid_str.replace("-", "")[-12:].upper()
    return ":".join(hex12[i : i + 2] for i in range(0, 12, 2))


def _airparrot_mode() -> bool:
    """Whether to speak AirParrot's mirror dialect (default) vs AVConference.

    AirParrot's simple type-110 SETUP + raw-TCP 128-byte-framed continuous
    AES-CTR video is the path that actually renders on tvOS 26 (the video key
    derivation was verified by decrypting AirParrot's live stream). Set
    ``MIRROR_AIRPARROT=0`` to fall back to the experimental AVConference path.
    """
    return os.environ.get("MIRROR_AIRPARROT", "1") != "0"


ChannelOpener = Callable[
    [Callable[[bytes, bytes], AbstractHAPChannel], str, int, str, str, str],
    Awaitable[Tuple[asyncio.BaseTransport, AbstractHAPChannel]],
]


def _build_announce_sdp(
    session_id: int,
    local_ip: str,
    remote_ip: str,
    width: int,
    height: int,
    fps: int,
    audio_sample_rate: int,
    audio_channels: int,
) -> str:
    """SDP body for the mirror ANNOUNCE.

    NOTE: Unlike the AirPlay 1 SDP, this body does NOT carry fpaeskey/aesiv
    attributes. The AES key/IV come from the MFiSAP handshake at
    /fp-setup + /auth-setup, NOT via SDP.
    """
    return (
        "v=0\r\n"
        f"o=AirPlay {session_id} 0 IN IP4 {local_ip}\r\n"
        "s=AirPlay\r\n"
        f"c=IN IP4 {remote_ip}\r\n"
        "t=0 0\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        f"a=rtpmap:96 H264/{fps * 1000}\r\n"
        "a=fmtp:96 profile-level-id=42E01F;packetization-mode=1;"
        f"width={width};height={height}\r\n"
        "m=audio 0 RTP/AVP 97\r\n"
        f"a=rtpmap:97 mpeg4-generic/{audio_sample_rate}/{audio_channels}\r\n"
    )


class MirrorSession:
    """Orchestrates the mirror MVP: setup → stream → teardown."""

    def __init__(
        self,
        rtsp: RtspSession,
        verifier: PairVerifyProcedure,
        ctx: MirrorContext,
        h264_path: Path,
        channel_opener: ChannelOpener,
    ) -> None:
        """Bind the session to one RTSP connection and one H.264 file."""
        self._rtsp = rtsp
        self._verifier = verifier
        self._ctx = ctx
        self._h264_path = h264_path
        self._open_channel = channel_opener
        # Not an AbstractHAPChannel: the AirParrot path opens a plain TCP
        # RawVideoTCPChannel and the UDP path a MirrorVideoDatagramChannel.
        # All three only ever have send() called on them.
        self._video_channel: Optional[streams.SendChannel] = None
        self._audio_channel: Optional[AbstractHAPChannel] = None
        self._audio_udp: Optional[asyncio.BaseTransport] = None
        self._event_transport: Optional[asyncio.BaseTransport] = None
        self._control_transport: Optional[asyncio.BaseTransport] = None
        self._control_channel: Optional[AbstractHAPChannel] = None
        self._video_sock: Optional[socket.socket] = None
        self._audio_control_sock: Optional[socket.socket] = None
        self._video_transport: Optional[asyncio.BaseTransport] = None
        self._audio_transport: Optional[asyncio.BaseTransport] = None
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
        if _airparrot_mode():
            # Exact AirParrot flow (verified via LLDB socket capture 2026-08-24):
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
            if os.environ.get("MIRROR_AUDIO_SEND"):
                self._register(asyncio.ensure_future(self._stream_screen_audio()))
            await self._stream_until_done()
            return
        # The receiver hands back an eventPort and expects the sender to
        # connect to it; RECORD is not answered until that channel is up.
        await self._open_event_channel()
        # The captured macOS sender queries /info again between the
        # session-init SETUP and RECORD (Phase 28 capture, seq 37).
        await self._rtsp.info()
        await self._record()
        await self._setup_streams()
        await self._open_channels()
        await self._stream_until_done()

    async def _setup_session(self) -> None:
        """Send the session-init SETUP (no streams) and record the event port.

        Phase 28 captured a real macOS mirroring session through atvproxy and
        found the modern flow has no ANNOUNCE/SDP at all. Instead the sender
        opens with a metadata-only SETUP that returns ``eventPort``. Crucially
        the body must NOT carry ``ekey``/``eiv``/``et`` — FPLY v3 has already
        established keying and the receiver drops the connection outright if a
        sender re-sends stream keys here. See
        docs/superpowers/specs/2026-08-22-fply-phase28-ground-truth-capture.md.
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
        timing_port = self._timing_server.port

        # Advertise the same AirPlay version we claim in ``sourceVersion``.
        self._rtsp.user_agent = MIRROR_USER_AGENT

        session_uuid = str(uuid4()).upper()
        # Retained so the AirParrot-dialect stream SETUP can echo the same
        # session identity (it repeats sessionUUID / deviceID / macAddress).
        self._session_uuid = session_uuid
        self._device_id = self._ctx.device_id or _device_id_from_uuid(session_uuid)
        self._mac_address = self._ctx.mac_address or _device_id_from_uuid(str(uuid4()))
        body = {
            "statsCollectionEnabled": False,
            "updateSessionRequest": False,
            "timingProtocol": "NTP",
            "sessionUUID": session_uuid,
            "osName": self._ctx.os_name,
            "osBuildVersion": self._ctx.os_build_version,
            "timingPort": timing_port,
            "sourceVersion": self._ctx.source_version,
            "isScreenMirroringSession": True,
            "osVersion": self._ctx.os_version,
            "isMultiSelectAirPlay": False,
            "sessionCorrelationUUID": str(uuid4()).upper(),
            "deviceID": self._device_id,
            "model": self._ctx.model,
            "name": self._ctx.name,
            "macAddress": self._mac_address,
        }
        if _airparrot_mode():
            # AirParrot sends NO macOS-AVConference session-init SETUP. Its flow
            # is SETUP(audio 96) -> connect eventPort -> RECORD -> SETUP(video
            # 110). The eventPort comes from the AUDIO SETUP response (not here).
            self._ctx.event_port = 0
            _LOGGER.debug("AirParrot mode: skipping session-init SETUP")
            return
        resp = await self._rtsp.setup(headers=dict(_SUPPRESS_RAOP_HEADERS), body=body)
        if resp.code != 200:
            raise exceptions.ProtocolError(
                f"SETUP (session init) failed: HTTP {resp.code}"
            )
        decoded = decode_bplist_from_body(resp)
        self._ctx.event_port = decoded.get("eventPort", 0)
        _LOGGER.debug("Mirror session established, eventPort=%d", self._ctx.event_port)

    async def _open_event_channel(self) -> None:  # pylint: disable=too-many-statements
        """Connect the event channel advertised by the session SETUP.

        macOS AVConference encrypts this channel with HAP-derived keys. The
        AirParrot dialect (no HAP pair-verify -> no channel keys) uses a
        PLAINTEXT TCP connection instead; the receiver only needs the socket
        up before it will answer RECORD.
        """
        if not self._ctx.event_port:
            _LOGGER.debug("No eventPort returned; skipping event channel")
            return
        addr = self._rtsp.connection.remote_ip
        if _airparrot_mode():
            reader, writer = await asyncio.open_connection(addr, self._ctx.event_port)
            self._event_reader = reader
            self._event_transport = writer.transport
            self._event_writer = writer

            async def _serve_events() -> None:  # pylint: disable=too-many-locals
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
                            body = buf[hdr_end + 4 : total]
                            buf = buf[total:]
                            _LOGGER.info(
                                "EVENT req: %s (CSeq %s, body %dB)",
                                req_line,
                                cseq,
                                clen,
                            )
                            if body and os.environ.get("MIRROR_DUMP_EVENTS"):
                                try:
                                    _LOGGER.info(
                                        "EVENT body plist: %r", plistlib.loads(body)
                                    )
                                except Exception:
                                    _LOGGER.debug(
                                        "EVENT body raw: %s", body[:200].hex()
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
            return
        transport, _channel = await self._open_channel(
            channels.EventChannel,
            addr,
            self._ctx.event_port,
            EVENTS_SALT,
            EVENTS_READ_INFO,  # NB: read/write reversed for event channel
            EVENTS_WRITE_INFO,
        )
        self._event_transport = transport
        _LOGGER.debug("Event channel connected on port %d", self._ctx.event_port)

    def _build_ekey_eiv(self):
        """Return (ekey, eiv) for the AirParrot stream SETUP, or (None, None).

        AirParrot transports a FairPlay-wrapped stream key in ``ekey`` + a
        16-byte ``eiv``. We proved the receiver decrypts video with the
        *derived* key (SQAirPlayClientSessionDeriveKeyAndIV), so it can derive
        the key itself; the first cut therefore omits ekey to test whether the
        receiver self-derives. If it rejects the SETUP, ekey must be generated
        by emulating ``_airplay_package_encryption_key`` (see handoff SESSION 3).
        ``MIRROR_EKEY``/``MIRROR_EIV`` (hex) allow injecting a captured pair.
        """
        ekey_hex = os.environ.get("MIRROR_EKEY")
        eiv_hex = os.environ.get("MIRROR_EIV")
        if ekey_hex and eiv_hex:
            return bytes.fromhex(ekey_hex), bytes.fromhex(eiv_hex)
        # The emulator-packaged ekey (wraps our chosen raw16). eiv is a 16-byte
        # value sent alongside; the video IV itself is derived from raw16, so a
        # random eiv is used unless one is pinned via MIRROR_EIV.
        if self._ctx.ekey:
            # eiv is a sender-chosen random 16B (AirParrot's sess[0xa8]); pyatv
            # is the sender, so it picks its own. The video IV itself derives
            # from raw16, so eiv's value is free unless the receiver validates it.
            eiv = bytes.fromhex(eiv_hex) if eiv_hex else secrets.token_bytes(16)
            return self._ctx.ekey, eiv
        return None, None

    async def _setup_audio_stream(self) -> None:
        """Send AirParrot's type-96 AUDIO stream SETUP (before RECORD).

        AirParrot's real flow is SETUP(audio 96) -> RECORD -> SETUP(video 110);
        the audio SETUP must come first or RECORD returns 455. The receiver also
        needs the audio (screen-audio) stream present to accept the video.
        Includes ``controlPort`` (a bound UDP port) as AirParrot does.
        """
        if self._audio_setup_done:
            return
        if not (
            self._ctx.audio_ekey and os.environ.get("MIRROR_AUDIO_STREAM", "1") != "0"
        ):
            return
        self._audio_setup_done = True
        timing_port = self._timing_server.port if self._timing_server else 0
        # Bind a UDP control port and advertise it, mirroring AirParrot.
        if self._audio_control_sock is None:
            self._audio_control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._audio_control_sock.bind((self._rtsp.connection.local_ip, 0))
        control_port = self._audio_control_sock.getsockname()[1]
        audio_id = secrets.randbits(32)
        audio_eiv = secrets.token_bytes(16)
        # The eiv is retained so the (optional) screen-audio sender can
        # AES-128-CBC encrypt AAC-ELD frames with (key=raw16, iv=eiv) — the
        # receiver derives the same from the audio ekey/eiv (see
        # airparrot_audio.py + audio spec). audio_id needs no such stash: it
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
                    "spf": int(os.environ.get("MIRROR_AUDIO_SPF", "480")),
                    "audioFormat": 16777216,
                    "controlPort": control_port,
                    "usingScreen": True,
                }
            ],
            "et": 32,
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
        # response (AirParrot dialect), not a session-init SETUP.
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
        """Send the mirror video stream SETUP and record the data ports.

        Sent AFTER ``RECORD`` — that ordering comes straight from the Phase 28
        capture and is the reverse of the AirPlay-1 flow. Keys are not
        transported: the receiver derives them from the FPLY secret plus the
        ``encryptionSeed`` values sent here.
        """
        self._ctx.encryption_seed = secrets.randbits(64)
        self._ctx.control_encryption_seed = secrets.randbits(64)

        # networkInfo.Port is the UDP port we will *send video from*, not a
        # separate listener: the real sender advertises the source port of its
        # media datagrams. Bind it now so the value we announce is the one the
        # receiver will actually see packets arrive from -- a receiver
        # filtering on the announced 5-tuple accepts datagrams at the socket
        # layer (no ICMP) but ignores them if the source port disagrees.
        self._video_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._video_sock.bind((self._rtsp.connection.local_ip, 0))
        network_port = self._video_sock.getsockname()[1]

        # AirParrot uses 32-bit streamConnectionIDs; the receiver appears to
        # store it in a 32-bit field, so a 63-bit value would make the
        # receiver's key-derivation label ("AirPlayStreamKey"+id) disagree with
        # ours. Match AirParrot's range in AirParrot mode.
        self._ctx.stream_connection_id = (
            secrets.randbits(32) if _airparrot_mode() else secrets.randbits(63)
        )
        if _airparrot_mode():
            # AirParrot dialect (reverse-engineered 2026-08-23): a simple
            # type-110 video stream plus session identity at the top level, and
            # a FairPlay-wrapped key transported in `ekey`/`eiv`. The receiver
            # returns a *TCP* dataPort (not the UDP one the AVConference dialect
            # gets). See airparrot_stream.py + the SESSION 3 handoff.
            timing_port = self._timing_server.port if self._timing_server else 0
            # AUDIO stream SETUP already sent (before RECORD, from run()).
            _mirror_et = int(os.environ.get("MIRROR_ET", "32"))
            body = {
                "streams": [
                    {
                        "type": 110,  # AirParrot video stream type
                        "streamConnectionID": self._ctx.stream_connection_id,
                        "timestampInfo": [
                            {"name": name}
                            for name in ("SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc")
                        ],
                    }
                ],
                "et": _mirror_et,
                "timingPort": timing_port,
                "sessionUUID": self._session_uuid or str(uuid4()).upper(),
                "osBuildVersion": self._ctx.os_build_version,
                "sourceVersion": self._ctx.source_version,
                "deviceID": self._device_id,
                "macAddress": self._mac_address,
                "name": self._ctx.name,
                "model": self._ctx.model,
            }
            ekey, eiv = self._build_ekey_eiv() if _mirror_et == 32 else (None, None)
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
        else:
            body = {
                "streams": [
                    {
                        "type": framing.STREAM_TYPE_VIDEO,
                        "streamConnectionID": self._ctx.stream_connection_id,
                        "encryptionSeed": self._ctx.encryption_seed,
                        "streamConnections": {
                            "streamConnectionTypeMediaDataControl": {
                                "streamConnectionKeyEncryptionSeed": (
                                    self._ctx.control_encryption_seed
                                ),
                            }
                        },
                        "networkInfo": {"Port": network_port},
                        "useAVConfMirroring": True,
                        "displayHDRMode": "SDR",
                        "hdrMirroringSupported": False,
                        "streamMode": 0,
                        "remoteLogLevel": 0,
                        "remoteShouldShowHUD": False,
                        "timestampInfo": [
                            {"name": name}
                            for name in ("SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc")
                        ],
                        "negotiationData": negotiation.build_negotiation_data(
                            model=self._ctx.model,
                            source_version=self._ctx.endpoint_version,
                            os_build=self._ctx.os_build_version,
                            # Describe the geometry we actually stream, not the
                            # display of the machine the blob was captured from.
                            source_size=(self._ctx.width, self._ctx.height),
                        ),
                    }
                ]
            }
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
        control = stream.get("streamConnections", {}).get(
            "streamConnectionTypeMediaDataControl", {}
        )
        self._ctx.stream_control_port = control.get("streamConnectionKeyPort", 0)
        # Derive the screen-video key from the pair-verify (HAP) shared secret.
        #
        # Static analysis of Apple's own AirPlayReceiver (Phase 29) shows tvOS 26
        # screen mirroring uses the CoreUtils "DataStream" path: the receiver's
        # _ScreenSetup/_GetDataStreamSecurityKeys derives a 32-byte key via
        # PairingSessionDeriveKey = HKDF-SHA512 over the pair-verify shared
        # secret with salt "DataStream-Salt"+decimal(streamConnectionID) and
        # info "DataStream-Output-Encryption-Key", then decrypts frames with
        # ChaCha20-Poly1305 (NOT the FairPlay master key, and NOT AES). pyatv's
        # verifier.encryption_keys IS that HKDF.
        if not _airparrot_mode():
            # AVConference/DataStream path only. AirParrot keys the video with
            # the FairPlay raw16 (+ pair-verify shared) as AES-CTR, so there is
            # no DataStream HKDF here and no verifier to derive from.
            self._ctx.datastream_video_key = framing.derive_datastream_video_key(
                self._verifier, self._ctx.stream_connection_id
            )
        _LOGGER.debug(
            "Mirror stream established, dataPort=%d controlPort=%d "
            "(SRTP AES-128-CTR video key from DataStream HKDF, "
            "streamConnectionID %d)",
            self._ctx.video_data_port,
            self._ctx.stream_control_port,
            self._ctx.stream_connection_id,
        )

    async def _open_control_channel(self, addr: str) -> None:
        """Connect the media-data-control channel, retrying briefly.

        The receiver can take a moment to start listening after answering the
        stream SETUP, so a single attempt races it.
        """
        last_error: Optional[OSError] = None
        for attempt in range(CONTROL_CHANNEL_ATTEMPTS):
            try:
                transport, channel = await self._open_channel(
                    streams.MirrorControlChannel,
                    addr,
                    self._ctx.stream_control_port,
                    MIRROR_CONTROL_SALT + str(self._ctx.control_encryption_seed),
                    MIRROR_CONTROL_OUTPUT_INFO,
                    MIRROR_CONTROL_INPUT_INFO,
                )
            except OSError as ex:
                last_error = ex
                await asyncio.sleep(CONTROL_CHANNEL_RETRY_DELAY)
                continue
            self._control_transport = transport
            self._control_channel = channel
            _LOGGER.debug(
                "Media-data-control channel open on port %d (attempt %d)",
                self._ctx.stream_control_port,
                attempt + 1,
            )
            return

        _LOGGER.warning(
            "Media-data-control channel unavailable on port %d after %d "
            "attempts (%s). The receiver opens its UDP data port only once "
            "this channel is up, so video will not be delivered.",
            self._ctx.stream_control_port,
            CONTROL_CHANNEL_ATTEMPTS,
            last_error,
        )

    async def _open_channels(self) -> None:
        """Open the media transports negotiated by the stream SETUP.

        Probing a real Apple TV (tvOS 26.6) after a successful stream SETUP
        shows an unambiguous split:

        =========================  =========  ==========
        port                       TCP        UDP
        =========================  =========  ==========
        ``dataPort``               refused    **open**
        ``streamConnectionKeyPort`` **open**  ICMP unreachable
        =========================  =========  ==========

        So mirror video is sent as UDP datagrams to ``dataPort`` (matching the
        receiver's ``hasUDPMirroringSupport: True``), while
        ``streamConnectionKeyPort`` is a HAP-encrypted TCP control channel.
        """
        addr = self._rtsp.connection.remote_ip

        # The control connection must come first: the receiver only opens the
        # UDP data port once it is established. When it is missing, every
        # datagram we send comes back as ICMP port-unreachable.
        if self._ctx.stream_control_port:
            await self._open_control_channel(addr)

        loop = asyncio.get_event_loop()
        # Declared up front: the branches below open a TCP connection and a
        # UDP endpoint respectively, which have neither transport nor channel
        # type in common beyond these two.
        v_transport: asyncio.BaseTransport
        v_channel: streams.SendChannel
        if _airparrot_mode():
            # AirParrot's mirror video is a RAW TCP connection to dataPort
            # (no HAP/ChaCha layer; the AES-CTR on each frame is the only
            # encryption). Verified by decrypting AirParrot's live TCP stream.
            v_transport, v_channel = await loop.create_connection(
                airparrot_stream.RawVideoTCPChannel,
                addr,
                self._ctx.video_data_port,
            )
            self._video_transport, self._video_channel = v_transport, v_channel
            _LOGGER.debug(
                "Raw TCP video channel open to %s:%d",
                addr,
                self._ctx.video_data_port,
            )
        else:
            # Reuse the socket bound in _setup_streams so datagrams leave from
            # the port announced as networkInfo.Port.
            v_transport, v_channel = await loop.create_datagram_endpoint(
                lambda: streams.MirrorVideoDatagramChannel(
                    (addr, self._ctx.video_data_port)
                ),
                sock=self._video_sock,
            )
            # The endpoint owns the socket now and closes it with the
            # transport; dropping the reference is what tells stop() not to
            # close it a second time, out from under the event loop.
            self._video_sock = None
            self._video_transport, self._video_channel = v_transport, v_channel
            _LOGGER.debug(
                "Video datagram channel open to %s:%d",
                addr,
                self._ctx.video_data_port,
            )

        # The modern mirror flow negotiates the video stream only (Phase 28
        # capture shows a single type-110 stream); audio is not part of the
        # screen-mirroring SETUP. Open the audio channel only if a port was
        # actually negotiated. In AirParrot mode the audio channel is NOT a
        # HAP-encrypted channel (no verifier); skip it for now (video-only
        # render — the receiver still switches to mirror on the video stream).
        if self._ctx.audio_data_port and not _airparrot_mode():
            a_transport, a_channel = await self._open_channel(
                streams.AudioStreamChannel,
                addr,
                self._ctx.audio_data_port,
                MIRROR_AUDIO_SALT,
                MIRROR_AUDIO_OUTPUT_INFO,
                MIRROR_AUDIO_INPUT_INFO,
            )
            self._audio_transport, self._audio_channel = a_transport, a_channel

    async def _stream_screen_audio(self) -> None:
        """Send screen audio as AAC-ELD over UDP/RTP (AirParrot dialect).

        VERIFIED playing on tvOS 26 (mic-confirmed +15 dB, drops on stop). The
        key detail: the sync (0xD4) MUST be sent FROM the advertised controlPort
        socket, or the receiver never opens its audio control channel and refuses
        the sync (ICMP), leaving the audio unscheduled/silent.
        Gated behind MIRROR_AUDIO_SEND. Reads length-prefixed AAC-ELD frames
        (4-byte BE length + frame, repeated) from MIRROR_AUDIO_ELD_FILE and
        sends them as RTP packets to the type-96 audio dataPort, AES-128-CBC
        encrypted with (key=raw16, iv=eiv). See airparrot_audio.py + the audio
        spec. If no file is set, sends nothing (matches AirParrot on silence).
        """
        # One method because the sequence -- key derivation, two sockets,
        # the sync packet, then the send loop -- has to be read in order.
        # pylint: disable=too-many-locals,too-many-branches
        # pylint: disable=too-many-statements
        port = self._ctx.audio_data_port
        eld_file = os.environ.get("MIRROR_AUDIO_ELD_FILE")
        audio_live_cmd = os.environ.get("MIRROR_AUDIO_LIVE_CMD")
        _pair32_hex = os.environ.get("MIRROR_PAIR32", "")
        raw16 = self._ctx.stream_raw16
        iv = self._ctx.audio_eiv
        # Audio key = secret16 = sha512(raw16 || pair32)[:16] (DeriveAudioKeyAndIV
        # passes sess[0xa0] through PairingContextDeriveKey when the flag is set;
        # NO "AirPlayStreamKey" labeling, unlike video).
        if len(raw16) == 16 and _pair32_hex:
            key = hashlib.sha512(raw16 + bytes.fromhex(_pair32_hex)).digest()[:16]
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
        spf = int(os.environ.get("MIRROR_AUDIO_SPF", "480"))
        latency = 2205  # matches AirParrot's captured sync (now - now_without_latency)
        base_ts = int(time.time()) & 0xFFFFFFFF
        pk = airparrot_audio.AirParrotAudioPacketizer(
            key, iv, ssrc=0, spf=spf, base_ts=base_ts
        )
        interval = spf / airparrot_audio.AUDIO_SAMPLE_RATE
        sync_every = int(
            os.environ.get(
                "MIRROR_AUDIO_SYNC_EVERY",
                str(max(1, int(airparrot_audio.AUDIO_SAMPLE_RATE / spf))),
            )
        )  # ~1/s

        adv_ctrl = self._audio_control_sock
        if adv_ctrl is not None:
            adv_ctrl.setblocking(False)
            if os.environ.get("MIRROR_DUMP_EVENTS"):

                def _ctrl_rx():
                    try:
                        while True:
                            data, a = adv_ctrl.recvfrom(2048)
                            _LOGGER.debug(
                                "AUDIO CTRL RX %dB from %s: %s",
                                len(data),
                                a,
                                data[:20].hex(),
                            )
                    except BlockingIOError:
                        pass
                    except Exception:  # noqa: BLE001
                        pass

                try:
                    loop.add_reader(adv_ctrl.fileno(), _ctrl_rx)
                except Exception:  # noqa: BLE001
                    pass

        def _send_sync(first: bool) -> None:
            if ctrl_port == 0:
                return
            # last_sync MUST be in the SAME clock domain as the TimingServer
            # (NTP-since-1900 via ntp_now), or the receiver correlates two
            # epochs 2.2e9 s apart and re-syncs the audio every sync packet
            # (~1/s) — an audible glitch each second.
            sync = airparrot_audio.build_audio_sync_packet(
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
            live_audio_q = asyncio.Queue(
                maxsize=int(os.environ.get("MIRROR_AUDIO_LIVE_BUFFER", "1200"))
            )
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
            _prebuf = int(os.environ.get("MIRROR_AUDIO_PREBUFFER", "180"))
            for _ in range(300):
                if live_audio_q.qsize() >= _prebuf:
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

    async def _airparrot_live_video(
        self, live_cmd: str, video_q: "asyncio.Queue", video_encryptor
    ) -> None:
        """Stream a LIVE H.264 source (AirParrot dialect) in real time.

        ``live_cmd`` is a shell command that writes an Annex-B H.264 elementary
        stream to stdout (e.g. ``yt-dlp -o - <url> | ffmpeg ... -f h264 -``).
        NAL units are parsed incrementally as they arrive, grouped into access
        units, buffered (dropping oldest to bound latency), and paced out at the
        configured fps. SPS/PPS go into the plaintext avcC config frame; VCL
        frames are sent as continuous-keystream AES-CTR messages, exactly like
        the file path. Gated by ``MIRROR_LIVE_CMD``.
        """
        # pylint: disable=too-many-locals,too-many-statements
        fps = max(self._ctx.fps, 1)
        frame_interval = 1.0 / fps
        w, h = float(self._ctx.width), float(self._ctx.height)
        geometry = airparrot_stream.build_geometry(w, h, 0.0, 0.0, w, h)
        loop = asyncio.get_event_loop()

        proc = await asyncio.create_subprocess_shell(
            live_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._live_proc = proc
        live_q: asyncio.Queue = asyncio.Queue(
            maxsize=int(os.environ.get("MIRROR_LIVE_BUFFER", "90"))
        )
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
                    # ``airparrot_stream._VCL_TYPES`` (1..5), which is the same
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

            config = airparrot_stream.build_avcc_config(state["sps"], state["pps"])
            config_hdr = airparrot_stream.build_data_header(
                len(config),
                0,
                geometry,
                # pylint: disable-next=protected-access
                msg_type=airparrot_stream._CONFIG_TYPE,
                dims=(w, h),
            )
            await video_q.put(config_hdr + config)
            _LOGGER.info(
                "live video: sent avcC config (%d B), streaming live @%dfps",
                len(config),
                fps,
            )
            await asyncio.sleep(float(os.environ.get("MIRROR_LIVE_PREBUFFER", "0.5")))

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
                avcc = airparrot_stream.to_avcc(au)
                ciphertext = video_encryptor.encrypt(avcc)
                # Real monotonic clock at send time: always increasing, so the
                # receiver keeps advancing its display even across underruns.
                header = airparrot_stream.build_data_header(
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
        # pylint: disable=too-many-locals,too-many-branches
        # pylint: disable=too-many-statements
        if self._ctx.stream_encryptor is None:
            raise RuntimeError(
                "MirrorContext.stream_encryptor not set — "
                "did the MFiSAP handshake complete?"
            )

        encryptor = self._ctx.stream_encryptor
        video_q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_HIGH_WATERMARK)
        audio_q: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_HIGH_WATERMARK)

        video_pacer = pacer.H264NaluPacer(self._h264_path, fps=self._ctx.fps)
        audio_pacer = pacer.SilentAacPacer()

        video_encryptor = self._ctx.video_encryptor or encryptor

        ticks_per_frame = rtp.CLOCK_RATE // max(self._ctx.fps, 1)

        # FairPlay keybuf -> video key. The mirror video is FairPlay-keyed; the
        # key is SHA512("AirPlayStreamKey"+id||keybuf)[:16] (salt likewise from
        # "AirPlayStreamIV "), where ``keybuf`` is the FairPlay SAP secret
        # (see fairplay_sap). MIRROR_KEYBUF_WINDOW="start:end" takes
        # ctx[start:end] of the SAP context as the keybuf (a sweep from when
        # real extraction had not landed). MIRROR_KEYBUF_MODE selects the
        # cipher:
        #   "srtp" (default)  -> per-packet SRTP AES-128-CTR across the SSRCs,
        #                        cipher from payload offset 8 (the real framing),
        #   "continuous"      -> single continuous AES-CTR keystream, 1 SSRC.
        keybuf_encryptor = None
        keybuf_srtp_key = None  # (key16, salt14) for the per-packet SRTP path
        keybuf_window = os.environ.get("MIRROR_KEYBUF_WINDOW")
        keybuf_mode = os.environ.get("MIRROR_KEYBUF_MODE", "srtp")
        # MIRROR_KEYBUF_DERIV: how the SRTP master key/salt come from the window:
        #   "sha512" (default) -> SHA512("AirPlayStreamKey"+id||window)[:16] (the
        #                         LEGACY TCP-screen recipe; disproven for UDP).
        #   "direct"           -> the window IS the SRTP master key(16)+salt(14),
        #                         used verbatim (tvOS 26 Viceroy suite-5 model:
        #                         a sender-chosen 16B AES master key used directly
        #                         with the RFC3711 AES-CM session KDF).
        keybuf_deriv = os.environ.get("MIRROR_KEYBUF_DERIV", "sha512")

        # PROVEN video-key recipe (default when no explicit KEYBUF_WINDOW sweep).
        #
        # Reverse-engineered and byte-verified against AirParrot 3's live
        # derivation on a tvOS 26 receiver (LLDB, 2026-08-23 — see
        # docs/.../2026-08-23-mirror-video-key-handoff.md SESSION 3 and memory
        # note project-mirror-video-key-solved). AirParrot's
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
        # streamConnectionID we sent in SETUP). MIRROR_VIDEO=legacy disables it.
        if (
            not keybuf_window
            and os.environ.get("MIRROR_VIDEO", "proven") == "proven"
            and (self._ctx.sap_context or self._ctx.stream_raw16)
        ):
            # Prefer the raw16 we CHOSE and packaged into ekey (the receiver
            # unwraps ekey -> this raw16 and derives the same key). Fall back to
            # a sap_context slice for the no-ekey experiments.
            if self._ctx.stream_raw16 and len(self._ctx.stream_raw16) == 16:
                raw16 = self._ctx.stream_raw16
            else:
                raw16_off = int(os.environ.get("MIRROR_RAW16_OFF", "8"))
                raw16 = self._ctx.sap_context[raw16_off : raw16_off + 16]
            # The screen video key uses the MEDIA-connection pair-verify's X25519
            # shared secret (AirParrot's raw /pair-verify), NOT the main HAP
            # pair-verify. MIRROR_PAIR32 (hex) supplies that media pair-verify
            # shared when pyatv relays the raw pair-verify.
            _pair32_ovr = os.environ.get("MIRROR_PAIR32")
            pair32: Optional[bytes]
            if _pair32_ovr:
                pair32 = bytes.fromhex(_pair32_ovr)
            else:
                pair32 = getattr(getattr(self._verifier, "srp", None), "_shared", None)
            if len(raw16) == 16 and pair32 and len(pair32) == 32:
                # AirParrot's live session bound the FairPlay secret with the
                # pair-verify secret (flag[0xb0]==1). pyatv's simpler SETUP may
                # take the flag==0 path where raw16 is used directly.
                # MIRROR_PAIR_TRANSFORM=0 selects the direct path.
                _flag = os.environ.get("MIRROR_PAIR_TRANSFORM", "1") != "0"
                secret16 = framing.airparrot_secret16(raw16, bytes(pair32), _flag)
                sid = self._ctx.stream_connection_id
                key, iv = framing.derive_airparrot_stream_key_iv(
                    raw16, bytes(pair32), sid, flag=_flag
                )
                if os.environ.get("MIRROR_CORRUPT_VIDEO_KEY"):
                    key = bytes([key[0] ^ 0xFF]) + key[1:]
                    _LOGGER.warning("VIDEO KEY DELIBERATELY CORRUPTED (test)")
                keybuf_encryptor = framing.MirrorEncryptor.from_key_iv(key, iv)
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
                    "falling back to experimental key paths",
                    len(raw16),
                    "None" if not pair32 else f"{len(pair32)}B",
                )

        if keybuf_window and self._ctx.sap_context:
            start, end = (int(x) for x in keybuf_window.split(":"))
            keybuf = self._ctx.sap_context[start:end]
            sid = self._ctx.stream_connection_id & 0xFFFFFFFFFFFFFFFF
            sid_override = os.environ.get("MIRROR_KEYBUF_STREAMID")
            if sid_override is not None:
                sid = int(sid_override) & 0xFFFFFFFFFFFFFFFF
            if keybuf_deriv == "direct":
                # window = master key(16) || master salt(14), used verbatim.
                key = self._ctx.sap_context[start : start + 16]
                iv = self._ctx.sap_context[start + 16 : start + 32]
            else:
                key, iv = framing.stream_key_iv_from_secret(keybuf, sid)
            if keybuf_mode == "continuous":
                keybuf_encryptor = framing.MirrorEncryptor.from_key_iv(key, iv)
            else:
                keybuf_srtp_key = (key[:16], iv[:14])
            _LOGGER.debug(
                "KEYBUF ACTIVE window=%s deriv=%s mode=%s key=%s iv=%s",
                keybuf_window,
                keybuf_deriv,
                keybuf_mode,
                key.hex(),
                iv.hex(),
            )

        # Number of parallel video SSRCs. The real sender stripes each frame
        # across 4 synchronised SSRCs (base+0..3, shared frame-counter/timestamp,
        # each with its own SRTP session key); ``MIRROR_SSRC_COUNT`` selects how
        # many pyatv emits (1 = single stream, 4 = replicate the real striping).
        if keybuf_encryptor:
            ssrc_count = 1  # continuous keystream is single-SSRC
        elif keybuf_srtp_key:
            ssrc_count = max(1, int(os.environ.get("MIRROR_SSRC_COUNT", "4")))
        else:
            ssrc_count = max(1, int(os.environ.get("MIRROR_SSRC_COUNT", "1")))
        base_ssrc = secrets.randbits(32)
        packetizers = [
            rtp.RtpPacketizer(ssrc=(base_ssrc + i) & 0xFFFFFFFF)
            for i in range(ssrc_count)
        ]

        # SRTP AES-128-CTR encryptors, one per SSRC (Apple's AES128AuthNoneRCCM3).
        # KEY SOURCE: the mirror video is FairPlay (ET=32) keyed. A ground-truth
        # atvproxy capture DISPROVED pair-verify keying (see srtp.py docstring
        # and memory note project-mirror-not-pairverify-keyed): with the exact
        # shared secret + ciphertext, no HKDF/SHA512 recipe over it decrypts to
        # H.264. The real key is the FairPlay SAP keybuf (keybuf_encryptor /
        # fply path). MIRROR_SRTP_SECRET selects the fallback when no keybuf
        # encryptor is set:
        #   "fply" (default)   -> the FairPlay-derived stream key/iv, or
        #   "pairverify"       -> disproven raw-shared-secret DataStream A/B, or
        #   "datastream"       -> disproven precomputed DataStream key.
        # Env toggles: MIRROR_SRTP_KDF (per-SSRC HMAC KDF),
        # MIRROR_SRTP_ROC_TRAILER (4-byte RCCM3 trailer).
        secret_src = os.environ.get("MIRROR_SRTP_SECRET", "fply")
        shared_key = getattr(getattr(self._verifier, "srp", None), "shared_key", None)
        master_material = None
        srtp_encs: list = []
        if keybuf_encryptor is not None:
            # An encryptor handed in on the context is an explicit caller
            # choice and outranks the derived one -- line ~1250 already
            # promises `self._ctx.video_encryptor or encryptor`, and this
            # branch used to quietly take it back. The branch is still
            # *taken* either way, so srtp_encs stays empty exactly as before;
            # only the reassignment is skipped. ctx.video_encryptor is None in
            # every shipping configuration, where this is unchanged.
            if self._ctx.video_encryptor is None:
                video_encryptor = keybuf_encryptor  # continuous AES-CTR, 1 SSRC
        elif keybuf_srtp_key is not None:
            # FairPlay keybuf, per-packet SRTP AES-128-CTR across the SSRCs
            # (cipher covers payload[8:], per-RTP-packet IV). MIRROR_KEYBUF_SRTP_KDF:
            #   "direct" (default) -> use derived key/salt as the session key/salt,
            #   "aescm"            -> treat them as SRTP master key/salt and run the
            #                         RFC3711 AES-CM session KDF (standard SRTP).
            k16, s14 = keybuf_srtp_key
            srtp_kdf = os.environ.get("MIRROR_KEYBUF_SRTP_KDF", "direct")
            if srtp_kdf == "aescm":
                k16, s14 = srtp.derive_srtp_session_aescm(k16, s14)
                _LOGGER.debug(
                    "KEYBUF SRTP aescm session key=%s salt=%s", k16.hex(), s14.hex()
                )
            for pkt in packetizers:
                if srtp_kdf == "cc":
                    # AVConference _SRTPDeriveMediaKeyInfo: session key/salt =
                    # CCKeyDerivationHMac(6, SHA256, 0, master_key,
                    # context=derivedSSRC(4B), salt=master_salt) -> 30B (16+14).
                    # derivedSSRC = first 4 bytes of the master key material
                    # (VCControlChannelMultiWay getKeyDerivationCryptoSet@0x1b7baa150),
                    # SAME for all SSRCs -- NOT the RTP SSRC.
                    cc_ctx = os.environ.get("MIRROR_KEYBUF_CC_CONTEXT", "derived")
                    ctxb = k16[:4] if cc_ctx == "derived" else b""
                    # pylint: disable-next=protected-access
                    okm = srtp._cc_key_derivation_hmac(k16, s14, pkt.ssrc, ctxb)
                    sk, ss = okm[:16], okm[16:30]
                    if pkt is packetizers[0]:
                        _LOGGER.debug(
                            "KEYBUF SRTP cc ssrc=%x session key=%s salt=%s",
                            pkt.ssrc,
                            sk.hex(),
                            ss.hex(),
                        )
                    srtp_encs.append(
                        srtp.SrtpVideoEncryptor(sk, ss, pkt.ssrc, use_kdf=False)
                    )
                    continue
                srtp_encs.append(
                    srtp.SrtpVideoEncryptor(k16, s14, pkt.ssrc, use_kdf=False)
                )
        elif secret_src == "pairverify" and shared_key:
            session_kdf = os.environ.get("MIRROR_SRTP_KDF", "1") != "0"
            for pkt in packetizers:
                srtp_encs.append(
                    srtp.SrtpVideoEncryptor.from_shared_key(
                        shared_key,
                        self._ctx.stream_connection_id,
                        pkt.ssrc,
                        session_kdf=session_kdf,
                    )
                )
        elif secret_src == "fply" and self._ctx.stream_encryptor is not None:
            key = getattr(self._ctx.stream_encryptor, "key", b"")
            iv = getattr(self._ctx.stream_encryptor, "iv", b"")
            if len(key) >= 16 and len(iv) >= 14:
                master_material = key[:16] + iv[:14]
        elif self._ctx.datastream_video_key is not None:
            master_material = self._ctx.datastream_video_key

        if master_material is not None:
            master_key, master_salt = srtp.derive_master_key_salt(master_material)
            use_kdf = os.environ.get("MIRROR_SRTP_KDF", "1") != "0"
            roc_trailer = os.environ.get("MIRROR_SRTP_ROC_TRAILER", "0") != "0"
            for pkt in packetizers:
                enc = srtp.SrtpVideoEncryptor(
                    master_key, master_salt, pkt.ssrc, use_kdf=use_kdf
                )
                enc.roc_trailer = roc_trailer
                srtp_encs.append(enc)

        async def airparrot_video_producer() -> None:  # pylint: disable=too-many-locals
            """Send one raw-TCP message per H.264 access unit (AirParrot).

            Each message = 128-byte header + AES-128-CTR ciphertext, where the
            ciphertext is a single CONTINUOUS keystream across the whole stream
            (no per-frame reset) and the plaintext is the access unit in AVCC
            form (4-byte BE length + NAL per unit). Verified against AirParrot's
            live stream — see airparrot_stream.py.
            """
            live_cmd = os.environ.get("MIRROR_LIVE_CMD")
            if live_cmd:
                await self._airparrot_live_video(live_cmd, video_q, video_encryptor)
                return
            h264 = Path(self._h264_path).read_bytes()
            nalus = pacer.split_nalus(h264)
            # SPS/PPS are transported PLAINTEXT in the avcC config, NOT in the
            # encrypted frames (verified against AirParrot's stream), so strip
            # them from the frame NALs.
            sps = next((n for n in nalus if pacer.nal_type(n) == 7), None)
            pps = next((n for n in nalus if pacer.nal_type(n) == 8), None)
            # AirParrot's video frames carry only [SEI][slice]; SPS/PPS live
            # solely in the plaintext avcC config built below. Match that so
            # the receiver's screen decoder sees the same structure.
            # MIRROR_STRIP_SPSPPS=0 leaves them in the frames, for
            # experiments.
            strip_ps = os.environ.get("MIRROR_STRIP_SPSPPS", "1") != "0"
            frame_nalus = [
                n for n in nalus if not strip_ps or pacer.nal_type(n) not in (7, 8)
            ]
            units = airparrot_stream.group_access_units(frame_nalus, pacer.nal_type)
            if not units or sps is None or pps is None:
                _LOGGER.warning(
                    "AirParrot video: missing SPS/PPS or no access units "
                    "(sps=%s pps=%s units=%d)",
                    sps is not None,
                    pps is not None,
                    len(units),
                )
                return
            frame_interval = 1.0 / max(self._ctx.fps, 1)
            ns_per_frame = 1_000_000_000 // max(self._ctx.fps, 1)
            geom_hex = os.environ.get("MIRROR_GEOM_HEX")
            if geom_hex:
                geometry = bytes.fromhex(geom_hex)
            else:
                w, h = float(self._ctx.width), float(self._ctx.height)
                geometry = airparrot_stream.build_geometry(w, h, 0.0, 0.0, w, h)

            # 1) FIRST message: plaintext avcC decoder config (type 0x01000600),
            #    so the receiver can initialise its H.264 decoder. Not encrypted,
            #    so it does not advance the continuous AES-CTR keystream.
            config = airparrot_stream.build_avcc_config(sps, pps)
            config_hdr = airparrot_stream.build_data_header(
                len(config),
                0,
                geometry,
                # pylint: disable-next=protected-access
                msg_type=airparrot_stream._CONFIG_TYPE,
                dims=(float(self._ctx.width), float(self._ctx.height)),
            )
            await video_q.put(config_hdr + config)
            _LOGGER.info(
                "AirParrot video: sent avcC config (%d B), %d access units, "
                "continuous AES-CTR",
                len(config),
                len(units),
            )

            # 2) Then encrypted frames (type 0x00000600), continuous keystream.
            # The header timestamp ([8:16]) is a large monotonic mach-style value
            # (AirParrot uses mach_absolute_time); a 0-based value can fail the
            # receiver's timing validation.
            ts_base = time.monotonic_ns()
            _LOGGER.debug(
                "producer video_encryptor key=%s iv=%s",
                getattr(video_encryptor, "key", b"").hex(),
                getattr(video_encryptor, "iv", b"").hex(),
            )
            if os.environ.get("MIRROR_CONFIG_ONLY"):
                _LOGGER.info("MIRROR_CONFIG_ONLY: sent config, holding (no frames)")
                while True:
                    await asyncio.sleep(1.0)
            # Give the receiver time to initialise its decoder from the config
            # before the first encrypted frame (avoid a race).
            await asyncio.sleep(float(os.environ.get("MIRROR_CONFIG_DELAY", "0.3")))
            index = 0
            _loop_time = asyncio.get_event_loop().time
            _pace_start = _loop_time()
            while True:
                unit = units[index % len(units)]
                avcc = airparrot_stream.to_avcc(unit)
                if int(os.environ.get("MIRROR_ET", "32")) == 32:
                    ciphertext = video_encryptor.encrypt(avcc)  # continuous keystream
                else:
                    ciphertext = avcc  # et=1/0: no stream-level encryption
                header = airparrot_stream.build_data_header(
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

        async def video_producer() -> None:
            """Stripe each frame across the SSRCs and SRTP-encrypt each part.

            The real sender splits every frame across 4 synchronised SSRCs
            (shared frame-counter + timestamp). Here the length-prefixed H.264
            access unit is split into ``ssrc_count`` byte-parts; part *i* goes on
            SSRC base+i, SRTP AES-128-CTR encrypted with that SSRC's session key
            (per-packet IV keyed by the RTP sequence number, inside ``packetize``).
            The receiver reassembles the parts by shared frame-counter.
            """
            index = 0
            frame_counter = 0
            n = len(packetizers)
            async for nal, _pts, _ft in video_pacer.iter_paced(loop=True):
                payload = struct.pack(">I", len(nal)) + nal
                ts = index * ticks_per_frame
                part_len = (len(payload) + n - 1) // n
                for i, pkt in enumerate(packetizers):
                    part = payload[i * part_len : (i + 1) * part_len]
                    if srtp_encs:
                        datagrams = pkt.packetize(
                            part,
                            ts,
                            encryptor=srtp_encs[i],
                            frame_counter=frame_counter,
                        )
                    else:
                        encrypted = video_encryptor.encrypt(part)
                        video_encryptor.start_fresh_block()
                        datagrams = pkt.packetize(
                            encrypted, ts, frame_counter=frame_counter
                        )
                    for datagram in datagrams:
                        await video_q.put(datagram)
                frame_counter = (frame_counter + 1) & 0xFFFF
                index += 1

        async def audio_producer() -> None:
            async for payload, pts, _ft in audio_pacer.iter_paced():
                hdr = framing.MirrorHeader(
                    payload_size=len(payload),
                    payload_type=framing.PAYLOAD_TYPE_AUDIO,
                    timestamp_ntp=pts,
                    flags=0,
                )
                frame = framing.pack_mirror_frame(encryptor, hdr, payload)
                await audio_q.put(frame)

        assert self._video_channel is not None

        async def send_feedback(_msg) -> None:
            resp = await self._rtsp.feedback(allow_error=True)
            if os.environ.get("MIRROR_DUMP_EVENTS") and resp is not None:
                body = getattr(resp, "body", None)
                try:
                    _LOGGER.info(
                        "FEEDBACK resp code=%s body=%r",
                        getattr(resp, "code", "?"),
                        decode_bplist_from_body(resp) if body else None,
                    )
                except Exception:
                    raw = (
                        body
                        if isinstance(body, (bytes, bytearray))
                        else str(body).encode()
                    )
                    _LOGGER.info(
                        "FEEDBACK resp code=%s raw=%s",
                        getattr(resp, "code", "?"),
                        raw[:160],
                    )

        producer = airparrot_video_producer if _airparrot_mode() else video_producer
        # EXTEND, never replace: run() and _open_event_channel() have already
        # registered the screen-audio sender and the event-channel POST
        # /command responder here. Assigning drops them from the list, so
        # stop() never cancels or awaits them — today they still wind
        # themselves down off the ._stopped flag, but only by luck.
        self._register(
            asyncio.create_task(producer(), name="mirror-video-pacer"),
            asyncio.create_task(
                streams.drain_queue_to_channel(self._video_channel, video_q),
                name="mirror-video-drain",
            ),
        )
        if self._audio_channel is not None:
            self._register(
                asyncio.create_task(audio_producer(), name="mirror-audio-pacer"),
                asyncio.create_task(
                    streams.drain_queue_to_channel(self._audio_channel, audio_q),
                    name="mirror-audio-drain",
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

        The raw sockets are the part worth knowing about. ``_video_sock`` is
        bound in ``_setup_streams`` so the announced ``networkInfo.Port`` is
        the one datagrams leave from, and ``_audio_control_sock`` is used for
        bare ``sendto`` -- neither is a transport. The AVConference dialect
        hands ``_video_sock`` to a datagram endpoint, which adopts it and
        clears the reference here, so anything still set is ours to close and
        closing it cannot race a live transport.
        """
        for transport in (
            self._control_transport,
            self._event_transport,
            self._video_transport,
            self._audio_transport,
            self._audio_udp,
            self._timing_server,
        ):
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()

        for sock in (self._video_sock, self._audio_control_sock):
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()
        self._video_sock = None
        self._audio_control_sock = None

        # The live sources, which each producer also kills in its own
        # `finally`. That covers every way the producer can end -- except
        # ending before it starts: both spawn the subprocess and record it
        # here, then read an env var to size their queue, and a non-numeric
        # `MIRROR_LIVE_BUFFER` raises between the two. The process is then
        # running with no `finally` left to reach it, and a real source is
        # ffmpeg or yt-dlp, so it keeps encoding and downloading for as long
        # as it feels like. Killing an already-dead process is a no-op.
        for proc in (self._live_proc, self._audio_proc):
            if proc is not None and proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
        self._live_proc = None
        self._audio_proc = None
