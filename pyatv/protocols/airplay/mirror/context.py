"""Per-session context shared between mirror submodules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pyatv.protocols.airplay.mirror.framing import MirrorEncryptor


@dataclass
class MirrorContext:
    """Parameters and derived crypto state for one mirror session."""

    # From the test asset
    width: int = 1280
    height: int = 720
    fps: int = 30

    # Continuous-keystream AES-CTR encryptor returned by the MFiSAP
    # handshake. Same instance encrypts the M3 sig AND every subsequent
    # mirror frame payload.
    stream_encryptor: Optional[MirrorEncryptor] = None

    # Sender identity advertised in the stream SETUPs. Real senders pass
    # their hardware values; these defaults mirror the shape captured from a
    # macOS 15.7.4 sender (Phase 28) so the receiver's mirror path accepts us.
    name: str = "pyatv"
    model: str = "Mac15,6"
    os_build_version: str = "24G517"
    source_version: str = "870.14.1"
    # Hardware identifiers sent in the stream SETUPs. Real senders pass
    # their actual AirPlay device ID / WiFi MAC; when left as None a random
    # pseudo-MAC is synthesized per session.
    device_id: Optional[str] = None
    mac_address: Optional[str] = None

    # Filled in after RTSP SETUP
    video_data_port: int = 0
    audio_data_port: int = 0
    audio_control_port: int = 0
    audio_eiv: bytes = b""
    event_port: int = 0
    # streamConnectionID sent in the stream SETUP. The mirror video key/IV are
    # derived from it (see framing.derive_tcp_stream_key_iv), so it must be kept.
    stream_connection_id: int = 0
    # AES-CTR encryptor for mirror video payloads, keyed by the derivation
    # above rather than by the raw FairPlay key.
    video_encryptor: Optional[MirrorEncryptor] = None

    # The FPLY emulator's SAP context after M3 (ctx[8:44] holds the FairPlay
    # keybuf). The video key falls back to ctx[8:24] as raw16 when no
    # ``stream_raw16`` was chosen.
    sap_context: bytes = b""

    # TCP-dialect key transport: the 16-byte raw16 (SAP secret) we CHOSE
    # and packaged into ``ekey`` (the receiver unwraps ekey -> raw16 and derives
    # the video key from it, so we derive/encrypt with this same raw16).
    stream_raw16: bytes = b""
    ekey: bytes = b""
    audio_ekey: bytes = b""
