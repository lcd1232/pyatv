"""Per-session context shared between mirror submodules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from pyatv.protocols.airplay.mirror.framing import (
    ChaChaVideoEncryptor,
    MirrorEncryptor,
)


@dataclass
class MirrorContext:
    """Parameters and derived crypto state for one mirror session."""

    # From the test asset
    width: int = 1280
    height: int = 720
    fps: int = 30

    # AAC-LC audio configuration (matches SilentAacPacer constants:
    # 1024 samples / 48 kHz / 2 ch — see pacer.py for the rationale on
    # AAC-LC instead of AAC-ELD)
    audio_sample_rate: int = 48_000
    audio_frame_samples: int = 1024
    audio_channels: int = 2

    # Continuous-keystream AES-CTR encryptor returned by the MFiSAP
    # handshake. Same instance encrypts the M3 sig AND every subsequent
    # mirror frame payload.
    stream_encryptor: Optional[MirrorEncryptor] = None

    # Sender identity advertised in the session-init SETUP. Real senders pass
    # their hardware values; these defaults mirror the shape captured from a
    # macOS 15.7.4 sender (Phase 28) so the receiver's mirror path accepts us.
    name: str = "pyatv"
    model: str = "Mac15,6"
    os_name: str = "macOS"
    os_version: str = "15.7.4"
    os_build_version: str = "24G517"
    source_version: str = "870.14.1"
    # Version reported inside the Viceroy endpoint-info protobuf. Distinct
    # from source_version — the capture showed 2125.2.1 vs 870.14.1.
    endpoint_version: str = "2125.2.1"
    # Hardware identifiers sent in the session-init SETUP. Real senders pass
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
    # Control port the receiver returns under
    # streams[0].streamConnections.streamConnectionTypeMediaDataControl.
    stream_control_port: int = 0
    # Seeds sent in the stream SETUP; the receiver derives the stream keys
    # from these plus the FPLY shared secret (mechanism not yet reversed).
    encryption_seed: int = 0
    control_encryption_seed: int = 0
    # streamConnectionID sent in the stream SETUP. The mirror video key/IV are
    # derived from it (see framing.derive_stream_keys), so it must be kept.
    stream_connection_id: int = 0
    # AES-CTR encryptor for mirror video payloads, keyed by the derivation
    # above rather than by the raw FairPlay key.
    video_encryptor: Optional[Union[MirrorEncryptor, ChaChaVideoEncryptor]] = None

    # 32-byte DataStream-Output HKDF key (over the pair-verify secret) used to
    # derive the SRTP AES-128-CTR master key + salt for the mirror video stream.
    datastream_video_key: Optional[bytes] = None

    # The FPLY emulator's SAP context after M3 (ctx[8:44] holds the FairPlay
    # keybuf). Used by the MIRROR_KEYBUF_WINDOW sweep to derive the video key as
    # SHA512("AirPlayStreamKey"+id||keybuf)[:16] over continuous AES-CTR.
    sap_context: bytes = b""

    # AirParrot-dialect key transport: the 16-byte raw16 (SAP secret) we CHOSE
    # and packaged into ``ekey`` (the receiver unwraps ekey -> raw16 and derives
    # the video key from it, so we derive/encrypt with this same raw16).
    stream_raw16: bytes = b""
    ekey: bytes = b""
    audio_ekey: bytes = b""
