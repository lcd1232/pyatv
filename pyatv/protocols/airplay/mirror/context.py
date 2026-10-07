"""Per-session context shared between mirror submodules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pyatv.protocols.airplay.mirror.framing import MirrorEncryptor


@dataclass
class MirrorContext:
    """Parameters and derived crypto state for one mirror session."""

    # Source video geometry and frame rate.
    width: int = 1280
    height: int = 720
    fps: int = 30

    # Continuous-keystream AES-CTR encryptor from the MFiSAP handshake; the
    # fallback video cipher when no stream key can be derived.
    stream_encryptor: Optional[MirrorEncryptor] = None

    # Sender identity advertised in the stream SETUPs. The defaults have the
    # shape of a macOS sender, which the receiver's mirror path accepts.
    name: str = "pyatv"
    model: str = "Mac15,6"
    os_build_version: str = "24G517"
    source_version: str = "870.14.1"
    # Device ID / MAC sent in the stream SETUPs; None synthesizes a
    # pseudo-MAC per session.
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

    # FairPlay SAP context after M3. The video key falls back to ctx[8:24]
    # as raw16 when no ``stream_raw16`` is set.
    sap_context: bytes = b""

    # The 16-byte secret wrapped into ``ekey``. The receiver unwraps ekey to
    # this value and derives the stream keys from it, so the sender must too.
    stream_raw16: bytes = b""
    ekey: bytes = b""
    audio_ekey: bytes = b""
