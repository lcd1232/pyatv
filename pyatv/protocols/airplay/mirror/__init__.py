"""AirPlay 2 screen mirroring sender.

Streams H.264 video (and optionally AAC-ELD screen audio) to an Apple TV
(verified on tvOS 27): a type-110 video stream sent over TCP, keyed through a
FairPlay-wrapped key in ``ekey``/``eiv``. The FairPlay SAP handshake is
implemented in pure Python in
:mod:`~pyatv.protocols.airplay.mirror.fairplay_sap`.

This package is not wired into pyatv's public API: there is no
``FeatureName`` or interface method for mirroring, and nothing else in pyatv
imports it. It is used by driving the classes directly: on a fresh
connection run the media pair-verify (:func:`media_pair_verify`), then the
FPLY handshake (:func:`run_fply_handshake`), fill a :class:`MirrorContext`,
and :meth:`MirrorSession.run` with the pair-verify secret as
``pair_secret``.
"""

from pyatv.protocols.airplay.mirror.context import MirrorContext
from pyatv.protocols.airplay.mirror.fply import FPLYHandshake, run_fply_handshake
from pyatv.protocols.airplay.mirror.media_pair_verify import media_pair_verify
from pyatv.protocols.airplay.mirror.session import MirrorSession

__all__ = [
    "MirrorContext",
    "MirrorSession",
    "FPLYHandshake",
    "run_fply_handshake",
    "media_pair_verify",
]
