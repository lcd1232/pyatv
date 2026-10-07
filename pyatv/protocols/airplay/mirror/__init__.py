"""AirPlay 2 screen mirroring sender.

Sends H.264 to an Apple TV over AirPlay 2 and renders on-device; verified
live against AppleTV11,1 on tvOS 26. The FairPlay handshake underneath is
pure Python -- see :mod:`~pyatv.protocols.airplay.mirror.fairplay_sap`,
recovered from a vendor binary by devirtualisation, so no blob ships.

NOT WIRED INTO pyatv's PUBLIC API. Nothing under ``pyatv/`` imports this
package: there is no ``FeatureName`` for mirroring in :mod:`pyatv.const`, no
method on :mod:`pyatv.interface`, and no protocol registration. It is
reached only by driving these classes directly, which is what
``examples/airplay_mirror_e2e.py --full-session`` does.

Integrating it would mean at least: a public interface method and its
``FeatureName``, wiring in ``pyatv/protocols/airplay/__init__.py`` so the
relevant service reports the feature, a source of frames (the example shells
out to an encoder), and a decision about the two dialects below. That is a
design question, not a missing import.

One thing to settle at that point: the state-machine guards here raise bare
``RuntimeError`` -- "handshake not complete", "called in state X", "not
connected" -- fourteen of them, where the rest of pyatv raises
``exceptions.InvalidStateError`` for exactly that. Nothing catches either today, so
it costs nothing to leave; a public caller would want the pyatv type.

Which of the two, though, is not uniform in pyatv and the choice has a rule.
``RuntimeError`` is raised sixteen times outside this package, and every one
is an invariant a caller cannot provoke -- "no service (bug)", "missing
implementation for", "no response was saved for". ``InvalidStateError`` is
documented as "an action not possible in the current state" and is raised
for things a caller does: "already connected", "not connected". By that
split the fourteen here are the second kind and the fifteenth raise --
``_stream_until_done`` on an unset ``stream_encryptor`` -- is the first, and
should stay. ``auth/hap_channel`` raises ``InvalidStateError("not
connected")`` for the same condition ``streams.send`` raises
``RuntimeError`` for, which is the sharpest instance of the mismatch.

TWO DIALECTS, and the default is not the obvious one. ``MIRROR_TCP``
selects between them and defaults to on:

* TCP -- a simple type-110 video stream with a FairPlay-wrapped key in
  ``ekey``/``eiv`` over TCP. This is the one that renders on tvOS 26.
* AVConference -- the macOS sender's dialect: a session-init SETUP, Viceroy
  negotiation blobs, SRTP over UDP. Exercised by the tests, but it is not
  what a current Apple TV was observed to accept.

Much of :mod:`~pyatv.protocols.airplay.mirror.session` is switched by
``MIRROR_*`` environment variables left from working the protocol out. They
are research controls, not configuration; the defaults are the verified
path.
"""

from pyatv.protocols.airplay.mirror.context import MirrorContext
from pyatv.protocols.airplay.mirror.fply import FPLYHandshake, run_fply_handshake
from pyatv.protocols.airplay.mirror.session import MirrorSession

__all__ = [
    "MirrorContext",
    "MirrorSession",
    # FPLY v3 handshake — new path for current Apple TVs
    "FPLYHandshake",
    "run_fply_handshake",
]
