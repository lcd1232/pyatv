"""Apple's FPLY v3 sender handshake, in pure Python.

The FairPlay SAP handshake an AirPlay mirror sender runs against an Apple
TV -- ``M1 -> M2 -> M3 -> M4 -> ekey`` on ``/fp-setup`` -- is four
algorithms:

* :func:`.region_a.sap_secret` -- ``M2`` in, the 36-byte SAP secret out;
  two SAPHash calls over one 290-byte message.
* :func:`.region_b.device_tag` -- the 20 bytes at ``M3[144:164]`` that
  the receiver checks and echoes back in M4.
* :func:`.m4_derive.context` -- the 276-byte FairPlay context after M4,
  AES-128-CBC over a template with the secret spliced in.
* :func:`.ekey_wrap.ekey` -- the 72-byte ekey that carries a chosen
  16-byte media secret to the receiver: an HMAC-SHA-1 tag and an
  AES-128 wrap.

``M3[0:144]`` is not computed: the sender's session randomness is fixed
at zero, so the 128-byte cipher block and the header in front of it are
the same bytes in every session.  See :data:`M3_CIPHER_BLOCK` in
:mod:`pyatv.protocols.airplay.mirror.fply`, where M3 is assembled.
"""

from pyatv.protocols.airplay.mirror.fairplay_sap import m4_derive
from pyatv.protocols.airplay.mirror.fairplay_sap.ekey_wrap import ekey
from pyatv.protocols.airplay.mirror.fairplay_sap.m4_derive import context
from pyatv.protocols.airplay.mirror.fairplay_sap.region_a import sap_secret
from pyatv.protocols.airplay.mirror.fairplay_sap.region_b import device_tag

__all__ = [
    "sap_secret",
    "device_tag",
    "context",
    "context_after_m3",
    "ekey",
    "handshake",
]

# context[1] is a state counter: 4 once M3 has been built, 5 once the M4
# call has run.  :data:`.m4_derive.TEMPLATE` is the context as the M4
# derive engine opens, so it carries the 5.
_STATE_AFTER_M3 = 0x04


def context_after_m3(sap36: bytes) -> bytes:
    """Return the 276-byte FairPlay context as it stands after M3, in the clear.

    :func:`.m4_derive.context` is the same context after M4, which is where
    it gets encrypted; this is the plaintext one, and the only thing in it
    that varies per session is the SAP secret at ``[8:44]``.
    """
    if len(sap36) != m4_derive.SECRET_LENGTH:
        raise ValueError(f"sap36 must be {m4_derive.SECRET_LENGTH} bytes")
    plain = bytearray(m4_derive.TEMPLATE)
    plain[1] = _STATE_AFTER_M3
    plain[m4_derive.SECRET_AT : m4_derive.SECRET_AT + len(sap36)] = sap36
    return bytes(plain)


def handshake(m2: bytes, raw16: bytes):
    """Return ``(sap36, device_tag, context, ekey)`` for one session.

    *m2* is the receiver's 142-byte FPLY M2 and *raw16* the 16-byte media
    secret to wrap.  Everything else in the handshake follows from those
    two: the SAP secret is a function of M2 alone, and the tag, context
    and ekey are functions of the secret (and, for the ekey, of *raw16*).
    M4 does not enter -- it only echoes the tag back for verification.
    """
    sap36 = sap_secret(m2)
    return sap36, device_tag(sap36), context(sap36), ekey(sap36, raw16)
