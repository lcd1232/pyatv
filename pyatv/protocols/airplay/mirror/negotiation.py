"""Build the ``negotiationData`` blob for a mirror stream SETUP.

Modern Apple TVs (tvOS 17+; verified against tvOS 26.6 / AirTunes 960.13.1)
negotiate the mirroring video stream through Apple's "Viceroy" AVC media
stream negotiator rather than through the AirPlay-1 ANNOUNCE/SDP exchange.
The stream ``SETUP`` therefore carries a ``negotiationData`` value: a nested
binary plist holding

``avcMediaStreamNegotiatorMode``
    Integer mode selector. Real senders use ``2``.
``avcMediaStreamOptionCallID``
    Uppercase UUID identifying this negotiation.
``avcMediaStreamOptionRemoteEndpointInfo``
    A small protobuf describing the sender hardware.
``avcMediaStreamNegotiatorMediaBlob``
    A zlib-deflated protobuf describing the encoder's H.264 capabilities.

The capability blob used to be replayed verbatim from a file. It is not
opaque: it is ``VCMediaNegotiationBlob``, an Apple-protobuf message shared with
FaceTime, so :func:`build_media_blob` constructs it field by field and the
captured bytes survive only as a test fixture
(``tests/protocols/airplay/mirror/data/viceroy_media_blob.bin``), which the
builder is checked against byte-for-byte.

Where the names come from
-------------------------

Not from guesswork. ``AVConference`` carries the generated Objective-C classes
for this message, and two artefacts pin every field number to a name:

* ``nm -a AVConference`` lists the ivars, e.g.
  ``_OBJC_IVAR_$_VCMediaNegotiationBlob._ntpTime`` at ``0x1ecd740f0``;
* ``-[VCMediaNegotiationBlob writeTo:]`` loads each ivar offset and passes the
  field number in ``w2``, which fixes the mapping ``slot = 0xbc + 4 * field``
  (checked against ``mov w2, #4``/``#5``/``#0xb`` at slots ``0xcc``/``0xd0``/
  ``0xe8``).

The mapping then predicts the capture: field 13 is ``ntpTime``, and the two
captured sender blobs decode as NTP 32.32 to 2026-08-22 05:14:14Z and
09:01:30Z -- 09:14 and 13:01 local, landing inside the two proxy captures they
came from. A wrong field numbering could not do that.

Eleven blobs from those captures (two sender, nine from the Apple TV) say
which values are constant, which vary per session, and which carry no
ordering. Fields whose *meaning* is still unknown -- the bitmask contents, the
enum values -- keep Apple's name and the observed value, and say so.
"""

from __future__ import annotations

import plistlib
from typing import NamedTuple, Optional, Sequence, Tuple
from uuid import uuid4
import zlib

#: Mode value observed in every captured sender negotiation.
NEGOTIATOR_MODE = 2


def _varint(value: int) -> bytes:
    """Encode ``value`` as a protobuf base-128 varint."""
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _protobuf_varint(field: int, value: int) -> bytes:
    """Encode ``value`` as a varint (wire type 0) field."""
    return _varint(field << 3) + _varint(value)


def _protobuf_bytes(field: int, payload: bytes) -> bytes:
    """Encode ``payload`` as a length-delimited (wire type 2) field."""
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def _protobuf_string(field: int, value: str) -> bytes:
    """Encode ``value`` as a length-delimited UTF-8 field."""
    return _protobuf_bytes(field, value.encode("utf-8"))


def build_endpoint_info(model: str, source_version: str, os_build: str) -> bytes:
    """Encode ``avcMediaStreamOptionRemoteEndpointInfo``.

    Captured from macOS as ``field1=0, field2=1, model, "2125.2.1", build``;
    the Apple TV replies with the same shape describing itself.
    """
    return b"".join(
        [
            _protobuf_varint(1, 0),
            _protobuf_varint(2, 1),
            _protobuf_string(3, model),
            _protobuf_string(4, source_version),
            _protobuf_string(5, os_build),
        ]
    )


#: Source geometry baked into the captured blob's ``AR:``/``XR:`` options.
#: 756x491 is the capture machine's Retina panel (1512x982) halved.
CAPTURED_SOURCE = (756, 491)

#: ``VCMediaNegotiationBlob.userAgent`` (field 6). The only ``Viceroy 1.7.0``
#: literal in AVConference; all nine captured Apple TV replies answer with
#: ``Viceroy 1.7.0/GK``.
USER_AGENT = "Viceroy 1.7.0"

#: ``VCMediaNegotiationBlobVideoSettings.rtpSSRC`` (field 5.1) -- the RTP
#: synchronisation source for the video stream. Distinct in all eleven captured
#: blobs, as an SSRC should be.
#:
#: pyatv replays the captured one, which the receiver accepts. Strictly an SSRC
#: ought to be drawn fresh per stream (RFC 3550), and ``ntpTime`` below exists
#: precisely so the receiver can break SSRC collisions
#: (``-[VCSession detectSSRCCollisionWithRemoteMediaStream:
#: remoteBlobCreationTime:resetNeeded:]``) -- so two pyatv senders talking to
#: one Apple TV would collide. Left as-is deliberately: this module was a
#: legibility change, and altering what goes on the wire needs a live test.
#:
#: SCOPE.  ``build_negotiation_data`` is called only from the AVConference
#: branch of ``session.py`` -- the ``else`` of ``if _airparrot_mode()``, which
#: defaults to True.  So neither this SSRC nor ``ntpTime`` below reaches the
#: wire on the dialect that renders on tvOS 26; the collision above needs two
#: senders BOTH in AVConference mode.  That is why these are documented rather
#: than fixed: the fix is untestable from here and unreachable by default.
CAPTURED_RTP_SSRC = 1229047899

#: ``VCMediaNegotiationBlob.ntpTime`` (field 13), an NTP 64-bit 32.32 fixed
#: point timestamp -- seconds since 1900 in the high word, binary fraction in
#: the low. The captured value is 2026-08-22 05:14:14Z, the moment the capture
#: was taken. A live sender writes the current time; replaying the captured one
#: is accepted, and is kept for the same reason as ``rtpSSRC`` above.
CAPTURED_NTP_TIME = 0xEE33AEA649A1D000

#: ``VCMediaNegotiationBlob`` scalars, identical in every captured blob.
#: ``blobVersion`` selects this (V1) blob format;
#: ``mediaControlInfoVersion`` is a uint8 and ``basebandCodecSampleRate`` a
#: uint32, both left at zero by a screen sender.
ALLOW_DYNAMIC_MAX_BITRATE = 1
ALLOWS_CONTENTS_CHANGE_WITH_ASPECT_PRESERVATION = 1
BASEBAND_CODEC_SAMPLE_RATE = 0
BLOB_VERSION = 2
MEDIA_CONTROL_INFO_VERSION = 0

#: ``VCMediaNegotiationBlobVideoSettings`` scalars. Note the sender fills in
#: field 5, ``screenSettings``, and leaves field 4, ``videoSettings``, empty --
#: they are the same message type and screen capture uses the former.
#:
#: ``pixelFormats`` is a bitmask (63 here, 39 in the Apple TV's reply); which
#: bit is which pixel format was not extracted, so only the value is claimed.
#: ``ltrpEnabled`` agrees with the ``LTR`` token in the feature string below.
ALLOW_RTCP_FB = 0
TILES_PER_FRAME = 4
LTRP_ENABLED = 1
PIXEL_FORMATS = 63
BLACK_FRAME_ON_CLEAR_SCREEN_ENABLED = 1

#: ``VCMediaNegotiationBlobVideoRuleCollection`` fields other than
#: ``operation``. ``transport`` and ``formats`` are an enum and a bitmask whose
#: value meanings were not extracted; ``formats`` is 0xC3C3 from the sender and
#: 128 from the Apple TV, so it describes the endpoint, not the protocol.
RULE_TRANSPORT = 1
RULE_FORMATS = 0xC3C3
RULE_PREFERRED_FORMAT = 0


class _VideoPayloadSettings(NamedTuple):
    """One ``VCMediaNegotiationBlobVideoPayloadSettings`` (field 5.3).

    Two are sent. ``payload`` (the RTP payload type) and ``parameter_set`` are
    perfectly correlated across all eleven captured blobs -- 123 always travels
    with 1 and the ``CABAC``/``LTR`` feature string, 100 always with 14 and the
    ``POSE:4`` one -- including in the Apple TV's reply, which sends the two in
    the opposite order.
    """

    #: Field 5.3.1, ``payload``: the RTP payload type this entry describes.
    payload: int
    #: Field 5.3.2, repeated ``videoRuleCollections``. Every field of those
    #: records is constant except ``operation``, so only that is listed here.
    #: It takes 1 and 2, and the sender repeats the pair twice for payload 123
    #: and once for 100 (the Apple TV sends it once for both), so it is not an
    #: index. Which operation 1 and 2 name was not extracted.
    operations: Sequence[int]
    #: Field 5.3.3, ``featureString`` -- the "FLS" (Feature List String) that
    #: ``VCVideoFeatureListStringHelper`` builds and parses. A ``;``-separated
    #: set of ``KEY`` and ``KEY:value`` tokens; the Apple TV echoes the same
    #: set reordered and without the trailing ``;``, so order is insignificant.
    #:
    #: ``AR``/``XR`` are formatted by
    #: ``+[VCVideoFeatureListStringHelper deriveAspectRatioFLSWith...]`` through
    #: ``"%s:%d/%d,%d/%d;%s:%d/%d,%d/%d;"`` as
    #: ``landscapeX/landscapeY,portraitX/portraitY`` -- ``AR`` the sender's own
    #: aspect ratios, ``XR`` the ones it expects to receive. So ``{0}/{1}`` is
    #: the landscape pair, which is the geometry being streamed, and the
    #: trailing ``5/8`` is the portrait ratio, left as captured.
    #:
    #: ``LTR`` and ``CABAC`` are built as literal immediates in
    #: ``-[VCCallSession(PrivateMethods) setMatchedFeaturesString:...]``. The
    #: remaining keys -- ``MS``, ``LF``, ``POS``, ``POSE``, ``EOD``, ``HTS``,
    #: ``RR`` -- appear only in VideoProcessing.framework's
    #: ``VCPRealtimeEncoder`` bundle, with no expansion text anywhere, so what
    #: they mean is still unknown and they are reproduced verbatim.
    feature_string: str
    #: Field 5.3.4, ``parameterSet``.
    parameter_set: int


_PAYLOAD_SETTINGS = (
    _VideoPayloadSettings(
        payload=123,
        operations=(1, 2, 1, 2),
        feature_string=(
            "FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;"
            "AR:{0}/{1},5/8;XR:{0}/{1},5/8;"
        ),
        parameter_set=1,
    ),
    _VideoPayloadSettings(
        payload=100,
        operations=(1, 2),
        feature_string=(
            "FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;" "AR:{0}/{1},5/8;XR:{0}/{1},5/8;"
        ),
        parameter_set=14,
    ),
)

#: ``VCMediaNegotiationBlob.bandwidthSettings`` (field 9), as
#: ``(configuration, maxBandwidth, configurationExtension)`` -- the third is
#: omitted where the capture omits it.
#:
#: ``configuration`` and ``configurationExtension`` are bitmasks over connection
#: type and arbiter mode, built by
#: ``+[VCMediaNegotiationBlobBandwidthSettings(BandwidthSettings)
#: bandwidthConfigurationFor<X>WithArbiterMode:]``; 16384 and 262144 appear
#: there as inline immediates for 5G and Wired, the rest come from lookup
#: tables. Which bit is which is not reproduced here.
#:
#: ``maxBandwidth`` ranges from 299 to 60,000,000 across these eight records,
#: so more than one unit is clearly in play; which is which is not established,
#: and nothing here depends on it.
#:
#: The two captured sender blobs carry exactly these eight records in a
#: different order, so the order is arbitrary -- the sender iterates something
#: unordered. The capture's order is reproduced so the builder is byte-exact.
_BANDWIDTH_SETTINGS: Tuple[Tuple[int, ...], ...] = (
    (4074, 0, 16384),
    (0, 20000000, 98304),
    (0, 40000000, 12288),
    (16, 4100),
    (0, 6000000, 131072),
    (4, 6500),
    (0, 60000000, 262144),
    (1, 299),
)


def _build_payload_settings(
    settings: _VideoPayloadSettings, width: int, height: int
) -> bytes:
    """Encode one ``VCMediaNegotiationBlobVideoPayloadSettings`` (field 5.3)."""
    rules = [
        _protobuf_bytes(
            2,
            b"".join(
                [
                    _protobuf_varint(1, RULE_TRANSPORT),
                    _protobuf_varint(2, operation),
                    _protobuf_varint(3, RULE_FORMATS),
                    _protobuf_varint(4, RULE_PREFERRED_FORMAT),
                ]
            ),
        )
        for operation in settings.operations
    ]
    return b"".join(
        [
            _protobuf_varint(1, settings.payload),
            *rules,
            _protobuf_string(3, settings.feature_string.format(width, height)),
            _protobuf_varint(4, settings.parameter_set),
        ]
    )


def _build_screen_settings(width: int, height: int) -> bytes:
    """Encode the ``screenSettings`` submessage (field 5)."""
    return b"".join(
        [
            _protobuf_varint(1, CAPTURED_RTP_SSRC),
            _protobuf_varint(2, ALLOW_RTCP_FB),
            *[
                _protobuf_bytes(3, _build_payload_settings(settings, width, height))
                for settings in _PAYLOAD_SETTINGS
            ],
            _protobuf_varint(6, TILES_PER_FRAME),
            _protobuf_varint(7, LTRP_ENABLED),
            _protobuf_varint(8, PIXEL_FORMATS),
            _protobuf_varint(12, BLACK_FRAME_ON_CLEAR_SCREEN_ENABLED),
        ]
    )


def build_media_blob(source_size: Optional[Tuple[int, int]] = None) -> bytes:
    """Build the ``VCMediaNegotiationBlob`` protobuf, uncompressed.

    ``source_size`` sets the geometry advertised as the ``AR:``/``XR:``
    landscape aspect ratio; it defaults to :data:`CAPTURED_SOURCE`. Because the
    message is assembled rather than patched, every enclosing length is
    recomputed, so any geometry works -- the old byte-substitution could only
    handle a replacement the same width as ``756/491`` and silently left the
    blob describing the capture machine otherwise.
    """
    width, height = source_size or CAPTURED_SOURCE
    return b"".join(
        [
            _protobuf_varint(1, ALLOW_DYNAMIC_MAX_BITRATE),
            _protobuf_varint(2, ALLOWS_CONTENTS_CHANGE_WITH_ASPECT_PRESERVATION),
            _protobuf_bytes(5, _build_screen_settings(width, height)),
            _protobuf_string(6, USER_AGENT),
            _protobuf_varint(8, BASEBAND_CODEC_SAMPLE_RATE),
            *[
                _protobuf_bytes(
                    9,
                    b"".join(
                        _protobuf_varint(index, value)
                        for index, value in enumerate(record, start=1)
                    ),
                )
                for record in _BANDWIDTH_SETTINGS
            ],
            _protobuf_varint(13, CAPTURED_NTP_TIME),
            _protobuf_varint(14, BLOB_VERSION),
            _protobuf_varint(16, MEDIA_CONTROL_INFO_VERSION),
        ]
    )


def deflate_media_blob(source_size: Optional[Tuple[int, int]] = None) -> bytes:
    """Return the zlib-deflated capability protobuf, as it goes on the wire.

    Level 9 is not a guess: it is the level at which CPython's stock zlib
    reproduces the captured 248-byte stream exactly. That is a reason to pick 9
    rather than a guarantee -- a build linking zlib-ng emits a different but
    equally valid stream, and the receiver inflates the blob before reading it.
    """
    return zlib.compress(build_media_blob(source_size), 9)


def build_negotiation_data(
    model: str,
    source_version: str,
    os_build: str,
    call_id: Optional[str] = None,
    source_size: Optional[Tuple[int, int]] = None,
) -> bytes:
    """Serialize the ``negotiationData`` binary plist for a stream SETUP."""
    return plistlib.dumps(
        {
            "avcMediaStreamOptionRemoteEndpointInfo": build_endpoint_info(
                model, source_version, os_build
            ),
            "avcMediaStreamNegotiatorMode": NEGOTIATOR_MODE,
            "avcMediaStreamNegotiatorMediaBlob": deflate_media_blob(source_size),
            "avcMediaStreamOptionCallID": call_id or str(uuid4()).upper(),
        },
        # plistlib injects FMT_BINARY from an enum, so astroid misses it.
        fmt=plistlib.FMT_BINARY,  # pylint: disable=no-member
    )
