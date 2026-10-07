"""Tests for the Viceroy negotiationData builder.

All expected values come from a real macOS 15.7.4 mirroring session captured
through atvproxy in Phase 28 -- see
docs/superpowers/specs/2026-08-22-fply-phase28-ground-truth-capture.md.

The capability blob from that capture is kept beside this file as
``data/viceroy_media_blob.bin``. It is no longer shipped: it is the fixture
:func:`test_builder_reproduces_the_captured_payload` checks the builder
against, which is the whole reason the builder can be trusted.
"""

import datetime
from pathlib import Path
import plistlib
import zlib

import pytest

from pyatv.protocols.airplay.mirror import negotiation

# streams[0].negotiationData.avcMediaStreamOptionRemoteEndpointInfo, verbatim.
CAPTURED_ENDPOINT_INFO = b'\x08\x00\x10\x01\x1a\x07Mac15,6"\x082125.2.1*\x0624G517'

#: streams[0].negotiationData.avcMediaStreamNegotiatorMediaBlob, verbatim.
CAPTURED_MEDIA_BLOB = (
    Path(__file__).parent / "data" / "viceroy_media_blob.bin"
).read_bytes()


def _consume_message(payload: bytes) -> None:
    """Walk every field of a protobuf message, recursing into submessages.

    Raises if any length prefix overruns its parent, which is what makes this
    a real check that the builder recomputed the enclosing lengths.
    """
    offset = 0
    while offset < len(payload):
        key, offset = _read_varint(payload, offset)
        wire_type = key & 7
        if wire_type == 0:
            _, offset = _read_varint(payload, offset)
        elif wire_type == 2:
            length, offset = _read_varint(payload, offset)
            end = offset + length
            assert end <= len(payload), "length prefix overruns its parent"
            sub = payload[offset:end]
            offset = end
            try:
                decoded = sub.decode("ascii")
            except UnicodeDecodeError:
                _consume_message(sub)
            else:
                if not decoded.isprintable():
                    _consume_message(sub)
        else:  # pragma: no cover - the blob has no other wire types
            raise AssertionError(f"unexpected wire type {wire_type}")
    assert offset == len(payload)


def _read_varint(payload: bytes, offset: int):
    value = 0
    shift = 0
    while True:
        assert offset < len(payload), "varint runs off the end"
        byte = payload[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7


def test_builder_reproduces_the_captured_payload():
    """The bar for the builder: it must rebuild the capture exactly.

    The comparison is on the inflated bytes, because deflate output is a
    property of the compressor rather than of the protocol.
    """
    assert negotiation.build_media_blob() == zlib.decompress(CAPTURED_MEDIA_BLOB)


def test_deflated_blob_inflates_back_to_the_builder_output():
    """What goes on the wire must inflate to what the builder produced.

    Deliberately not an assertion that the compressed bytes equal the captured
    248: deflate output is a property of the compressor, not the protocol, and
    CPython builds that link zlib-ng emit a different (equally valid) stream.
    At the time of writing CPython's stock zlib at level 9 does reproduce the
    capture byte-for-byte, which is why level 9 was chosen -- but the receiver
    inflates the blob before looking at it, so nothing may depend on that.
    """
    assert zlib.decompress(negotiation.deflate_media_blob()) == (
        negotiation.build_media_blob()
    )


def test_endpoint_info_reproduces_captured_bytes():
    assert (
        negotiation.build_endpoint_info("Mac15,6", "2125.2.1", "24G517")
        == CAPTURED_ENDPOINT_INFO
    )


def test_media_blob_is_valid_deflate_stream():
    blob = negotiation.deflate_media_blob()
    assert blob[:2] == b"\x78\xda"  # zlib, max compression
    raw = zlib.decompress(blob)
    # The capability protobuf advertises the H.264 options and negotiator
    # version the receiver matches against.
    assert b"Viceroy" in raw
    assert b"CABAC" in raw


def test_negotiation_data_has_the_four_captured_keys():
    data = negotiation.build_negotiation_data("Mac15,6", "2125.2.1", "24G517")
    decoded = plistlib.loads(data)
    assert set(decoded) == {
        "avcMediaStreamOptionRemoteEndpointInfo",
        "avcMediaStreamNegotiatorMode",
        "avcMediaStreamNegotiatorMediaBlob",
        "avcMediaStreamOptionCallID",
    }
    assert decoded["avcMediaStreamNegotiatorMode"] == negotiation.NEGOTIATOR_MODE
    assert decoded["avcMediaStreamOptionRemoteEndpointInfo"] == CAPTURED_ENDPOINT_INFO


def test_call_id_is_uppercase_uuid_and_unique_per_call():
    first = plistlib.loads(
        negotiation.build_negotiation_data("Mac15,6", "2125.2.1", "24G517")
    )["avcMediaStreamOptionCallID"]
    second = plistlib.loads(
        negotiation.build_negotiation_data("Mac15,6", "2125.2.1", "24G517")
    )["avcMediaStreamOptionCallID"]
    assert first == first.upper()
    assert len(first) == 36
    assert first != second


def test_explicit_call_id_is_used():
    call_id = "12111938-399C-4535-BD60-BB949C112727"
    decoded = plistlib.loads(
        negotiation.build_negotiation_data(
            "Mac15,6", "2125.2.1", "24G517", call_id=call_id
        )
    )
    assert decoded["avcMediaStreamOptionCallID"] == call_id


def test_media_blob_geometry_can_be_rewritten():
    """The capture advertises the capture machine's display, not ours."""
    original = negotiation.build_media_blob()
    assert original.count(b"756/491") == 4

    patched = negotiation.build_media_blob((960, 540))
    assert patched.count(b"960/540") == 4
    assert b"756/491" not in patched


def test_geometry_of_a_different_width_is_rebuilt_not_skipped():
    """A geometry that is not 7 characters wide used to be silently dropped.

    The old code substituted the digits inside the already-compressed blob, so
    it could only handle a replacement exactly as long as ``756/491`` and left
    the blob describing the capture machine for anything else -- pyatv streamed
    1920x1080 while telling the receiver 756x491. Building the message instead
    recomputes every enclosing length, so any geometry works and the result is
    still a well-formed protobuf.
    """
    blob = negotiation.build_media_blob((1920, 1080))

    assert blob.count(b"1920/1080") == 4
    assert b"756/491" not in blob
    _consume_message(blob)


def test_varint_encodes_multi_byte_values():
    """Values above 0x7F need continuation bytes."""
    # 0x7F is the largest single-byte value; 0x80 is the first two-byte one.
    assert negotiation._protobuf_varint(1, 0x7F) == b"\x08\x7f"
    assert negotiation._protobuf_varint(1, 0x80) == b"\x08\x80\x01"
    assert negotiation._protobuf_varint(1, 300) == b"\x08\xac\x02"
    # Three bytes, to exercise more than one loop iteration.
    assert negotiation._protobuf_varint(2, 0x4000) == b"\x10\x80\x80\x01"


def test_field_keys_and_lengths_above_127_are_themselves_varints():
    """The blob needs both, and the encoder it replaced got both wrong.

    Field 16's key is 128, and the field 5 submessage is 254 bytes long. An
    encoder that writes either as a single byte produces a message that does
    not parse -- so these are the two cases the capture exercises and a
    one-byte encoder would silently corrupt.
    """
    assert negotiation._protobuf_varint(16, 0) == b"\x80\x01\x00"
    assert negotiation._protobuf_bytes(5, b"x" * 254)[:3] == b"\x2a\xfe\x01"


def test_media_blob_unchanged_when_source_size_matches_the_capture():
    """Passing the captured geometry explicitly must change nothing."""
    blob = negotiation.deflate_media_blob()

    assert negotiation.deflate_media_blob(negotiation.CAPTURED_SOURCE) == blob
    assert negotiation.deflate_media_blob((960, 540)) != blob


def test_captured_ntp_time_decodes_to_the_moment_of_the_capture():
    """Field 13 is an NTP timestamp, and this is what proves the field map.

    ``ntpTime`` is NTP 64-bit 32.32 fixed point: seconds since 1900 in the high
    word. Decoding the captured constant lands on 2026-08-22 05:14:14Z, which
    is 09:14 in the +04:00 zone the proxy log ``proxy-20260822-091057.log`` was
    recorded in -- inside the session it came from. A wrong field numbering
    could not produce a valid timestamp at exactly the right minute.
    """
    seconds = negotiation.CAPTURED_NTP_TIME >> 32
    unix = seconds - 2208988800  # NTP epoch 1900 -> Unix epoch 1970

    assert (
        datetime.datetime.fromtimestamp(unix, datetime.timezone.utc).isoformat()
        == "2026-08-22T05:14:14+00:00"
    )


@pytest.mark.parametrize(
    "size",
    [
        (1, 1),
        (999, 999),
        (1000, 1000),
        (640, 480),
        (1280, 720),
        (1920, 1080),
        (3840, 2160),
        (65535, 65535),
    ],
)
def test_any_geometry_builds_a_well_formed_message(size):
    """Every enclosing length is recomputed, at every digit width.

    `test_geometry_of_a_different_width_is_rebuilt_not_skipped` pins one
    size.  The interesting cases are the boundaries: the geometry is
    written as decimal text, so its width changes at 9->10, 99->100 and
    999->1000, and each change moves the length of three enclosing
    submessages.  1000x1000 pushes one of them past 127, where the length
    stops fitting in a single byte -- the exact case the pre-`e56a640f`
    encoder got wrong, since it wrote keys and lengths as one byte each.

    The blob cannot be checked against a receiver from here, so this
    checks the property that is checkable: whatever comes out still parses
    as protobuf, end to end, with no trailing or truncated field.
    """
    blob = negotiation.build_media_blob(size)
    _consume_message(blob)
    assert f"{size[0]}/{size[1]}".encode().count(b"/") == 1
    assert blob.count(f"{size[0]}/{size[1]}".encode()) == 4


def test_a_geometry_wide_enough_to_grow_a_length_prefix_still_parses():
    """999->1000 grows the message; the varint lengths must grow with it."""
    small = negotiation.build_media_blob((999, 999))
    large = negotiation.build_media_blob((1000, 1000))

    assert len(large) > len(small), (len(small), len(large))
    _consume_message(small)
    _consume_message(large)
