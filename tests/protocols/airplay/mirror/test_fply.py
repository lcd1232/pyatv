"""Tests for the FPLY v3 wire format and handshake state machine.

Known-answer tests for the message contents (device tag, ekey) are in
``test_fairplay_sap.py``.
"""

from __future__ import annotations

import logging
import struct

import pytest

from pyatv.protocols.airplay.mirror import fairplay_sap, fply

# ---------------------------------------------------------------------------
# M1
# ---------------------------------------------------------------------------


def test_build_m1_matches_spec_test_vector():
    """build_m1(mode=0) matches a known M1 byte-for-byte."""
    expected = bytes.fromhex("46504c5903010100000000040200" + "00bb")
    assert fply.build_m1(0) == expected


def test_build_m1_length():
    """M1 must be exactly 16 bytes for any mode."""
    for mode in range(4):
        assert len(fply.build_m1(mode)) == 16


def test_build_m1_magic():
    """M1 bytes 0–3 must be b'FPLY'."""
    assert fply.build_m1(0)[:4] == b"FPLY"


def test_build_m1_mode_in_byte14():
    """M1[14] must carry the mode selector (0–3)."""
    for mode in range(4):
        m1 = fply.build_m1(mode)
        assert m1[14] == mode


def test_build_m1_mode_masked_to_2_bits():
    """Mode values > 3 must be masked to 2 bits."""
    m1 = fply.build_m1(0xFF)
    assert m1[14] == 0x03


def test_build_m1_terminal_byte():
    """M1[15] must always be 0xBB."""
    for mode in range(4):
        assert fply.build_m1(mode)[15] == 0xBB


# ---------------------------------------------------------------------------
# M2 parsing
# ---------------------------------------------------------------------------


def _valid_m2(mode: int = 1) -> bytes:
    """Build a minimal syntactically valid 142-byte M2.

    Mode 1 is the default because it is what real receivers send.
    """
    m2 = bytearray(142)
    m2[0:4] = b"FPLY"
    m2[4] = 0x03  # version
    m2[5] = 0x01
    m2[6] = 0x02  # message type M2
    m2[7] = 0x00
    struct.pack_into(">I", m2, 8, 0x7E)  # length field
    m2[12] = 0x00
    m2[13] = mode & 0x03
    return bytes(m2)


def test_parse_m2_validates_magic():
    """parse_m2 must raise ValueError for wrong magic bytes."""
    bad = bytearray(_valid_m2())
    bad[0:4] = b"XXXX"
    with pytest.raises(ValueError, match="magic"):
        fply.parse_m2(bytes(bad))


def test_parse_m2_validates_length():
    """parse_m2 must raise ValueError for truncated M2.

    141 bytes is the boundary case: the payload is ``m2[14:142]`` and a short
    slice would otherwise give a 127-byte payload instead of an error.
    """
    with pytest.raises(ValueError, match="truncated"):
        fply.parse_m2(_valid_m2()[:100])

    with pytest.raises(ValueError, match="truncated"):
        fply.parse_m2(_valid_m2()[:141])

    assert len(fply.parse_m2(_valid_m2()).payload) == 128


def test_parse_m2_too_short_header():
    """parse_m2 must raise ValueError when fewer than 16 bytes supplied."""
    with pytest.raises(ValueError, match="too short"):
        fply.parse_m2(b"FPLY\x03")


def test_parse_m2_extracts_mode():
    """parse_m2 must extract the mode byte from M2[13]."""
    for mode in range(4):
        parsed = fply.parse_m2(_valid_m2(mode))
        assert parsed.mode == mode


def test_parse_m2_payload_length():
    """M2Parsed.payload must be exactly 128 bytes (8 cipher blocks)."""
    parsed = fply.parse_m2(_valid_m2())
    assert len(parsed.payload) == 128


def test_parse_m2_returns_raw():
    """M2Parsed.raw must be the original bytes."""
    m2 = _valid_m2()
    parsed = fply.parse_m2(m2)
    assert parsed.raw == m2


# ---------------------------------------------------------------------------
# build_m3
# ---------------------------------------------------------------------------


def test_build_m3_length():
    """M3 must be exactly 164 bytes."""
    payload = bytes(128)
    assert len(fply.build_m3(0, payload)) == 164


def test_build_m3_magic():
    """M3 bytes 0–3 must be b'FPLY'."""
    assert fply.build_m3(0, bytes(128))[:4] == b"FPLY"


def test_build_m3_message_type():
    """M3[6] must be 0x03 (message type 'client response')."""
    assert fply.build_m3(0, bytes(128))[6] == 0x03


def test_build_m3_mode_byte():
    """M3[12] must carry the mode byte."""
    for mode in range(4):
        m3 = fply.build_m3(mode, bytes(128))
        assert m3[12] == mode


def test_build_m3_aux_header_default_and_custom():
    """M3[13:16] holds 3 aux header bytes (default 8f 1a 9c, overridable)."""
    m3 = fply.build_m3(0, bytes(128))
    assert m3[13:16] == b"\x8f\x1a\x9c"  # value seen on the wire
    m3 = fply.build_m3(0, bytes(128), aux_header=b"\x00\x00\x00")
    assert m3[13:16] == b"\x00\x00\x00"


def test_build_m3_payload_placed():
    """The 128-byte cipher payload must be placed at M3[16:144]."""
    payload = bytes(range(128))
    m3 = fply.build_m3(0, payload)
    assert m3[16:144] == payload


def test_build_m3_device_tag_default_zero():
    """Default device_tag must be 20 zero bytes at M3[144:164]."""
    m3 = fply.build_m3(0, bytes(128))
    assert m3[144:164] == b"\x00" * 20


def test_build_m3_custom_device_tag():
    """Custom device_tag must appear at M3[144:164]."""
    tag = bytes(range(20))
    m3 = fply.build_m3(0, bytes(128), device_tag=tag)
    assert m3[144:164] == tag


def test_build_m3_rejects_wrong_payload_length():
    """build_m3 must raise ValueError if cipher_payload is not 128 bytes."""
    with pytest.raises(ValueError):
        fply.build_m3(0, bytes(64))


def test_build_m3_rejects_wrong_device_tag_length():
    """build_m3 must raise ValueError if device_tag is not 20 bytes."""
    with pytest.raises(ValueError):
        fply.build_m3(0, bytes(128), device_tag=bytes(10))


# ---------------------------------------------------------------------------
# derive_stream_key
# ---------------------------------------------------------------------------


def test_derive_stream_key_length():
    """derive_stream_key must return exactly 16 bytes."""
    key = fply.derive_stream_key(bytes(16), bytes(128), b"AirPlayStreamKey", 0)
    assert len(key) == 16


def test_derive_stream_key_deterministic():
    """Same inputs must produce the same key."""
    args = (bytes(16), bytes(128), b"AirPlayStreamKey", 0)
    assert fply.derive_stream_key(*args) == fply.derive_stream_key(*args)


def test_derive_stream_key_differs_for_key_vs_iv():
    """Key and IV derivations must produce different bytes."""
    round0 = bytes(16)
    m3p = bytes(128)
    key = fply.derive_stream_key(round0, m3p, b"AirPlayStreamKey", 0)
    iv = fply.derive_stream_key(round0, m3p, b"AirPlayStreamIV ", 0)
    assert key != iv


def test_derive_stream_key_differs_for_different_stream_id():
    """Different stream IDs must produce different keys."""
    round0 = bytes(16)
    m3p = bytes(128)
    label = b"AirPlayStreamKey"
    k0 = fply.derive_stream_key(round0, m3p, label, 0)
    k1 = fply.derive_stream_key(round0, m3p, label, 1)
    assert k0 != k1


def test_derive_stream_key_rejects_wrong_lengths():
    """derive_stream_key must raise ValueError for wrong-length arguments."""
    with pytest.raises(ValueError, match="round0_block"):
        fply.derive_stream_key(bytes(8), bytes(128), b"AirPlayStreamKey", 0)
    with pytest.raises(ValueError, match="m3_payload"):
        fply.derive_stream_key(bytes(16), bytes(64), b"AirPlayStreamKey", 0)
    with pytest.raises(ValueError, match="label"):
        fply.derive_stream_key(bytes(16), bytes(128), b"short", 0)


# ---------------------------------------------------------------------------
# FPLYHandshake state machine
# ---------------------------------------------------------------------------


def test_handshake_build_m1_returns_16_bytes():
    h = fply.FPLYHandshake()
    m1 = h.build_m1()
    assert len(m1) == 16
    # FPLYHandshake defaults to mode 1, as real senders use.
    assert m1 == fply.build_m1(1)


def test_handshake_build_m1_twice_raises():
    h = fply.FPLYHandshake()
    h.build_m1()
    with pytest.raises(RuntimeError):
        h.build_m1()


def test_handshake_consume_m2_before_m1_raises():
    h = fply.FPLYHandshake()
    with pytest.raises(RuntimeError):
        h.consume_m2_build_m3(_valid_m2())


def test_handshake_properties_before_complete_raise():
    h = fply.FPLYHandshake()
    with pytest.raises(RuntimeError):
        _ = h.stream_aes_key
    with pytest.raises(RuntimeError):
        _ = h.stream_aes_iv


def test_handshake_full_flow_returns_164_byte_m3():
    """Full state machine must produce a 164-byte M3 without error."""
    h = fply.FPLYHandshake(mode_byte=0)
    h.build_m1()
    m3 = h.consume_m2_build_m3(_valid_m2(0))
    assert len(m3) == 164
    assert m3[:4] == b"FPLY"


def test_handshake_stream_keys_available_after_m3():
    """stream_aes_key and stream_aes_iv must be 16 bytes each after M3."""
    h = fply.FPLYHandshake()
    h.build_m1()
    h.consume_m2_build_m3(_valid_m2())
    assert len(h.stream_aes_key) == 16
    assert len(h.stream_aes_iv) == 16
    assert h.stream_aes_key != h.stream_aes_iv


def test_handshake_m3_payload_available_after_m3():
    """m3_payload must be 128 bytes after the handshake completes."""
    h = fply.FPLYHandshake()
    h.build_m1()
    h.consume_m2_build_m3(_valid_m2())
    assert len(h.m3_payload) == 128


# ---------------------------------------------------------------------------
# run_fply_handshake async integration
# ---------------------------------------------------------------------------


class _FakeHttpResponse:
    def __init__(self, code: int, body: bytes) -> None:
        self.code = code
        self.body = body
        self.headers = {}


class _FakeConnection:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent: list = []
        #: Headers of each request, in order.
        self.headers: list = []

    async def send_and_receive(self, method, uri, **kwargs):
        self.sent.append((method, uri, kwargs.get("body"), kwargs.get("content_type")))
        self.headers.append(dict(kwargs.get("headers") or {}))
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_run_fply_handshake_posts_m1_and_m3_to_fp_setup():
    """run_fply_handshake must POST M1 then M3 to /fp-setup."""
    conn = _FakeConnection(
        [
            _FakeHttpResponse(200, _valid_m2()),
            _FakeHttpResponse(200, b""),
        ]
    )
    sm = await fply.run_fply_handshake(conn)

    assert len(conn.sent) == 2

    method1, uri1, body1, ct1 = conn.sent[0]
    assert method1 == "POST"
    assert uri1 == "/fp-setup"
    assert ct1 == "application/octet-stream"
    assert len(body1) == 16  # M1

    method2, uri2, body2, ct2 = conn.sent[1]
    assert method2 == "POST"
    assert uri2 == "/fp-setup"
    assert len(body2) == 164  # M3

    assert body2[16:144] == fply.M3_CIPHER_BLOCK
    assert body2[144:164] != bytes(20)  # a real device tag
    assert len(sm.stream_aes_key) == 16
    assert len(sm.stream_aes_iv) == 16


@pytest.mark.asyncio
async def test_run_fply_handshake_raises_on_m1_non_200():
    """run_fply_handshake must raise ProtocolError if /fp-setup M1 → non-200."""
    from pyatv import exceptions

    conn = _FakeConnection([_FakeHttpResponse(500, b"")])
    with pytest.raises(exceptions.ProtocolError):
        await fply.run_fply_handshake(conn)


@pytest.mark.asyncio
async def test_run_fply_handshake_raises_on_m3_non_200():
    """run_fply_handshake must raise ProtocolError if /fp-setup M3 → non-200."""
    from pyatv import exceptions

    conn = _FakeConnection(
        [
            _FakeHttpResponse(200, _valid_m2()),
            _FakeHttpResponse(403, b""),
        ]
    )
    with pytest.raises(exceptions.ProtocolError):
        await fply.run_fply_handshake(conn)


# ---------------------------------------------------------------------------
# m2_stepper compression functions
# ---------------------------------------------------------------------------


# Known-answer triples (iv_hex, message_hex_64bytes, expected_output_hex)
# recorded from a real sender.
_M2_STEPPER_TRIPLES = (
    (
        "dcdcf3b90b74dcfb867ff76016729051",
        "4dad9cfa8c26684b9988f37f952e92de7301001eb2d350e2"
        "b00ea882c9a3b80e844e17eb38e48c534ec75453e8487157"
        "4a1cac6ab508fc4aecf8802b5bd71df5",
        "c859d3fbfc99a9c6f3ec98f0119bf37a",
    ),
    (
        "00bda4dd62c5d6b182ac8428e35d9547",
        "2e71e0ecf259a37b1ce87735fc2c117a6d250a28b566bf0d"
        "4a46ae5c144f277d168a9d92966783955d755e95ce7d789a"
        "85810619160ae714ca8ea65ea8f75920",
        "4a2a69a60c9fe913d656806e80df402d",
    ),
    (
        "d343b77da6b3bc7df4e27f5a9a64483d",
        "a829875203e5d20907077a550e97fbee67010068889c3f75"
        "b2d249ea3d3bb78e9b38b4a5147e281719bbfe64010dff35"
        "db159461f2f910bcb9d0cb029bc2b279",
        "095daa047bea6b4b1f36f73be49c4cc5",
    ),
    (
        "1e5ca69c9f9cb732349ceefecf856f63",
        "2244b3a4112558fef55c472d4dca4ae7c8b32048ccd7286e"
        "2712a1bc9ae4e3612af20dc1dfc47a5feaae44e0810849ce"
        "0bc0e61e0d48e4f540c7befe4901c621",
        "a56309c678730c23c15a54afd4f23d8c",
    ),
    (
        "955213e292ca63c0a90f235579c27ef3",
        "7ff733be5aa6d0705edad0693c13eb1a274eec5de8f2fd5e70ae97303f00e0fb0080391c00000000000000000000000000000000000000000000091000000000",
        "f733b7a75c077088c83a7040a632a52e",
    ),
)


@pytest.mark.parametrize("iv_h,msg_h,expected_h", _M2_STEPPER_TRIPLES)
def test_m2_stepper_compress_matches_captured_triples(iv_h, msg_h, expected_h):
    """m2_stepper_compress reproduces the recorded known-answer triples."""
    iv = bytes.fromhex(iv_h)
    msg = bytes.fromhex(msg_h)
    if len(msg) > 64:
        msg = msg[:64]
    elif len(msg) < 64:
        msg = msg.ljust(64, b"\x00")
    output = fply.m2_stepper_compress(iv, msg)
    assert output.hex() == expected_h, (
        f"m2_stepper_compress mismatch:\n"
        f"  expected: {expected_h}\n"
        f"  got:      {output.hex()}"
    )


def test_m2_stepper2_compress_signature():
    """STEPPER2 has the right signature and validates input lengths."""
    iv = b"\x00" * 16
    msg = b"\x00" * 64
    out = fply.m2_stepper2_compress(iv, msg)
    assert isinstance(out, bytes) and len(out) == 16
    with pytest.raises(ValueError, match="iv must be 16 bytes"):
        fply.m2_stepper2_compress(b"\x00" * 8, msg)
    with pytest.raises(ValueError, match="message must be 64 bytes"):
        fply.m2_stepper2_compress(iv, b"\x00" * 32)


def test_m2_stepper2_compress_validated_block1_macp1():
    """m2_stepper2_compress matches a known-answer vector."""
    iv = bytes.fromhex("4dad9cfa8c26684b9988f37f952e92de")
    msg = bytes.fromhex(
        "4dad9cfa8c26684b9988f37f952e92de"
        "7f01001e3fc3ad95e80f88d46ad77971"
        "fc89020cbb230291cf20b091a096ec1d"
        "7d6aa428bea98dc73e0a050fe29b49d3"
    )
    expected = bytes.fromhex("be3496aacd2e73de6e6d0cb54fec78fa")
    assert fply.m2_stepper2_compress(iv, msg) == expected


def test_m2_stepper2_compress_deterministic():
    """Same (iv, message) input always produces the same output."""
    iv = bytes.fromhex("4dad9cfa8c26684b9988f37f952e92de")
    msg = b"\x42" * 64
    a = fply.m2_stepper2_compress(iv, msg)
    b = fply.m2_stepper2_compress(iv, msg)
    assert a == b
    # Different message → different output (sanity)
    msg2 = b"\x42" * 32 + b"\x43" * 32
    assert fply.m2_stepper2_compress(iv, msg2) != a


def test_m2_stepper_compress_rejects_wrong_lengths():
    """Argument validation: iv must be 16 bytes, message must be 64 bytes."""
    with pytest.raises(ValueError, match="iv must be 16"):
        fply.m2_stepper_compress(b"\x00" * 15, b"\x00" * 64)
    with pytest.raises(ValueError, match="message must be 64"):
        fply.m2_stepper_compress(b"\x00" * 16, b"\x00" * 63)


# ---------------------------------------------------------------------------
# Validation and state guards
#
# These branches never run in a successful handshake, so each test checks the
# exception type and that the message names the field (and value, if given).
# ---------------------------------------------------------------------------


def _handshake_awaiting_m2() -> "fply.FPLYHandshake":
    """A handshake advanced past M1, which is where M2 may be consumed."""
    handshake = fply.FPLYHandshake()
    handshake.build_m1()
    return handshake


def test_parse_m2_warns_on_unexpected_version_byte(caplog):
    """A version byte other than 3 warns but must not abort the handshake."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.fply")
    m2 = bytearray(_valid_m2())
    m2[4] = 0x09

    parsed = fply.parse_m2(bytes(m2))

    assert parsed is not None, "an unexpected version must not stop parsing"
    messages = [r.getMessage() for r in caplog.records]
    assert any("0x09" in m and "0x03" in m for m in messages), messages


def test_build_m3_rejects_wrong_aux_header_length():
    """aux_header is a fixed 3-byte field; the error must say so."""
    with pytest.raises(ValueError, match="aux_header must be 3 bytes, got 4"):
        fply.build_m3(
            mode=1,
            cipher_payload=bytes(128),
            device_tag=bytes(20),
            aux_header=b"\x00\x00\x00\x00",
        )


def test_build_m3_stateful_is_an_alias_of_consume_m2_build_m3():
    """The legacy name must produce byte-identical output."""
    m2 = _valid_m2()
    assert _handshake_awaiting_m2().build_m3_stateful(
        m2
    ) == _handshake_awaiting_m2().consume_m2_build_m3(m2)


def test_finish_ekey_before_m3_is_refused():
    """finish_ekey needs the SAP secret that consume_m2_build_m3 derives."""
    with pytest.raises(RuntimeError, match="consume_m2_build_m3 must be called first"):
        fply.FPLYHandshake().finish_ekey(b"")


def test_finish_ekey_rejects_wrong_raw16_length():
    """raw16 is the 16-byte media secret; the error must name the real size."""
    handshake = _handshake_awaiting_m2()
    handshake.consume_m2_build_m3(_valid_m2())
    with pytest.raises(ValueError, match="raw16 must be 16 bytes, got 8"):
        handshake.finish_ekey(b"", raw16=b"\x01" * 8)


def test_finish_ekey_warns_when_m4_echoes_a_different_device_tag(caplog):
    """M4 echoes M3's device tag; a mismatch is logged as a warning."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.fply")
    handshake = _handshake_awaiting_m2()
    handshake.consume_m2_build_m3(_valid_m2())

    # 32+ bytes so the echo check runs, with a final 20 bytes that are not
    # the tag we sent.
    handshake.finish_ekey(bytes(12) + b"\xaa" * 20, raw16=b"\x01" * 16)

    messages = [r.getMessage() for r in caplog.records]
    assert any("M4 echoes device_tag" in m for m in messages), messages
    assert any("aa" * 20 in m for m in messages), messages


def test_finish_ekey_accepts_a_matching_m4_echo_without_warning(caplog):
    """The happy half of the same branch: a correct echo must stay quiet."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.fply")
    handshake = _handshake_awaiting_m2()
    handshake.consume_m2_build_m3(_valid_m2())
    ours = fairplay_sap.device_tag(handshake.sap_secret)

    handshake.finish_ekey(bytes(12) + ours, raw16=b"\x01" * 16)

    assert not [
        r.getMessage()
        for r in caplog.records
        if "M4 echoes device_tag" in r.getMessage()
    ]


def test_sap_secret_before_m3_is_refused():
    """Reading the SAP secret early must say the handshake is incomplete."""
    with pytest.raises(RuntimeError, match="handshake not complete"):
        _ = fply.FPLYHandshake().sap_secret


def test_sap_secret_after_m3_is_the_36_byte_secret():
    """The other half of the same property."""
    handshake = _handshake_awaiting_m2()
    handshake.consume_m2_build_m3(_valid_m2())
    assert len(handshake.sap_secret) == 36


def test_sap_context_after_m3_carries_the_secret_at_offset_8():
    """session.py slices the FairPlay secret out of ctx[8:44]."""
    handshake = _handshake_awaiting_m2()
    handshake.consume_m2_build_m3(_valid_m2())
    context = handshake.sap_context
    assert len(context) == 276
    assert context[8:44] == handshake.sap_secret


def test_m3_payload_before_m3_is_refused():
    """The 128-byte session block does not exist until M3 is built."""
    with pytest.raises(RuntimeError, match="handshake not complete"):
        _ = fply.FPLYHandshake().m3_payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "m4_body,expected",
    [
        pytest.param(b"\x04\x05\x06", b"\x04\x05\x06", id="bytes"),
        pytest.param(bytearray(b"\x07\x08"), bytearray(b"\x07\x08"), id="bytearray"),
        pytest.param("\x04\x05\x06", b"\x04\x05\x06", id="str-ascii"),
        pytest.param("\xff\xfe", b"\xff\xfe", id="str-above-7f"),
        pytest.param("", b"", id="str-empty"),
        pytest.param(None, b"", id="no-body"),
    ],
)
async def test_run_fply_handshake_accepts_every_shape_of_m4_body(m4_body, expected):
    """M4 arrives as bytes or as latin-1 text, and may be empty.

    pyatv's HTTP layer returns ``str`` for a decoded body and ``bytes``
    otherwise.  A ``str`` must be encoded as latin-1 so bytes above 0x7f
    survive, and an empty or missing body must give ``b""``.
    """
    conn = _FakeConnection(
        [_FakeHttpResponse(200, _valid_m2()), _FakeHttpResponse(200, m4_body)]
    )
    sm = await fply.run_fply_handshake(conn)
    assert sm.m4 == expected


@pytest.mark.asyncio
async def test_a_normal_m2_produces_no_warning(caplog):
    """A handshake with the usual M2 mode (0x01) logs no warning."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.fply")

    conn = _FakeConnection(
        [_FakeHttpResponse(200, _valid_m2()), _FakeHttpResponse(200, b"")]
    )
    await fply.run_fply_handshake(conn)

    assert "mode" not in caplog.text.lower(), caplog.text


@pytest.mark.asyncio
async def test_an_unverified_m2_mode_does_warn(caplog):
    """An M2 mode other than 0x01 logs a warning."""
    caplog.set_level(logging.WARNING, logger="pyatv.protocols.airplay.mirror.fply")

    conn = _FakeConnection(
        [_FakeHttpResponse(200, _valid_m2(mode=2)), _FakeHttpResponse(200, b"")]
    )
    await fply.run_fply_handshake(conn)

    assert "mode" in caplog.text.lower(), "an unverified M2 mode passed silently"


@pytest.mark.asyncio
async def test_the_fply_handshake_sends_the_apple_headers():
    """Both FPLY posts carry ``X-Apple-HKP: 3`` and ``X-Apple-ET: 32``.

    ``X-Apple-ET: 32`` selects FairPlay encryption on the receiver.
    """
    conn = _FakeConnection(
        [_FakeHttpResponse(200, _valid_m2()), _FakeHttpResponse(200, b"")]
    )
    await fply.run_fply_handshake(conn)

    assert len(conn.headers) == 2, conn.headers
    for headers in conn.headers:
        assert headers.get("X-Apple-HKP") == "3", headers
        assert headers.get("X-Apple-ET") == "32", headers
