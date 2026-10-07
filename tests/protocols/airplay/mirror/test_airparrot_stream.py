"""Tests for the AirParrot-dialect data-channel framing."""

import asyncio
import logging
import struct

import pytest

from pyatv.protocols.airplay.mirror import airparrot_stream


def test_data_header_basic_layout():
    hdr = airparrot_stream.build_data_header(
        1234, 0x1122334455667788, msg_type=airparrot_stream._VIDEO_DATA_TYPE
    )
    assert len(hdr) == 128
    assert struct.unpack_from("<I", hdr, 0)[0] == 1234
    assert hdr[4:8] == airparrot_stream._VIDEO_DATA_TYPE
    assert struct.unpack_from("<Q", hdr, 8)[0] == 0x1122334455667788
    # No dims/geometry -> [16:24] and [40:64] stay zero.
    assert hdr[16:24] == b"\x00" * 8
    assert hdr[40:64] == b"\x00" * 24


def test_config_header_carries_source_dims():
    # The CONFIG frame must carry (width, height) as two float32 LE at [16:24];
    # without them the receiver decodes but renders black.
    hdr = airparrot_stream.build_data_header(
        31,
        0,
        msg_type=airparrot_stream._CONFIG_TYPE,
        dims=(1280.0, 720.0),
    )
    w, h = struct.unpack_from("<ff", hdr, 16)
    assert (w, h) == (1280.0, 720.0)
    assert hdr[4:8] == airparrot_stream._CONFIG_TYPE


def test_geometry_lands_at_offset_40():
    geom = airparrot_stream.build_geometry(1280.0, 720.0, 0.0, 0.0, 1280.0, 720.0)
    assert len(geom) == 24
    hdr = airparrot_stream.build_data_header(10, 0, geom)
    assert hdr[40:64] == geom
    assert struct.unpack_from("<ffffff", hdr, 40) == (
        1280.0,
        720.0,
        0.0,
        0.0,
        1280.0,
        720.0,
    )


def test_derive_stream_key_matches_airparrot_ground_truth():
    # Captured live from AirParrot's DeriveKeyAndIV (2026-08-24): given these
    # raw16/pair32/streamConnectionID, its AES key/iv were exactly these.
    from pyatv.protocols.airplay.mirror.framing import (
        derive_airparrot_stream_key_iv,
    )

    raw16 = bytes.fromhex("b2afda803e40288d693df7084e17fe83")
    pair32 = bytes.fromhex(
        "db2f925a4bb807ffc764fef7728efc89d27842dff25a709e898dca9441a0aa64"
    )
    key, iv = derive_airparrot_stream_key_iv(raw16, pair32, 527657112)
    assert key.hex() == "3f9ec9a5a6d69c05b961f7bb3c38718d"
    assert iv.hex() == "a0cd20d57da1e134f8c858e5aedbf7c3"


def test_group_access_units_keeps_trailing_non_vcl_nals():
    """NALs after the last coded slice must still be emitted as a unit.

    Non-VCL NALs attach to the *following* VCL NAL, so a file ending in
    SPS/PPS (or a trailing SEI) has a pending group with no slice to close it.
    Dropping it would silently discard parameter sets at end of stream.
    """
    sps, pps, slice_nal, sei = b"\x67\xaa", b"\x68\xbb", b"\x65\xcc", b"\x06\xdd"

    units = airparrot_stream.group_access_units(
        [sps, pps, slice_nal, sei], lambda n: n[0] & 0x1F
    )

    assert units == [[sps, pps, slice_nal], [sei]]


def test_group_access_units_without_a_trailing_group():
    """The complementary case: ending on a slice leaves nothing pending."""
    slice_nal = b"\x65\xcc"
    units = airparrot_stream.group_access_units([slice_nal], lambda n: n[0] & 0x1F)
    assert units == [[slice_nal]]


def test_group_access_units_does_not_split_on_an_sei_nal():
    """SEI (type 6) is not a coded slice, so it must not close an access unit.

    A real stream carries SEI immediately before nearly every IDR, and the SEI
    describes the picture that follows it. Counting type 6 as VCL would emit it
    as an access unit of its own and strip it from the frame it belongs to.

    The trailing-SEI case above cannot catch that: an SEI left pending at end
    of stream is flushed as its own unit whether or not it counts as VCL, so
    both readings produce the same grouping there. Putting a slice *after* the
    SEI is what separates them.
    """
    sei, idr = b"\x06\xdd", b"\x65\xcc"

    units = airparrot_stream.group_access_units([sei, idr], lambda n: n[0] & 0x1F)

    assert units == [[sei, idr]]


def test_avcc_config_follows_the_decoder_configuration_record_layout():
    """avcC must lift profile/compat/level from bytes 1..3 of the SPS.

    The receiver configures its H.264 decoder from this record before the
    first frame arrives, so each of the three bytes has to come from its own
    SPS offset: profile_idc, then the constraint-flag byte, then level_idc.
    They are asserted as the values a real High@4.0 SPS carries, so lifting
    the wrong offset advertises a profile the stream is not encoded in.
    """
    # An H.264 High profile, level 4.0 SPS: NAL header, then 0x64 0x00 0x28.
    sps = bytes([0x67, 0x64, 0x00, 0x28, 0xAC, 0xD9, 0x40])
    pps = bytes([0x68, 0xEE, 0x3C, 0xB0])

    record = airparrot_stream.build_avcc_config(sps, pps)

    assert record[0] == 0x01  # configurationVersion
    assert record[1] == 0x64  # AVCProfileIndication: 100 = High
    assert record[2] == 0x00  # profile_compatibility: no constraint flags
    assert record[3] == 0x28  # AVCLevelIndication: 40 = level 4.0
    assert record[4] == 0xFF  # 6 reserved bits + lengthSizeMinusOne = 3
    assert record[5] == 0xE1  # 3 reserved bits + numOfSequenceParameterSets = 1
    assert record[6:8] == struct.pack(">H", len(sps))
    assert record[8 : 8 + len(sps)] == sps

    after_sps = record[8 + len(sps) :]
    assert after_sps[0] == 0x01  # numOfPictureParameterSets
    assert after_sps[1:3] == struct.pack(">H", len(pps))
    assert after_sps[3:] == pps


# ---------------------------------------------------------------------------
# RawVideoTCPChannel: the asyncio.Protocol callbacks the event loop invokes
# when the receiver does something other than quietly consume video.
# ---------------------------------------------------------------------------


class _Peer:
    """A loopback server that can talk back to, or half-close on, the sender."""

    def __init__(self, reply: bytes = b"", half_close: bool = False):
        self.reply = reply
        self.half_close = half_close
        self.received = bytearray()
        self.connected = asyncio.Event()
        self._server = None
        self._writers = []

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader, writer):
        self._writers.append(writer)
        self.connected.set()
        try:
            if self.reply:
                writer.write(self.reply)
                await writer.drain()
            if self.half_close:
                writer.write_eof()
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    return
                self.received += chunk
        except (ConnectionResetError, asyncio.CancelledError):
            return
        finally:
            # Server.wait_closed() waits for every live connection handler, so
            # the handler must always drop its own side or teardown hangs.
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def close(self):
        while self._writers:
            writer = self._writers.pop()
            try:
                writer.transport.abort()
            except Exception:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()


async def _connect_channel(port):
    loop = asyncio.get_event_loop()
    return await loop.create_connection(
        airparrot_stream.RawVideoTCPChannel, "127.0.0.1", port
    )


@pytest.mark.asyncio
async def test_channel_logs_inbound_bytes_from_the_receiver(caplog):
    """A receiver may push a control byte back; it must be logged, not dropped."""
    caplog.set_level(
        logging.INFO, logger="pyatv.protocols.airplay.mirror.airparrot_stream"
    )
    peer = _Peer(reply=b"\xde\xad\xbe\xef")
    port = await peer.start()
    transport = None
    try:
        transport, _channel = await _connect_channel(port)
        for _ in range(20):
            await asyncio.sleep(0)
            if any("inbound bytes" in r.getMessage() for r in caplog.records):
                break
    finally:
        if transport:
            transport.abort()
        await peer.close()

    messages = [r.getMessage() for r in caplog.records]
    assert any("got 4 inbound bytes: deadbeef" in m for m in messages), messages


@pytest.mark.asyncio
async def test_channel_warns_when_the_receiver_half_closes(caplog):
    """EOF from the receiver is abnormal mid-mirror and must be reported."""
    caplog.set_level(
        logging.WARNING, logger="pyatv.protocols.airplay.mirror.airparrot_stream"
    )
    peer = _Peer(half_close=True)
    port = await peer.start()
    transport = None
    try:
        transport, _channel = await _connect_channel(port)
        for _ in range(20):
            await asyncio.sleep(0)
            if any("half-close" in r.getMessage() for r in caplog.records):
                break
    finally:
        if transport:
            transport.abort()
        await peer.close()

    messages = [r.getMessage() for r in caplog.records]
    assert any("receiver sent EOF (half-close)" in m for m in messages), messages


@pytest.mark.asyncio
async def test_channel_send_is_a_no_op_once_the_transport_is_gone():
    """Sending after teardown must not raise -- frames can race the close."""
    channel = airparrot_stream.RawVideoTCPChannel()

    # Never connected.
    channel.send(b"frame")

    # Connected, then closing.
    peer = _Peer()
    port = await peer.start()
    transport, live = await _connect_channel(port)
    transport.close()
    live.send(b"frame")
    await peer.close()

    assert live._sent == 0, "a closing transport must not be counted as sent"


@pytest.mark.asyncio
async def test_channel_logs_a_progress_line_every_200_messages(caplog):
    """The periodic progress line is the only signal that video is flowing."""
    caplog.set_level(
        logging.INFO, logger="pyatv.protocols.airplay.mirror.airparrot_stream"
    )
    peer = _Peer()
    port = await peer.start()
    transport = None
    try:
        transport, channel = await _connect_channel(port)
        for _ in range(200):
            channel.send(b"x" * 10)
    finally:
        if transport:
            transport.abort()
        await peer.close()

    messages = [r.getMessage() for r in caplog.records]
    assert any("VIDEO SENT 200 messages, 2000 bytes" in m for m in messages), messages
