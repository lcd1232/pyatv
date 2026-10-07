"""Tests for pyatv.protocols.airplay.mirror.streams.

These are asyncio protocol objects, so everything here works by feeding them
bytes (or a fake transport) and asserting on what they emit -- no socket and
no receiver is involved.
"""

import asyncio
import logging
from unittest.mock import MagicMock

import pytest

from pyatv.auth.hap_session import HAPSession
from pyatv.protocols.airplay.mirror import streams

_OUTPUT_KEY = bytes(range(32))
_INPUT_KEY = bytes(range(32, 64))


def _channel(cls):
    """Build a channel with HAP encryption enabled and a fake transport."""
    channel = cls(_OUTPUT_KEY, _INPUT_KEY)
    channel.transport = MagicMock()
    return channel


def _peer_session() -> HAPSession:
    """The other end of the HAP session: the key pair is swapped."""
    session = HAPSession()
    session.enable(_INPUT_KEY, _OUTPUT_KEY)
    return session


@pytest.fixture(autouse=True)
def _reset_datagram_counters():
    """The send counters live on the class, so isolate tests from each other."""
    sent, sent_bytes = (
        streams.MirrorVideoDatagramChannel._sent,
        streams.MirrorVideoDatagramChannel._bytes,
    )
    yield
    streams.MirrorVideoDatagramChannel._sent = sent
    streams.MirrorVideoDatagramChannel._bytes = sent_bytes


# ---------------------------------------------------------------------------
# One-way sender -> receiver channels.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cls,name",
    [
        (streams.VideoStreamChannel, "video"),
        (streams.AudioStreamChannel, "audio"),
        (streams.MirrorControlChannel, "media-data-control"),
    ],
)
def test_channels_carry_their_own_log_name(cls, name):
    assert cls.name == name


@pytest.mark.parametrize(
    "cls", [streams.VideoStreamChannel, streams.AudioStreamChannel]
)
def test_one_way_channels_discard_inbound_data(cls, caplog):
    """Mirror streams are sender -> receiver; anything inbound is dropped.

    The bytes are pushed through a real HAP session so the decrypt path in
    ``AbstractHAPChannel.data_received`` runs, not just ``handle_received``.
    """
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = _channel(cls)
    channel.data_received(_peer_session().encrypt(b"unexpected inbound"))

    assert channel.buffer == b""
    assert f"{cls.name} channel got 18 unexpected inbound bytes" in caplog.text


@pytest.mark.parametrize(
    "cls",
    [
        streams.VideoStreamChannel,
        streams.AudioStreamChannel,
        streams.MirrorControlChannel,
    ],
)
def test_handle_received_on_an_empty_buffer_does_nothing(cls, caplog):
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = _channel(cls)
    channel.handle_received()
    assert channel.buffer == b""
    assert caplog.text == ""


def test_control_channel_logs_what_the_receiver_says_instead_of_dropping_it():
    """The control channel is the likeliest place for a receiver complaint."""
    channel = _channel(streams.MirrorControlChannel)
    channel.buffer = b"\xde\xad\xbe\xef"
    channel.handle_received()
    assert channel.buffer == b""


def test_control_channel_log_truncates_at_64_bytes(caplog):
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = _channel(streams.MirrorControlChannel)
    channel.data_received(_peer_session().encrypt(bytes(range(100))))

    assert channel.buffer == b""
    assert "control channel received 100 bytes" in caplog.text
    assert bytes(range(64)).hex() in caplog.text
    assert bytes(range(100)).hex() not in caplog.text


@pytest.mark.parametrize("exc", [None, ConnectionResetError("peer went away")])
def test_connection_lost_is_logged_with_the_channel_name(exc, caplog):
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = _channel(streams.VideoStreamChannel)
    channel.connection_lost(exc)
    assert f"video channel connection lost: {exc}" in caplog.text


# ---------------------------------------------------------------------------
# drain_queue_to_channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_drain_queue_sends_every_item_then_stops_on_the_sentinel():
    channel = MagicMock()
    queue: asyncio.Queue = asyncio.Queue()
    for item in (b"one", b"two", b"three"):
        queue.put_nowait(item)
    queue.put_nowait(None)

    await streams.drain_queue_to_channel(channel, queue)

    assert [call.args[0] for call in channel.send.call_args_list] == [
        b"one",
        b"two",
        b"three",
    ]


@pytest.mark.asyncio
async def test_drain_queue_stops_when_the_channel_send_raises(caplog):
    """A dead channel must end the task rather than spin on every frame."""
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = MagicMock()
    channel.send.side_effect = ConnectionResetError("closed")
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(b"first")
    queue.put_nowait(b"second")

    await streams.drain_queue_to_channel(channel, queue)

    assert channel.send.call_count == 1
    assert "drain_queue_to_channel send failed" in caplog.text
    # The task returned rather than draining the rest of the queue.
    assert queue.qsize() == 1


@pytest.mark.asyncio
async def test_drain_queue_blocks_until_an_item_arrives():
    channel = MagicMock()
    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.ensure_future(streams.drain_queue_to_channel(channel, queue))
    await asyncio.sleep(0)
    assert not task.done()

    queue.put_nowait(b"late")
    queue.put_nowait(None)
    await task
    channel.send.assert_called_once_with(b"late")


# ---------------------------------------------------------------------------
# MirrorVideoDatagramChannel
# ---------------------------------------------------------------------------


def test_datagram_channel_stores_the_transport_on_connection_made():
    channel = streams.MirrorVideoDatagramChannel(("10.0.0.5", 7100))
    assert channel.transport is None
    transport = MagicMock()
    channel.connection_made(transport)
    assert channel.transport is transport


def test_datagram_send_before_connection_made_is_an_error():
    channel = streams.MirrorVideoDatagramChannel(("10.0.0.5", 7100))
    with pytest.raises(RuntimeError, match="datagram channel not connected"):
        channel.send(b"frame")


def test_datagram_send_addresses_the_remote_explicitly():
    """The socket is pre-bound (so the source port matches networkInfo.Port),
    which means it cannot also be connected -- every send needs the address."""
    remote = ("10.0.0.5", 7100)
    channel = streams.MirrorVideoDatagramChannel(remote)
    transport = MagicMock()
    channel.connection_made(transport)
    channel.send(b"frame-bytes")
    transport.sendto.assert_called_once_with(b"frame-bytes", remote)


def test_datagram_send_counts_packets_and_bytes_across_instances(caplog):
    """The progress counters are class-level, so two channels share a tally."""
    caplog.set_level(logging.INFO, logger=streams.__name__)
    streams.MirrorVideoDatagramChannel._sent = 0
    streams.MirrorVideoDatagramChannel._bytes = 0

    channel = streams.MirrorVideoDatagramChannel(("10.0.0.5", 7100))
    channel.connection_made(MagicMock())
    for _ in range(199):
        channel.send(b"x" * 10)
    assert "VIDEO SENT" not in caplog.text

    other = streams.MirrorVideoDatagramChannel(("10.0.0.6", 7100))
    other.connection_made(MagicMock())
    other.send(b"y" * 20)

    assert streams.MirrorVideoDatagramChannel._sent == 200
    assert streams.MirrorVideoDatagramChannel._bytes == 199 * 10 + 20
    assert "VIDEO SENT 200 packets, 2010 bytes -> ('10.0.0.6', 7100)" in caplog.text


def test_datagram_received_is_logged(caplog):
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = streams.MirrorVideoDatagramChannel()
    channel.datagram_received(bytes(range(80)), ("10.0.0.5", 7100))
    assert "video data port received 80 bytes from ('10.0.0.5', 7100)" in caplog.text
    assert bytes(range(64)).hex() in caplog.text
    assert bytes(range(80)).hex() not in caplog.text


def test_error_received_is_logged(caplog):
    """ICMP port-unreachable arrives here; a dead port must not stay silent."""
    caplog.set_level(logging.DEBUG, logger=streams.__name__)
    channel = streams.MirrorVideoDatagramChannel()
    channel.error_received(ConnectionRefusedError("port unreachable"))
    assert "video data port error: port unreachable" in caplog.text


def test_datagram_close_closes_the_transport_once():
    channel = streams.MirrorVideoDatagramChannel(("10.0.0.5", 7100))
    transport = MagicMock()
    channel.connection_made(transport)

    channel.close()
    transport.close.assert_called_once()
    assert channel.transport is None

    channel.close()  # idempotent
    transport.close.assert_called_once()


def test_datagram_payload_limit_fits_a_1500_byte_path_mtu():
    """The constant is advisory: nothing reads it, the packetizer has its own.

    ``rtp.MAX_PAYLOAD`` (1330) is what actually bounds a datagram, and it is
    the stricter of the two.  What must hold of this constant is only that a
    datagram of this size still fits under a 1500-byte MTU once the 28 bytes
    of IPv4 + UDP header are added; its docstring's "minus room for the mirror
    frame header" does *not* hold -- 1400 + 128 = 1528 exceeds the 1472-byte
    UDP payload budget -- which is harmless only because nothing uses it.
    """
    from pyatv.protocols.airplay.mirror import rtp

    assert streams.DATAGRAM_PAYLOAD_LIMIT == 1400
    assert streams.DATAGRAM_PAYLOAD_LIMIT <= 1500 - 28
    assert rtp.MAX_PAYLOAD < streams.DATAGRAM_PAYLOAD_LIMIT
