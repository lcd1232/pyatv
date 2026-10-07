"""Tests for pyatv.protocols.airplay.mirror.streams."""

import asyncio
import logging
from unittest.mock import MagicMock

import pytest

from pyatv.protocols.airplay.mirror import streams


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
