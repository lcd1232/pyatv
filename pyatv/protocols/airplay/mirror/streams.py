"""Queue-to-channel plumbing for the AirPlay 2 mirror video stream."""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol

_LOGGER = logging.getLogger(__name__)


class SendChannel(Protocol):
    """Anything the mirror pipeline can push an already-framed message at.

    :class:`..tcp_stream.RawVideoTCPChannel` fills this role. ``send()`` is
    the whole of what the drain task needs, so that is what is asked for here.
    """

    def send(self, data: bytes) -> None:
        """Send one already-framed message."""


async def drain_queue_to_channel(
    channel: SendChannel,
    queue: asyncio.Queue,
) -> None:
    """Background task: pop pre-framed bytes from `queue` and send on `channel`.

    Sentinel `None` ends the task.
    """
    while True:
        item = await queue.get()
        if item is None:
            return
        try:
            channel.send(item)
        except Exception:
            _LOGGER.exception("drain_queue_to_channel send failed")
            return
