"""Transports for the AirPlay 2 mirror video and audio streams.

Two shapes are used:

* :class:`MirrorVideoDatagramChannel` -- the modern (AVConf / "UDP mirroring")
  video path. The receiver returns a ``dataPort`` that accepts **UDP only**;
  TCP to it is refused while UDP is open, and the receiver advertises
  ``hasUDPMirroringSupport: True``. Frames are datagrams, so anything larger
  than the path MTU has to be split.
* :class:`VideoStreamChannel` / :class:`AudioStreamChannel` -- the older
  HAP-encrypted TCP side channels, kept for the legacy path and for the
  media-data-control connection.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Protocol

from pyatv.auth.hap_channel import AbstractHAPChannel

_LOGGER = logging.getLogger(__name__)


class SendChannel(Protocol):
    """Anything the mirror pipeline can push an already-framed message at.

    Three unrelated classes fill this role -- :class:`VideoStreamChannel`
    (HAP over TCP), :class:`MirrorVideoDatagramChannel` (UDP) and
    :class:`..tcp_stream.RawVideoTCPChannel` (plain TCP). They share no
    base class: two are :class:`asyncio.Protocol` subclasses and one is a
    :class:`asyncio.DatagramProtocol`. ``send()`` is the whole of what the
    drain task needs from any of them, so that is what is asked for here.
    """

    def send(self, data: bytes) -> None:
        """Send one already-framed message."""


class _MirrorChannelBase(AbstractHAPChannel):
    """Base for one-way (sender → receiver) mirror stream channels."""

    name = "mirror"

    def handle_received(self) -> None:
        """Discard inbound bytes: the receiver pushes nothing back in the MVP."""
        # Discard anything we somehow get; mirror streams are sender → receiver.
        if self.buffer:
            _LOGGER.debug(
                "%s channel got %d unexpected inbound bytes; discarding",
                self.name,
                len(self.buffer),
            )
            self.buffer = b""

    def connection_lost(self, exc: Optional[Exception]) -> None:
        super().connection_lost(exc)
        _LOGGER.debug("%s channel connection lost: %s", self.name, exc)


class VideoStreamChannel(_MirrorChannelBase):
    """TCP side channel carrying mirror-framed H.264 video frames."""

    name = "video"


class AudioStreamChannel(_MirrorChannelBase):
    """TCP side channel carrying mirror-framed AAC-LC audio frames."""

    name = "audio"


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


#: Conservative payload budget for one datagram (1500 MTU - IP/UDP headers,
#: minus room for the mirror frame header).
DATAGRAM_PAYLOAD_LIMIT = 1400


class MirrorControlChannel(_MirrorChannelBase):
    """HAP-encrypted TCP channel to ``streamConnectionKeyPort``.

    The receiver opens this port (TCP) alongside the UDP ``dataPort`` and
    stays silent until the sender speaks, so anything arriving here is logged
    rather than discarded -- it is the most likely place for the receiver to
    report a problem with the media stream.
    """

    name = "media-data-control"

    def handle_received(self) -> None:
        """Log whatever the receiver sends on the control channel."""
        if self.buffer:
            _LOGGER.debug(
                "control channel received %d bytes: %s",
                len(self.buffer),
                self.buffer[:64].hex(),
            )
            self.buffer = b""


class MirrorVideoDatagramChannel(asyncio.DatagramProtocol):
    """UDP transport for mirror video frames."""

    def __init__(self, remote_addr=None) -> None:
        """Initialize a new datagram channel.

        ``remote_addr`` is required when the endpoint is built from an
        already-bound socket (so the send port matches networkInfo.Port),
        since such a socket cannot also be connected.
        """
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.remote_addr = remote_addr

    def connection_made(self, transport) -> None:
        """Store the transport once the endpoint is up."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        """Log anything the receiver sends back on the data port."""
        _LOGGER.debug(
            "video data port received %d bytes from %s: %s",
            len(data),
            addr,
            data[:64].hex(),
        )

    def error_received(self, exc: Exception) -> None:
        """Log ICMP errors (e.g. port unreachable)."""
        _LOGGER.debug("video data port error: %s", exc)

    _sent = 0
    _bytes = 0

    def send(self, datagram: bytes) -> None:
        """Send one datagram.

        Fragmentation is handled upstream by :class:`~.rtp.RtpPacketizer`,
        which splits a frame across consecutive RTP sequence numbers.
        """
        if self.transport is None:
            raise RuntimeError("datagram channel not connected")
        self.transport.sendto(datagram, self.remote_addr)
        MirrorVideoDatagramChannel._sent += 1
        MirrorVideoDatagramChannel._bytes += len(datagram)
        if MirrorVideoDatagramChannel._sent % 200 == 0:
            _LOGGER.info(
                "VIDEO SENT %d packets, %d bytes -> %s",
                MirrorVideoDatagramChannel._sent,
                MirrorVideoDatagramChannel._bytes,
                self.remote_addr,
            )

    def close(self) -> None:
        """Close the datagram endpoint."""
        if self.transport is not None:
            self.transport.close()
            self.transport = None
