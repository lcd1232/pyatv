"""Unit tests for pyatv.core.protocol."""

import asyncio
from functools import partial
import logging
import math
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from pyatv.core.protocol import MessageDispatcher, heartbeater

from tests.utils import total_sleep_time, until

pytestmark = pytest.mark.asyncio

# heartbeat


class HeartbeatMonitor:
    def __init__(self) -> None:
        self.task: Optional[asyncio.Task] = None
        self.send_call_count: int = 0
        self.send_event: asyncio.Event = asyncio.Event()
        self.send_message: Optional[Any] = None
        self.finish_called: bool = False
        self.failure_called: bool = False
        self.make_send_fail: bool = False

    def start(self, message_factory=None, retries=0, interval=5):
        self.task = asyncio.ensure_future(
            heartbeater(
                "name",
                self.send,
                self.finish,
                self.failure,
                message_factory=message_factory or (lambda: None),
                retries=retries,
                interval=interval,
            )
        )

    async def stop(self) -> None:
        self.task.cancel()
        await self.task

    def next_lap(self) -> None:
        self.send_event.set()

    async def send(self, message) -> None:
        self.send_call_count += 1
        self.send_message = message

        if self.make_send_fail:
            raise Exception("send failed")
        else:
            await self.send_event.wait()
            self.send_event.clear()

    def finish(self) -> None:
        self.finish_called = True

    def failure(self, exc: Exception) -> None:
        self.failure_called = True


@pytest_asyncio.fixture(name="monitor")
async def monitor_fixture():
    monitor = HeartbeatMonitor()
    yield monitor
    await monitor.stop()


async def test_send_heartbeats(monitor):
    monitor.start()

    for lap in range(1, 4):
        await until(lambda: monitor.send_call_count == lap)
        monitor.next_lap()


async def test_failure_called_on_send_error(monitor):
    monitor.make_send_fail = True
    monitor.start()

    await until(lambda: monitor.failure_called)
    assert monitor.send_call_count == 1


async def test_finish_called_on_cancel(monitor):
    monitor.start()

    await until(lambda: monitor.send_call_count == 1)
    await monitor.stop()

    await until(lambda: monitor.finish_called)
    assert not monitor.failure_called


async def test_retry_before_failure(monitor):
    monitor.make_send_fail = True
    monitor.start(retries=3, interval=5)

    await until(lambda: monitor.send_call_count == 4)
    assert monitor.failure_called
    assert not monitor.finish_called


async def test_sleep_between_send(monitor):
    monitor.start(interval=5)

    await until(lambda: monitor.send_call_count == 1)
    assert math.isclose(total_sleep_time(), 5)
    monitor.next_lap()

    await until(lambda: monitor.send_call_count == 2)
    assert math.isclose(total_sleep_time(), 10)


async def test_no_sleep_for_first_retry(monitor):
    monitor.make_send_fail = True
    monitor.start(retries=1, interval=5)

    await until(lambda: monitor.send_call_count == 2)
    monitor.next_lap()
    await until(lambda: monitor.failure_called)
    assert math.isclose(total_sleep_time(), 5)


async def test_message_is_passed_to_send(monitor):
    message = object()
    monitor.start(message_factory=lambda: message)

    await until(lambda: monitor.send_call_count == 1)
    assert monitor.send_message is message


# MessageDispatcher


async def test_simple_dispatch(caplog):
    """Both an async and a plain listener receive their message.

    The two halves take different paths through ``dispatch``: a coroutine
    function becomes an awaitable task, while a plain one is handed to
    ``loop.call_soon`` and produces no task at all. That is why the second
    half needs a loop turn before asserting -- ``gather()`` over an empty
    task list returns before ``call_soon`` has run anything.

    The log is checked too. ``_call_listener`` catches and logs anything a
    listener raises, which is right -- one bad listener must not stop the
    others -- but it also means a broken listener looks exactly like a
    working one from out here. This test used to call an undefined name and
    assert on the wrong mock, and passed for precisely that reason.
    """
    caplog.set_level(logging.ERROR, logger="pyatv.core.protocol")
    test_mock = MagicMock()

    async def dispatch_func1(mock, message: bytes) -> None:
        mock.func1(message)

    def dispatch_func2(mock, message: bytes) -> None:
        mock.func2(message)

    dispatcher = MessageDispatcher[int, bytes]()
    dispatcher.listen_to(1, partial(dispatch_func1, test_mock))
    dispatcher.listen_to(2, partial(dispatch_func2, test_mock))

    await asyncio.wait_for(asyncio.gather(*dispatcher.dispatch(1, b"123")), 5.0)
    test_mock.func1.assert_called_once_with(b"123")

    await asyncio.wait_for(asyncio.gather(*dispatcher.dispatch(2, b"456")), 5.0)
    await asyncio.sleep(0)  # let call_soon deliver before asserting
    test_mock.func2.assert_called_once_with(b"456")

    assert "error during dispatch" not in caplog.text, caplog.text


async def test_dispatch_with_filter():
    dispatched_value = None

    async def dispatch_func(value: int) -> None:
        nonlocal dispatched_value
        dispatched_value = value

    dispatcher = MessageDispatcher[int, int]()
    dispatcher.listen_to(
        1, dispatch_func, message_filter=lambda message: (message % 2) == 0
    )

    await asyncio.wait_for(asyncio.gather(*dispatcher.dispatch(1, 1)), 5.0)
    assert dispatched_value is None

    await asyncio.wait_for(asyncio.gather(*dispatcher.dispatch(1, 2)), 5.0)
    assert dispatched_value == 2
