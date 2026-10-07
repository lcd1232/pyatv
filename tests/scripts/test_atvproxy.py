"""Quit handling in :mod:`pyatv.scripts.atvproxy`.

The proxy blocks until the user quits. Reading stdin returns immediately at
EOF -- which is what a script, a pipe, or ``nohup`` gives it -- so a plain
``stdin.readline()`` makes the proxy exit the instant it starts. Waiting on
an Event instead fixes that and breaks quitting with ENTER, which is how the
tool is normally used.

``_wait_until_quit`` has to do both, and which branch it takes is decided by
something no other test touches: whether stdin is a terminal.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from pyatv.scripts import atvproxy

pytestmark = pytest.mark.asyncio


async def test_enter_quits_when_stdin_is_a_terminal(capsys):
    """A newline on a TTY returns control to the caller."""
    loop = asyncio.get_running_loop()
    read = MagicMock(return_value="\n")

    with (
        patch.object(atvproxy.sys.stdin, "isatty", return_value=True),
        patch.object(atvproxy.sys.stdin, "readline", read),
    ):
        await asyncio.wait_for(atvproxy._wait_until_quit(loop), timeout=5)

    read.assert_called_once()
    assert "Press ENTER to quit" in capsys.readouterr().out


async def test_a_non_terminal_stdin_does_not_end_the_proxy(capsys):
    """At EOF the proxy must keep running rather than exit immediately.

    ``readline`` would return ``""`` straight away here. If the function
    consulted it, this would return instead of timing out -- so the timeout
    *is* the assertion, and ``readline`` must never be reached.
    """
    loop = asyncio.get_running_loop()
    read = MagicMock(return_value="")

    with (
        patch.object(atvproxy.sys.stdin, "isatty", return_value=False),
        patch.object(atvproxy.sys.stdin, "readline", read),
    ):
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(atvproxy._wait_until_quit(loop), timeout=0.25)

    read.assert_not_called()
    out = capsys.readouterr().out
    assert "Ctrl-C" in out
    assert "Press ENTER to quit" not in out, "promised something ENTER cannot do"


async def test_cancelling_the_wait_is_not_swallowed():
    """Cancellation must propagate, not be absorbed into a normal return.

    ``_wait_until_quit`` catches KeyboardInterrupt so the caller still reaches
    its Zeroconf unpublish, but deliberately does not catch CancelledError:
    absorbing that would make an awaiting caller believe the wait finished
    normally, and break cancellation for anything that ever cancels it.

    The first assertion matters as much as the last. Without it the test
    would pass against a function that returned immediately and never waited
    at all -- there would be nothing left to cancel.
    """
    loop = asyncio.get_running_loop()

    with patch.object(atvproxy.sys.stdin, "isatty", return_value=False):
        task = asyncio.ensure_future(atvproxy._wait_until_quit(loop))
        await asyncio.sleep(0)
        assert not task.done(), "returned without waiting for anything"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled(), "cancellation was absorbed into a normal return"
