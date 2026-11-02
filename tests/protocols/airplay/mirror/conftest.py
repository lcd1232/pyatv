"""Shared test configuration for AirPlay mirror tests."""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

_LOGGER = logging.getLogger(__name__)


# The heartbeat loop uses asyncio.sleep which is stubbed to return immediately
# in tests, causing a tight spin loop of RTSP feedback requests. Stub out the
# mirror heartbeater (analogous to the global stub for MRP's heartbeater).
@pytest.fixture(autouse=True)
def stub_mirror_heartbeat_loop():
    async def _stub(*args, **kwargs):
        _LOGGER.debug("Using stub for mirror heartbeat")

    with patch("pyatv.protocols.airplay.mirror.session.heartbeater") as mock_heartbeat:
        mock_heartbeat.side_effect = _stub
        yield
