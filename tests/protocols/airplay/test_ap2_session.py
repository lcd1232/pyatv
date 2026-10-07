"""Channel setup in :class:`pyatv.protocols.airplay.ap2_session.AP2Session`.

The event and data channels are opened by one shared helper,
``_setup_encrypted_channel``, which each caller parameterises with its own
salt, key-derivation info strings and port location.  Getting any of those
wrong swaps or corrupts the keys for an encrypted side channel, which fails
at the receiver rather than here.

Nothing exercised this: ``ap2_session`` had no tests at all, and the whole
module sat at 38% while the AirPlay remote-control path depends on it.  The
assertions below are deliberately about the *arguments handed to*
``setup_channel``, because that is the boundary the shared helper has to get
right for both callers.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyatv.auth.hap_pairing import HapCredentials
from pyatv.protocols.airplay import ap2_session
from pyatv.protocols.airplay.ap2_session import AP2Session
from pyatv.protocols.airplay.channels import DataStreamChannel, EventChannel
from pyatv.settings import InfoSettings

pytestmark = pytest.mark.asyncio


def _session():
    session = AP2Session("10.0.0.1", 7000, HapCredentials(), InfoSettings())
    session.verifier = MagicMock()
    session.rtsp = MagicMock()
    session.rtsp.setup = AsyncMock(return_value=MagicMock())
    return session


async def _run(session, coro_name, setup_response):
    """Drive one channel setup with the SETUP reply stubbed out."""
    transport, protocol = MagicMock(), MagicMock()
    with (
        patch.object(
            ap2_session, "decode_bplist_from_body", return_value=setup_response
        ),
        patch.object(
            ap2_session, "setup_channel", AsyncMock(return_value=(transport, protocol))
        ) as setup_channel,
    ):
        await getattr(session, coro_name)("10.0.0.2")
    return setup_channel, transport, protocol


async def test_event_channel_uses_the_events_salt_and_reversed_key_info():
    """Read/write info are deliberately reversed for the event channel.

    The connection originates at the receiver, so what pyatv reads with is
    what the receiver writes with.  A helper that passed these through in
    declaration order rather than this order would derive two keys that each
    side uses for the opposite direction.
    """
    session = _session()
    setup_channel, transport, _ = await _run(
        session, "_setup_event_channel", {"eventPort": 49152}
    )

    (factory, verifier, address, port, salt, output, input_), _ = (
        setup_channel.call_args
    )
    assert factory is EventChannel
    assert verifier is session.verifier
    assert (address, port) == ("10.0.0.2", 49152)
    assert salt == ap2_session.EVENTS_SALT
    assert output == ap2_session.EVENTS_READ_INFO
    assert input_ == ap2_session.EVENTS_WRITE_INFO

    assert transport in session._channels  # noqa: SLF001
    assert session.data_channel is None, "the event channel is not the data channel"


async def test_data_channel_salt_carries_the_per_session_seed():
    """``DataStream-Salt`` is only half the salt; the seed makes it per-session.

    The seed also goes out in the SETUP body, and the receiver derives from
    the same pair -- so sending one seed and salting with another yields a
    channel neither side can read.  This pins them to the same value.
    """
    session = _session()
    setup_channel, transport, protocol = await _run(
        session, "_setup_data_channel", {"streams": [{"dataPort": 50000}]}
    )

    (factory, _, address, port, salt, output, input_), _ = setup_channel.call_args
    assert factory is DataStreamChannel
    assert (address, port) == ("10.0.0.2", 50000)
    assert output == ap2_session.DATASTREAM_OUTPUT_INFO
    assert input_ == ap2_session.DATASTREAM_INPUT_INFO

    sent_seed = session.rtsp.setup.call_args.kwargs["body"]["streams"][0]["seed"]
    assert salt == ap2_session.DATASTREAM_SALT + str(sent_seed)

    assert transport in session._channels  # noqa: SLF001
    assert session.data_channel is protocol, "data_channel was not published"


async def test_both_channels_refuse_to_run_before_verification():
    """Neither channel may be opened without a verifier -- there are no keys."""
    from pyatv import exceptions

    for name in ("_setup_event_channel", "_setup_data_channel"):
        session = _session()
        session.verifier = None
        with pytest.raises(exceptions.InvalidStateError, match="not in connected"):
            await getattr(session, name)("10.0.0.2")
