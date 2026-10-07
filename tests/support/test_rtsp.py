"""Behaviour of :class:`pyatv.support.rtsp.RtspSession` around auth errors.

``announce`` passes ``allow_error=True`` whenever a password is configured.
It does that to handle the 401 digest challenge itself -- but ``allow_error``
suppresses every error status, and its only caller discards the response, so
a refusal has to be turned back into an exception here or it vanishes.
"""

from unittest.mock import MagicMock

import pytest

from pyatv import exceptions
from pyatv.support.http import HttpResponse
from pyatv.support.rtsp import RtspSession

pytestmark = pytest.mark.asyncio


def _session():
    connection = MagicMock()
    connection.local_ip = "10.0.0.1"
    connection.remote_ip = "10.0.0.2"
    return RtspSession(connection)


def _response(code: int, headers=None):
    return HttpResponse("RTSP/1.0", "RTSP/1.0", code, "Reason", headers or {}, b"")


async def _announce(session, password):
    return await session.announce(2, 2, 44100, password=password)


async def test_announce_raises_on_403_when_a_password_is_configured(monkeypatch):
    """A refused ANNOUNCE must not look like a successful one.

    ``HttpConnection`` raises ``AuthenticationError`` on 403 -- unless the
    caller passed ``allow_error``, which ``announce`` does whenever a
    password is set. ``airplayv1`` then throws the response away, so without
    this guard a receiver that refuses the stream outright is
    indistinguishable from one that accepted it, and the real failure
    surfaces much later as something unrelated.
    """
    session = _session()

    async def fake(self, method, **kwargs):
        return _response(403)

    monkeypatch.setattr(RtspSession, "exchange", fake)

    with pytest.raises(exceptions.AuthenticationError, match="not authenticated"):
        await _announce(session, "hunter2")


async def test_announce_returns_403_untouched_when_no_password_is_set(monkeypatch):
    """Without a password ``allow_error`` is False, so the raise is HTTP's job.

    This is the half that must NOT change: the guard is scoped to the case
    that opted into swallowing errors, so an unauthenticated session still
    gets its exception from ``HttpConnection`` exactly as before.
    """
    session = _session()
    seen = {}

    async def fake(self, method, **kwargs):
        seen["allow_error"] = kwargs.get("allow_error")
        return _response(200)

    monkeypatch.setattr(RtspSession, "exchange", fake)

    await _announce(session, None)
    assert seen["allow_error"] is False


async def test_announce_still_answers_the_401_digest_challenge(monkeypatch):
    """401 keeps flowing into the digest retry, which is why allow_error is on.

    The 403 guard must not intercept this: a 401 with a ``WWW-Authenticate``
    header is a challenge to answer, not a refusal, and answering it is the
    whole reason ``announce`` tolerates errors in the first place.
    """
    session = _session()
    codes = [
        _response(401, {"www-authenticate": 'Digest realm="raop", nonce="abc"'}),
        _response(200),
    ]
    calls = []

    async def fake(self, method, **kwargs):
        calls.append(kwargs.get("allow_error"))
        return codes.pop(0)

    monkeypatch.setattr(RtspSession, "exchange", fake)

    response = await _announce(session, "hunter2")

    assert response.code == 200, "the retry after the digest challenge did not run"
    assert len(calls) == 2, "announce did not retry after the 401"
    assert session.digest_info is not None
    assert session.digest_info.realm == "raop"
    assert session.digest_info.nonce == "abc"


async def test_a_plist_body_is_sent_as_rtsp_with_the_apple_content_type(monkeypatch):
    """The request line and the body's content type are both protocol.

    ``exchange`` sends ``RTSP/1.0`` and labels a dict body
    ``application/x-apple-binary-plist``.  A receiver parses on both: the
    version decides whether it treats the request as RTSP at all, and the
    content type decides whether it tries to decode the body as a plist.

    Neither was checked anywhere in the suite -- changing the version to
    ``HTTP/1.1``, or the content type to something else, passed all 1741
    tests.  They have no local effect to observe, so only what is handed to
    the transport shows them.
    """
    session = _session()
    captured: dict = {}

    async def fake_send(method, uri, **kwargs):
        captured.update(kwargs)
        captured["method"] = method
        # exchange() matches the reply to its request by CSeq and waits on an
        # event until one arrives; a response without it times out rather
        # than failing, which says nothing about the headers under test.
        return _response(200, {"CSeq": kwargs["headers"]["CSeq"]})

    session.connection.send_and_receive = fake_send

    await session.exchange("SETUP", body={"streams": []})

    assert captured["protocol"] == "RTSP/1.0", captured["protocol"]
    # A dict body is labelled through the Content-Type *header*, not the
    # content_type argument, which stays None on this path.
    assert (
        captured["headers"]["Content-Type"] == "application/x-apple-binary-plist"
    ), captured["headers"]
