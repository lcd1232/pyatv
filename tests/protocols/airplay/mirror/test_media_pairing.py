"""Tests for the one-time media identity registration (PIN pairing)."""

import binascii
import hashlib
import plistlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest
from srptools import SRPServerSession, constants

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import ed25519_scalar
from pyatv.protocols.airplay.mirror.media_pairing import (
    CONNECTION_AUTHORIZATION_REQUIRED,
    MediaIdentity,
    register_media_identity,
)
from pyatv.protocols.airplay.srp import AtvSRPContext

PIN = "0427"  # a leading zero, which an int would lose


class _Response:
    def __init__(self, code, body=b""):
        self.code = code
        self.body = body


def _plist(**fields):
    return _Response(200, plistlib.dumps(fields, fmt=plistlib.FMT_BINARY))


class _FakeReceiver:
    """Receiver side of the registration, with a real SRP server.

    Mirrors what tvOS 27 was seen to do: the raw /pair-setup of an unknown
    key is answered 470, /pair-pin-start shows the PIN, and the three
    /pair-setup-pin steps run SRP-6a and then hand over the sender's ed25519
    public key, AES-GCM encrypted with the SRP session key.
    """

    def __init__(self, pin=PIN):
        self.pin = pin
        self.requests = []
        self.registered = set()
        self.pin_shown = 0
        self._srp = None
        self._salt = ""

    async def exchange(self, method, uri, content_type=None, body=None, **kwargs):
        assert kwargs.get("allow_error")
        self.requests.append((method, uri))
        if (method, uri) == ("GET", "/info"):
            return _Response(200)
        if uri == "/pair-setup":
            assert content_type == "application/octet-stream" and len(body) == 32
            if bytes(body) in self.registered:
                return _Response(200)
            return _Response(CONNECTION_AUTHORIZATION_REQUIRED)
        if uri == "/pair-pin-start":
            self.pin_shown += 1
            return _Response(200)
        assert uri == "/pair-setup-pin"
        fields = plistlib.loads(body)
        if "method" in fields:
            return self._step1(fields)
        if "proof" in fields:
            return self._step2(fields)
        return self._step3(fields)

    def _step1(self, fields):
        assert fields["method"] == "pin"
        if not self.pin_shown:
            return _Response(403)
        context = AtvSRPContext(
            fields["user"],
            self.pin,
            prime=constants.PRIME_2048,
            generator=constants.PRIME_2048_GEN,
        )
        _, verifier, self._salt = context.get_user_data_triplet()
        self._srp = SRPServerSession(
            AtvSRPContext(
                fields["user"],
                prime=constants.PRIME_2048,
                generator=constants.PRIME_2048_GEN,
            ),
            verifier,
        )
        return _plist(
            pk=binascii.unhexlify(self._srp.public), salt=binascii.unhexlify(self._salt)
        )

    def _step2(self, fields):
        self._srp.process(binascii.hexlify(fields["pk"]).decode(), self._salt)
        # srptools compares the proof as hex bytes, not str.
        if not self._srp.verify_proof(binascii.hexlify(fields["proof"])):
            return _Response(470)  # wrong PIN
        return _plist(proof=binascii.unhexlify(self._srp.key_proof_hash))

    def _step3(self, fields):
        key = binascii.unhexlify(self._srp.key)
        aes_key = hashlib.sha512(b"Pair-Setup-AES-Key" + key).digest()[:16]
        iv = bytearray(hashlib.sha512(b"Pair-Setup-AES-IV" + key).digest()[:16])
        iv[-1] += 1
        public = AESGCM(aes_key).decrypt(
            bytes(iv), fields["epk"] + fields["authTag"], None
        )
        self.registered.add(public)
        return _plist(epk=b"\x00" * 32, authTag=b"\x00" * 16)


async def _pin():
    return PIN


@pytest.mark.asyncio
async def test_registers_the_identity_after_the_pin():
    receiver = _FakeReceiver()
    identity = MediaIdentity.generate()

    await register_media_identity(receiver, identity, _pin)

    assert receiver.registered == {identity.public_key}
    assert receiver.requests == [
        ("GET", "/info"),
        ("POST", "/pair-setup"),
        ("POST", "/pair-pin-start"),
        ("POST", "/pair-pin-start"),
        ("POST", "/pair-setup-pin"),
        ("POST", "/pair-setup-pin"),
        ("POST", "/pair-setup-pin"),
    ]


@pytest.mark.asyncio
async def test_the_pin_is_asked_for_only_once_it_is_shown():
    receiver = _FakeReceiver()

    async def pin():
        assert receiver.pin_shown, "PIN asked for before the receiver showed it"
        return PIN

    await register_media_identity(receiver, MediaIdentity.generate(), pin)


@pytest.mark.asyncio
async def test_a_wrong_pin_is_refused_and_nothing_is_registered():
    receiver = _FakeReceiver()

    async def wrong():
        return "9999"

    with pytest.raises(exceptions.AuthenticationError, match="HTTP 470"):
        await register_media_identity(receiver, MediaIdentity.generate(), wrong)
    assert not receiver.registered


@pytest.mark.asyncio
async def test_a_non_numeric_pin_is_rejected_before_it_is_sent():
    async def bad():
        return "12a4"

    with pytest.raises(exceptions.AuthenticationError, match="digits"):
        await register_media_identity(_FakeReceiver(), MediaIdentity.generate(), bad)


def test_identity_round_trips_through_hex():
    identity = MediaIdentity.generate()
    assert MediaIdentity.from_hex(identity.to_hex()) == identity


def test_identity_rejects_a_short_seed():
    with pytest.raises(ValueError):
        MediaIdentity(b"\x00" * 31)


def test_identity_scalar_belongs_to_its_public_key():
    identity = MediaIdentity.generate()
    point = ed25519_scalar._scalarmult(  # pylint: disable=protected-access
        ed25519_scalar._B, int.from_bytes(identity.scalar, "little")
    )
    assert ed25519_scalar._encodepoint(point) == identity.public_key


def test_identity_user_is_stable_and_shaped_like_the_captured_one():
    identity = MediaIdentity.generate()
    assert identity.user == identity.user
    assert identity.user.startswith("0x") and len(identity.user) == 14
    int(identity.user, 16)
