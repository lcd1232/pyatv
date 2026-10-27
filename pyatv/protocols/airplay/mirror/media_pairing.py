"""Media identity registration (one-time PIN pairing) for the mirror sender.

The receiver only accepts a media pair-verify (:mod:`.media_pair_verify`)
signed by an ed25519 identity it has registered, and registers one through
this PIN pairing (as seen on an Apple TV with tvOS 27):

    GET  /info
    POST /pair-setup      raw 32-byte public key  -> 470 (authorization needed)
    POST /pair-pin-start  (twice)                 -> the receiver shows a PIN
    POST /pair-setup-pin  {method: pin, user}     -> {pk, salt}      SRP step 1
    POST /pair-setup-pin  {pk, proof}             -> {proof}         SRP step 2
    POST /pair-setup-pin  {epk, authTag}          -> {epk, authTag}  key exchange

All of it goes over the connection's RTSP session. The SRP exchange is
pyatv's legacy AirPlay one (:class:`~pyatv.protocols.airplay.srp.LegacySRPAuthHandler`);
sent as plain HTTP, or without the preceding requests, the receiver answers
403. After the last step the identity's public key is registered and the
media pair-verify accepts it on any later connection.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
import hashlib
import logging
import os
import plistlib
from typing import Awaitable, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pyatv import exceptions
from pyatv.auth.hap_pairing import HapCredentials
from pyatv.protocols.airplay.srp import LegacySRPAuthHandler
from pyatv.support.http import decode_bplist_from_body
from pyatv.support.rtsp import RtspSession

_LOGGER = logging.getLogger(__name__)

_PLIST = "application/x-apple-binary-plist"

#: Status of the raw /pair-setup for an identity that is not registered yet.
CONNECTION_AUTHORIZATION_REQUIRED = 470

#: Length of an ed25519 seed.
SEED_LENGTH = 32

#: How many PINs one registration takes before giving up.
PIN_ATTEMPTS = 3


@dataclass(frozen=True)
class MediaIdentity:
    """The ed25519 identity a sender signs the media pair-verify with.

    Only the 32-byte seed is secret; keep it private, since anyone holding it
    can mirror to every receiver it is registered with.
    """

    seed: bytes

    def __post_init__(self) -> None:
        """Reject a seed of the wrong length."""
        if len(self.seed) != SEED_LENGTH:
            raise ValueError(f"seed must be {SEED_LENGTH} bytes, got {len(self.seed)}")

    @classmethod
    def generate(cls) -> "MediaIdentity":
        """Return a new random identity."""
        return cls(os.urandom(SEED_LENGTH))

    @classmethod
    def from_hex(cls, text: str) -> "MediaIdentity":
        """Return the identity whose seed is the hex string *text*."""
        return cls(bytes.fromhex(text.strip()))

    def to_hex(self) -> str:
        """Return the seed as hex, for storing the identity."""
        return self.seed.hex()

    @property
    def public_key(self) -> bytes:
        """Return the 32-byte ed25519 public key the receiver registers."""
        return (
            Ed25519PrivateKey.from_private_bytes(self.seed)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )

    @property
    def user(self) -> str:
        """Return the SRP user name, ``0x`` plus 12 hex digits of the key.

        The receiver takes any such name; deriving it keeps it stable.
        """
        return "0x" + hashlib.sha256(self.public_key).hexdigest()[:12]


async def register_media_identity(
    rtsp: RtspSession,
    identity: MediaIdentity,
    pin: Callable[[], Awaitable[str]],
    user: Optional[str] = None,
) -> None:
    """Register *identity* with the receiver, asking *pin* for the PIN it shows.

    *pin* is awaited after the receiver has been asked to show the PIN and
    returns it as a string of digits; leading zeros matter, so not an int.
    After a wrong PIN it is awaited again, up to :data:`PIN_ATTEMPTS` times.
    Raises :class:`~pyatv.exceptions.AuthenticationError` if the receiver
    refuses a step, or every PIN. Registering an identity that is registered
    already is harmless.
    """
    user = user or identity.user
    # The handler takes the seed as "legacy" credentials, which also need a
    # client id; this flow never sends it, so any stable value does.
    client_id = hashlib.sha256(identity.public_key).digest()[:8]
    srp = LegacySRPAuthHandler(HapCredentials(b"", identity.seed, b"", client_id))
    srp.initialize()

    async def post(uri: str, content_type: str, body: bytes):
        return await rtsp.exchange(
            "POST", uri, content_type=content_type, body=body, allow_error=True
        )

    async def post_pin(**fields):
        binary = plistlib.FMT_BINARY  # pylint: disable=no-member
        return await post("/pair-setup-pin", _PLIST, plistlib.dumps(fields, fmt=binary))

    async def setup_pin(**fields):
        resp = await post_pin(**fields)
        if resp.code != 200:
            raise exceptions.AuthenticationError(
                f"media pairing step {sorted(fields)} returned HTTP {resp.code}"
            )
        return decode_bplist_from_body(resp)

    await rtsp.exchange("GET", "/info", allow_error=True)
    resp = await post("/pair-setup", "application/octet-stream", identity.public_key)
    if resp.code not in (200, CONNECTION_AUTHORIZATION_REQUIRED):
        raise exceptions.AuthenticationError(
            f"media pairing /pair-setup returned HTTP {resp.code}"
        )
    # The receiver asks for authorization (470) and then shows a PIN. The
    # PIN is started twice; that is the tested sequence.
    for _ in range(2):
        resp = await post("/pair-pin-start", _PLIST, b"")
        if resp.code != 200:
            raise exceptions.AuthenticationError(
                f"media pairing /pair-pin-start returned HTTP {resp.code}"
            )

    # SRP step 1 needs no PIN, so it is sent before asking for one: the PIN
    # session is short-lived, and the PIN can take a while to be typed.
    first: Optional[dict] = await setup_pin(method="pin", user=user)
    for _ in range(PIN_ATTEMPTS):
        code = str(await pin()).strip()
        if not code.isdigit():
            raise exceptions.AuthenticationError(f"PIN must be digits, got {code!r}")
        if first is None:
            first = await setup_pin(method="pin", user=user)
        srp.step1(user, code)
        client_pk, proof = srp.step2(first["pk"], first["salt"])
        # A refused proof ends the receiver's SRP session; a retry starts over.
        first = None
        resp = await post_pin(
            pk=binascii.unhexlify(client_pk), proof=binascii.unhexlify(proof)
        )
        if resp.code == 200:
            break
        _LOGGER.debug("Media pairing PIN refused with HTTP %d", resp.code)
    else:
        raise exceptions.AuthenticationError(
            f"media pairing PIN refused {PIN_ATTEMPTS} times (HTTP {resp.code})"
        )
    epk, tag = srp.step3()
    await setup_pin(epk=epk, authTag=tag)
    _LOGGER.debug("Media identity %s registered", identity.public_key.hex()[:12])
