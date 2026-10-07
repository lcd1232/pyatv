"""Tests for the MFiSAP handshake state machine."""

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import pytest

from pyatv import exceptions
from pyatv.protocols.airplay.mirror import fairplay


def _x25519_keypair():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk


def test_build_m1_is_33_bytes_with_header_byte():
    h = fairplay.MFiSAPHandshake(header_byte=0x01)
    m1 = h.build_m1()
    assert len(m1) == 33
    assert m1[0] == 0x01


def test_build_m1_carries_a_usable_x25519_public_key():
    """M1 is a mode byte plus this handshake's own X25519 public key.

    X25519 has no point validation, so parsing the key proves only its length;
    a peer's shared secret against it must also equal ours against the peer's.
    """
    h = fairplay.MFiSAPHandshake()
    m1 = h.build_m1()
    assert len(m1) == 33, len(m1)
    advertised = x25519.X25519PublicKey.from_public_bytes(m1[1:])

    peer = x25519.X25519PrivateKey.generate()
    peer_pub = peer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    theirs = peer.exchange(advertised)
    ours = h._scalar_key.exchange(  # noqa: SLF001
        x25519.X25519PublicKey.from_public_bytes(peer_pub)
    )
    assert theirs == ours


def test_build_m1_twice_raises():
    h = fairplay.MFiSAPHandshake()
    h.build_m1()
    with pytest.raises(RuntimeError):
        h.build_m1()


def test_consume_m2_before_m1_raises():
    h = fairplay.MFiSAPHandshake()
    with pytest.raises(RuntimeError):
        h.consume_m2_build_m3(b"\x00" * 40)


def test_consume_m2_too_short_raises():
    h = fairplay.MFiSAPHandshake()
    h.build_m1()
    with pytest.raises(ValueError):
        h.consume_m2_build_m3(b"\x00" * 39)


def test_consume_m2_truncated_body_raises():
    h = fairplay.MFiSAPHandshake()
    h.build_m1()
    # Claim cert_len=10, sig_len=10 but provide no cert+sig bytes
    body = b"\x00" * 32 + struct.pack(">II", 10, 10)
    with pytest.raises(ValueError):
        h.consume_m2_build_m3(body)


def test_full_handshake_derives_correct_keys_and_returns_m3():
    """Drive the handshake against a synthetic server we control.

    Verifies that the AES key/IV follow the SHA1 derivation rule and that
    M3 = cert || AES-CTR(sig).
    """
    h = fairplay.MFiSAPHandshake(header_byte=0x01)
    m1 = h.build_m1()
    client_pubkey = x25519.X25519PublicKey.from_public_bytes(m1[1:])

    # Synthetic server side: ephemeral X25519, fixed cert + sig
    server_sk, server_pk = _x25519_keypair()
    cert = b"FAKE-CERT-BYTES-" * 4
    sig = b"FAKE-SIG-BYTES-" * 3

    m2 = server_pk + struct.pack(">II", len(cert), len(sig)) + cert + sig

    m3 = h.consume_m2_build_m3(m2)

    # Compute expected shared secret from the server's view
    shared_server = server_sk.exchange(client_pubkey)

    # Derive expected key/IV using the same SHA1 rule
    def sha1(data: bytes) -> bytes:
        d = hashes.Hash(hashes.SHA1())
        d.update(data)
        return d.finalize()

    expected_key = sha1(b"AES-KEY\x00" + shared_server)[:16]
    expected_iv = sha1(b"AES-IV\x00" + shared_server)[:16]

    assert h.aes_key == expected_key
    assert h.aes_iv == expected_iv

    # M3 layout: cert (unchanged) followed by encrypted sig
    assert m3[: len(cert)] == cert
    encrypted_sig = m3[len(cert) :]
    assert len(encrypted_sig) == len(sig)
    assert encrypted_sig != sig  # was actually encrypted

    # Decrypt with a fresh encryptor seeded the same way and verify match
    from pyatv.protocols.airplay.mirror import framing

    dec = framing.MirrorEncryptor.from_key_iv(expected_key, expected_iv)
    assert dec.encrypt(encrypted_sig) == sig


def test_stream_encryptor_state_continues_past_m3_sig():
    """After consume_m2_build_m3, stream_encryptor must continue the keystream."""
    h = fairplay.MFiSAPHandshake()
    h.build_m1()

    # Build a synthetic M2 with empty cert/sig (so M3 has empty encrypted_sig
    # and the stream encryptor starts at byte 0 of the keystream)
    server_sk, server_pk = _x25519_keypair()
    m2 = server_pk + struct.pack(">II", 0, 0)
    m3 = h.consume_m2_build_m3(m2)
    assert m3 == b""  # empty cert + empty encrypted_sig

    # Stream encryptor should now exist and produce non-zero output
    stream_enc = h.stream_encryptor
    out = stream_enc.encrypt(b"\x00" * 16)
    assert out != b"\x00" * 16


class _FakeHttpResponse:
    def __init__(self, code: int, body: bytes) -> None:
        self.code = code
        self.body = body
        self.headers = {}


class _FakeConnection:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    async def send_and_receive(self, method, uri, **kwargs):
        self.sent.append((method, uri, kwargs.get("body"), kwargs.get("content_type")))
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_run_handshake_posts_m1_and_m3_to_correct_endpoints():
    """run_handshake POSTs M1 to /fp-setup and M3 to /auth-setup."""
    server_sk, server_pk = _x25519_keypair()
    cert = b"CERT" * 4
    sig = b"SIG-" * 4
    m2 = server_pk + struct.pack(">II", len(cert), len(sig)) + cert + sig
    m4 = b""  # M4 is not parsed; receivers typically return it empty

    conn = _FakeConnection(
        [
            _FakeHttpResponse(200, m2),
            _FakeHttpResponse(200, m4),
        ]
    )

    sm = await fairplay.run_handshake(conn)

    assert len(conn.sent) == 2
    method1, uri1, body1, ct1 = conn.sent[0]
    assert method1 == "POST"
    assert uri1 == "/fp-setup"
    assert ct1 == "application/octet-stream"
    assert len(body1) == 33

    method2, uri2, body2, ct2 = conn.sent[1]
    assert method2 == "POST"
    assert uri2 == "/auth-setup"
    assert len(body2) == len(cert) + len(sig)

    # Returns a completed handshake state machine
    assert sm.aes_key is not None
    assert len(sm.aes_key) == 16


@pytest.mark.asyncio
async def test_run_handshake_raises_on_fp_setup_non_200():
    conn = _FakeConnection([_FakeHttpResponse(500, b"")])
    with pytest.raises(exceptions.ProtocolError):
        await fairplay.run_handshake(conn)


@pytest.mark.asyncio
async def test_run_handshake_raises_on_auth_setup_non_200():
    server_sk, server_pk = _x25519_keypair()
    m2 = server_pk + struct.pack(">II", 0, 0)
    conn = _FakeConnection(
        [
            _FakeHttpResponse(200, m2),
            _FakeHttpResponse(403, b""),
        ]
    )
    with pytest.raises(exceptions.ProtocolError):
        await fairplay.run_handshake(conn)


# The three properties below are the handshake's "have you finished?" guards.
# A caller that reads them early gets a RuntimeError instead of a None that
# would fail confusingly much later, in the middle of a mirror session.


def test_aes_key_before_handshake_is_refused():
    with pytest.raises(RuntimeError, match="handshake not complete"):
        _ = fairplay.MFiSAPHandshake().aes_key


def test_aes_iv_before_handshake_is_refused():
    with pytest.raises(RuntimeError, match="handshake not complete"):
        _ = fairplay.MFiSAPHandshake().aes_iv


def test_stream_encryptor_before_handshake_is_refused():
    with pytest.raises(RuntimeError, match="handshake not complete"):
        _ = fairplay.MFiSAPHandshake().stream_encryptor
