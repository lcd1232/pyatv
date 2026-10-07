"""Compute the 20-byte device_tag the receiver checks at ``M3[144:164]``.

Only the tail ``sap36[16:36]`` of the SAP secret reaches the tag.  The
algorithm itself lives in ``fply_md5`` and ``fply_pure``:

    A      = [MD5(KEY_BASE, secret^0x0d || r || SALT) for r in 0..8]
    X      = forward(CONSTANT_BLOCK, A)          one AES-shaped network
    init   = MD5(LINK_IV, X || LINK_SALT)
    out    = backward(init, A reversed) ^ FINAL_XOR
    tag    = out[:4] || MD5(LINK_IV, init || out)

That is nine modified MD5 compressions for the key schedule, a ten-round
block cipher run forwards over a fixed block and backwards over the link's
output, and two more compressions.  The MD5 is standard except that step
31 shuffles the message block with the state; the cipher's 320
substitution tables reduce to six plus a (class, in-xor, out-xor) triple
per step.
"""

from . import fply_pure

__all__ = ["device_tag", "SAP_LENGTH", "TAG_LENGTH", "TAG_HALF"]

SAP_LENGTH = 36
TAG_LENGTH = 20
# the only part of the secret the tag depends on
TAG_HALF = slice(16, 36)


def device_tag(sap36: bytes) -> bytes:
    """Return the 20-byte device_tag for the whole 36-byte SAP secret.

    ``sap36[0:16]`` is accepted and ignored; only the tail reaches the tag.
    """
    if len(sap36) != SAP_LENGTH:
        raise ValueError(f"sap36 is {len(sap36)} bytes, not {SAP_LENGTH}")
    return fply_pure.device_tag(bytes(sap36[TAG_HALF]))
