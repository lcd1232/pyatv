"""What the mirror package is allowed to put in a log record.

Structural checks over the whole package rather than over any one call site,
so a new offender has to be added to an allowlist deliberately.
"""

import ast
import pathlib

from pyatv.protocols.airplay.mirror import session


def test_no_log_above_debug_prints_raw_key_material():
    """Key material is logged at DEBUG, as everywhere else in pyatv.

    The mirror once logged the video key, its IV, the SRTP session key and
    salt, ``raw16`` and the pair-verify shared secret as hex at INFO -- six
    sites.  pyatv's own convention is the opposite: ``mrp/pairing.py`` and
    ``companion/protocol.py`` log credentials at DEBUG and nothing above it.
    INFO is a level users routinely enable, and logs get pasted into issue
    reports.

    Rather than pin those six call sites, this checks the property: no
    ``_LOGGER`` call above DEBUG in the package may pass a ``.hex()`` value.
    Two are allowed, and neither carries a secret -- see ``ALLOWED``.  A new
    one has to be added here deliberately, which is the point.
    """
    package = pathlib.Path(session.__file__).parent
    #: (module, format string) pairs whose hex payload is not key material.
    allowed = {
        # Bytes the receiver pushed back on the raw video channel; unexpected,
        # so worth surfacing, and it is inbound protocol data, not a secret.
        ("airparrot_stream.py", "raw video channel got %d inbound bytes: %s"),
        # A device_tag mismatch is a real anomaly, and the tag travels in M4
        # in the clear anyway.
        ("fply.py", "M4 echoes device_tag %s, we sent %s"),
    }

    offenders = []
    for path in sorted(package.rglob("*.py")):
        if "_saphash_systemcrash" in str(path):
            continue  # vendored, and off every code path
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "_LOGGER"
                and node.func.attr in ("info", "warning", "error", "critical")
            ):
                continue
            if not any(
                isinstance(arg, ast.Call)
                and isinstance(arg.func, ast.Attribute)
                and arg.func.attr == "hex"
                for arg in node.args[1:]
            ):
                continue
            fmt = node.args[0].value if isinstance(node.args[0], ast.Constant) else ""
            if (path.name, fmt) not in allowed:
                offenders.append(
                    f"{path.name}:{node.lineno} {node.func.attr}() {fmt!r}"
                )

    assert not offenders, "hex payload logged above DEBUG:\n  " + "\n  ".join(offenders)
