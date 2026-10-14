"""What the mirror package is allowed to put in a log record."""

import ast
import pathlib

from pyatv.protocols.airplay.mirror import session


def test_no_log_above_debug_prints_raw_key_material():
    """No ``_LOGGER`` call above DEBUG in the package passes a ``.hex()`` value.

    Key material may only be logged at DEBUG, as elsewhere in pyatv: INFO is
    commonly enabled and logs end up in issue reports. Exceptions must be
    added to ``allowed`` explicitly.
    """
    package = pathlib.Path(session.__file__).parent
    #: (module, format string) pairs whose hex payload is not key material.
    allowed = {
        # Bytes the receiver pushed back on the raw video channel; unexpected,
        # so worth surfacing, and it is inbound protocol data, not a secret.
        ("tcp_stream.py", "raw video channel got %d inbound bytes: %s"),
        # A device_tag mismatch is a real anomaly, and the tag travels in M4
        # in the clear anyway.
        ("fply.py", "M4 echoes device_tag %s, we sent %s"),
    }

    offenders = []
    for path in sorted(package.rglob("*.py")):
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
