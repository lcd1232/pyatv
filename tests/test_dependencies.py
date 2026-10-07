"""Every third-party module pyatv imports must be a declared dependency.

An import that is not in ``base_versions.txt`` works fine in a development
checkout -- the dev environment has far more installed than a user's -- and
fails with ``ImportError`` the first time somebody installs the wheel. No
other test can see that, because the whole suite runs against an environment
where everything is present.
"""

import ast
import pathlib
import sys

#: PyPI name -> the top-level module it actually installs, where they differ.
#: Only ``protobuf`` is genuinely surprising: it installs into ``google``.
_MODULE_OF = {"protobuf": "google"}


def _declared_modules() -> set:
    """Top-level module names provided by base_versions.txt."""
    modules = set()
    for line in pathlib.Path("base_versions.txt").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # "async-timeout==4.0.2;python_version<'3.11'" -> "async-timeout"
        name = line.split(";")[0].split("==")[0].split(">=")[0].split("<")[0].strip()
        if not name:
            continue
        modules.add(_MODULE_OF.get(name, name.replace("-", "_")))
    return modules


def _imported_modules() -> dict:
    """Third-party top-level imports in shipped pyatv code -> an example file."""
    stdlib = set(sys.stdlib_module_names)
    found: dict = {}
    for path in sorted(pathlib.Path("pyatv").rglob("*.py")):
        if "_saphash_systemcrash" in str(path):
            continue  # vendored, and no longer shipped -- see MANIFEST.in
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:  # pragma: no cover - would fail elsewhere first
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top not in stdlib and top != "pyatv":
                    found.setdefault(top, str(path))
    return found


def test_every_third_party_import_is_a_declared_dependency():
    """Nothing shipped may import a package a user would not have."""
    declared = _declared_modules()
    undeclared = {
        module: where
        for module, where in _imported_modules().items()
        if module not in declared
    }
    assert not undeclared, "not in base_versions.txt:\n  " + "\n  ".join(
        f"{module} (imported by {where})"
        for module, where in sorted(undeclared.items())
    )


def test_the_scan_actually_finds_the_known_dependencies():
    """Guard against the scan silently matching nothing.

    If the walk broke -- wrong root, parse failures swallowed -- the test
    above would pass by finding no imports at all. These are the ones pyatv
    cannot function without.
    """
    imported = _imported_modules()
    for module in ("aiohttp", "cryptography", "zeroconf", "protobuf"):
        expected = _MODULE_OF.get(module, module)
        assert expected in imported, f"{expected} not found by the import scan"
