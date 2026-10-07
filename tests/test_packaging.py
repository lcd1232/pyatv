"""What the wheel and sdist carry, which no other test looks at.

``_saphash_systemcrash`` is derived from GPLv2 code and pyatv is MIT, so
shipping it would distribute GPL-derived sources inside an MIT distribution
without the corresponding licence. Nothing imports it at runtime; only a
source-tree test reads it.

Two independent settings exclude it and either alone is not enough:
``packages.find`` in ``pyproject.toml`` keeps it out of the wheel, and
``prune`` in ``MANIFEST.in`` keeps it out of the sdist -- setuptools
otherwise re-adds package data the first has already dropped. Removing
either is a one-line edit that no other test in this suite would notice,
and the consequence is a licence violation rather than a broken build.
"""

import pathlib
import re

import pytest

_GPL_PACKAGE = "pyatv.protocols.airplay.mirror._saphash_systemcrash"
_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _configured_exclude() -> list:
    """The exclude globs ``[tool.setuptools.packages.find]`` actually declares.

    Read as text rather than parsed: ``tomllib`` is 3.11+, pyatv supports
    3.9, and a test that silently skips on the older interpreters is not a
    guard. The shape being matched is stable and lives four lines from the
    comment explaining why it exists.
    """
    body = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    section = body.split("[tool.setuptools.packages.find]", 1)[1]
    section = section.split("\n[", 1)[0]
    match = re.search(r"^exclude\s*=\s*\[(.*?)\]", section, re.S | re.M)
    assert match, "packages.find declares no exclude at all"
    return re.findall(r'"([^"]+)"', match.group(1))


def test_the_gpl_tree_is_named_in_the_exclude():
    """The glob itself, which needs nothing installed to check.

    ``setuptools`` is declared as a BUILD requirement, not a test one, and
    a virtualenv on 3.12+ does not carry it. The discovery check below skips
    without it, so this one asserts the configuration directly and always
    runs -- a guard that can skip is not the only guard here.
    """
    assert _GPL_PACKAGE + "*" in _configured_exclude()


def test_the_gpl_tree_is_not_a_discovered_package():
    """And setuptools' own discovery agrees, where setuptools exists."""
    find_packages = pytest.importorskip(
        "setuptools", reason="setuptools is a build requirement, not a test one"
    ).find_packages
    excluded = _configured_exclude()
    found = find_packages(where=str(_ROOT), include=["pyatv*"], exclude=excluded)

    assert _GPL_PACKAGE not in found, "%s is still discovered with exclude=%s" % (
        _GPL_PACKAGE,
        excluded,
    )
    # The exclusion has to be narrow: dropping the mirror package instead
    # would also pass the assertion above and ship nothing that works.
    assert "pyatv.protocols.airplay.mirror" in found, "the mirror package went too"
    assert "pyatv.protocols.airplay.mirror.fairplay_sap" in found


def test_the_sdist_prunes_the_gpl_tree():
    """``MANIFEST.in`` covers the sdist, which ``packages.find`` does not."""
    manifest = (_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    pruned = re.findall(r"^prune\s+(\S+)", manifest, re.M)
    wanted = "pyatv/protocols/airplay/mirror/_saphash_systemcrash"
    assert wanted in pruned, "MANIFEST.in no longer prunes %s: %s" % (wanted, pruned)


def test_the_tree_is_still_there_to_exclude():
    """A guard that passes because the subject vanished is not a guard."""
    assert (_ROOT / "pyatv/protocols/airplay/mirror/_saphash_systemcrash").is_dir()
