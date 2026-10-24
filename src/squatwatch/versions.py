"""Version ordering for PyPI (PEP 440, via ``packaging``) and npm (SemVer 2.0)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from packaging.version import InvalidVersion, Version

from squatwatch.models import Ecosystem

_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)

# Sort key: (major, minor, patch, is_release, prerelease identifiers)
SemverKey = tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]


def semver_key(text: str) -> SemverKey | None:
    """SemVer precedence key, or ``None`` if ``text`` is not a valid version.

    A release sorts after all of its pre-releases; numeric pre-release identifiers
    sort before alphanumeric ones and compare numerically (SemVer section 11).
    """
    m = _SEMVER.match(text.strip())
    if m is None:
        return None
    pre = m.group("pre")
    idents: tuple[tuple[int, int | str], ...] = ()
    if pre:
        idents = tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split("."))
    return (
        int(m.group("major")),
        int(m.group("minor")),
        int(m.group("patch")),
        0 if pre else 1,
        idents,
    )


def max_version(ecosystem: Ecosystem, versions: Iterable[str]) -> str | None:
    """Highest valid version in ``versions`` for the ecosystem's ordering."""
    best: str | None = None
    if ecosystem is Ecosystem.PYPI:
        best_v: Version | None = None
        for text in versions:
            try:
                v = Version(text)
            except InvalidVersion:
                continue
            if best_v is None or v > best_v:
                best_v, best = v, text
        return best
    best_k: SemverKey | None = None
    for text in versions:
        k = semver_key(text)
        if k is not None and (best_k is None or k > best_k):
            best_k, best = k, text
    return best


def is_newer(ecosystem: Ecosystem, candidate: str, baseline: str) -> bool | None:
    """Whether ``candidate`` > ``baseline``; ``None`` if either cannot be parsed."""
    if ecosystem is Ecosystem.PYPI:
        try:
            return Version(candidate) > Version(baseline)
        except InvalidVersion:
            return None
    a, b = semver_key(candidate), semver_key(baseline)
    if a is None or b is None:
        return None
    return a > b
