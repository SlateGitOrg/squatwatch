"""Shared types for manifest and lockfile parsers."""

from __future__ import annotations

from dataclasses import dataclass, field

from squatwatch.models import Dependency, Ecosystem, Location


@dataclass(frozen=True, slots=True)
class IndexSetting:
    """A package index declared by a manifest or tool config.

    ``role`` is one of ``primary`` (replaces the default index), ``extra`` (merged
    with the default: the dependency-confusion-prone setting), ``explicit`` (only
    used for packages pinned to it), ``supplemental``/``secondary`` (Poetry) or
    ``scope`` (npm ``@scope:registry``).
    """

    url: str
    role: str
    location: Location
    scope: str | None = None


@dataclass(frozen=True, slots=True)
class BuildBackend:
    """``[build-system]`` table of a pyproject.toml."""

    backend: str | None
    backend_path: tuple[str, ...]
    requires: tuple[str, ...]
    location: Location


@dataclass(slots=True)
class ParsedManifest:
    """Everything a parser extracted from one file."""

    path: str
    ecosystem: Ecosystem
    dependencies: list[Dependency] = field(default_factory=list)
    indexes: list[IndexSetting] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    package_name: str | None = None
    build: BuildBackend | None = None
    errors: list[str] = field(default_factory=list)
    included: list[str] = field(default_factory=list)


class LineFinder:
    """Best-effort 1-based line lookup for formats whose parsers drop positions
    (``tomllib``, ``json``). Searches for the first line containing ``needle``,
    starting after a section header when one is given."""

    def __init__(self, text: str) -> None:
        self._lines = text.splitlines()

    def find(self, needle: str, *, after: str | None = None) -> int | None:
        start = 0
        if after is not None:
            for i, line in enumerate(self._lines):
                if after in line:
                    start = i
                    break
        for i in range(start, len(self._lines)):
            if needle in self._lines[i]:
                return i + 1
        return None
