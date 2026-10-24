"""Core data model shared by parsers, detectors and reporters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from squatwatch.errors import ConfigError


class Ecosystem(StrEnum):
    """Package ecosystems squatwatch understands."""

    PYPI = "pypi"
    NPM = "npm"


class Severity(IntEnum):
    """Ordered finding severity; CI gating compares these numerically."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> Severity:
        """Parse a case-insensitive severity name."""
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ConfigError(f"unknown severity {text!r} (expected one of: {names})") from exc

    @property
    def label(self) -> str:
        """Lower-case display name."""
        return self.name.lower()

    def lowered(self, steps: int = 1) -> Severity:
        """Return this severity reduced by ``steps`` levels (floored at INFO)."""
        return Severity(max(int(Severity.INFO), int(self) - steps))


class DependencyKind(StrEnum):
    """Where in a manifest a dependency was declared."""

    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    BUILD = "build"
    LOCKED = "locked"


class SourceType(StrEnum):
    """How a dependency is fetched. Only REGISTRY names are name-checked."""

    REGISTRY = "registry"
    URL = "url"
    GIT = "git"
    PATH = "path"
    WORKSPACE = "workspace"


@dataclass(frozen=True, slots=True)
class Location:
    """A position in an input file (1-based line, if known)."""

    path: str
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line is not None else self.path


@dataclass(frozen=True, slots=True)
class Dependency:
    """One declared or locked dependency.

    ``name`` is spelled exactly as written in the input (case and separators kept),
    because the raw spelling is evidence for homoglyph tricks.
    """

    name: str
    ecosystem: Ecosystem
    location: Location
    spec: str = ""
    kind: DependencyKind = DependencyKind.RUNTIME
    source_type: SourceType = SourceType.REGISTRY
    version: str | None = None
    resolved: str | None = None
    alias_of: str | None = None

    @property
    def registry_name(self) -> str:
        """The name that is actually fetched from the registry (alias target if any)."""
        return self.alias_of or self.name


@dataclass(frozen=True, slots=True)
class Finding:
    """A single reportable issue."""

    rule: str
    severity: Severity
    title: str
    message: str
    location: Location | None = None
    package: str | None = None
    ecosystem: Ecosystem | None = None
    score: float | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def sort_key(self) -> tuple[int, str, str, int, str]:
        """Most severe first, then by file, line, and rule."""
        loc = self.location
        return (
            -int(self.severity),
            loc.path if loc else "",
            self.package or "",
            (loc.line or 0) if loc else 0,
            self.rule,
        )


@dataclass(slots=True)
class ScanResult:
    """Aggregate output of a scan."""

    findings: list[Finding] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def extend(self, other: ScanResult) -> None:
        """Merge another result into this one."""
        self.findings.extend(other.findings)
        self.dependencies.extend(other.dependencies)
        self.files.extend(other.files)
        self.errors.extend(other.errors)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered most severe first, deterministically."""
        return sorted(self.findings, key=Finding.sort_key)

    def max_severity(self) -> Severity | None:
        """Highest severity present, or ``None`` with no findings."""
        return max((f.severity for f in self.findings), default=None)
