"""End-to-end scan orchestration: discover -> parse -> name-check -> confusion ->
build-hook review -> one :class:`~squatwatch.models.ScanResult`."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from pathlib import Path

from squatwatch.checker import NameChecker, NameVerdict
from squatwatch.config import Config
from squatwatch.confusion import ConfusionChecker
from squatwatch.hooks.review import review_path, review_tree
from squatwatch.hooks.tree import DirectoryTree, is_archive
from squatwatch.models import (
    Dependency,
    DependencyKind,
    Ecosystem,
    Finding,
    Location,
    ScanResult,
    Severity,
    SourceType,
)
from squatwatch.names import is_valid_name, match_key
from squatwatch.parsers import ParsedManifest, discover, parse_file
from squatwatch.popular import PopularIndex
from squatwatch.registry import RegistryClient
from squatwatch.text.homoglyph import inspect_glyphs

log = logging.getLogger(__name__)

_HOOK_MANIFESTS = frozenset({"setup.py", "pyproject.toml", "package.json"})


#: Score bands. 0.75 is where the dev-split false-positive rate falls to about
#: 0.1% (see the sweep in eval/RESULTS.md), so findings above it gate CI by default.
HIGH_SCORE = 0.75
MEDIUM_SCORE = 0.65


def severity_for_score(score: float) -> Severity:
    """Map a typosquat score to a severity band."""
    if score >= HIGH_SCORE:
        return Severity.HIGH
    if score >= MEDIUM_SCORE:
        return Severity.MEDIUM
    return Severity.LOW


def verdict_finding(verdict: NameVerdict, location: Location | None, also: int = 0) -> Finding:
    """Render a name verdict as a finding."""
    target = verdict.target
    details = "; ".join(s.detail for s in verdict.signals)
    extra = f" (declared in {also + 1} places)" if also else ""
    return Finding(
        rule=verdict.primary.rule,
        severity=severity_for_score(verdict.score),
        title=f"possible typosquat of {target.name}",
        message=(
            f"{verdict.name!r} resembles popular {verdict.ecosystem} package {target.name!r} "
            f"(popularity rank {target.rank}): {details}{extra}"
        ),
        location=location,
        package=verdict.name,
        ecosystem=verdict.ecosystem,
        score=verdict.score,
        evidence={
            "target": target.name,
            "target_rank": target.rank,
            "techniques": list(verdict.techniques),
            "signals": [s.detail for s in verdict.signals],
        },
    )


class Scanner:
    """Runs every check configured in :class:`Config` over files and archives."""

    def __init__(
        self,
        config: Config | None = None,
        *,
        registry: RegistryClient | None = None,
        indexes: dict[Ecosystem, PopularIndex] | None = None,
    ) -> None:
        self.config = config or Config()
        self.registry = registry
        self._indexes = indexes or {}
        self._checkers: dict[Ecosystem, NameChecker] = {}

    def checker(self, ecosystem: Ecosystem) -> NameChecker:
        """The (lazily built) name checker for an ecosystem."""
        if ecosystem not in self._checkers:
            index = self._indexes.get(ecosystem) or PopularIndex.bundled(ecosystem)
            self._checkers[ecosystem] = NameChecker(index, self.config.checker_settings(ecosystem))
        return self._checkers[ecosystem]

    # ------------------------------------------------------------------ scan

    def scan(self, paths: Sequence[Path]) -> ScanResult:
        """Scan files, directories and archives."""
        result = ScanResult()
        manifests: list[ParsedManifest] = []
        hook_dirs: list[Path] = []
        for path in paths:
            if not path.exists():
                result.errors.append(f"{path}: no such file or directory")
            elif is_archive(path):
                archive = review_path(path, third_party=True)
                result.extend(archive)
            elif path.is_dir():
                for file in discover(path):
                    self._parse(file, manifests, result)
                    if file.name in _HOOK_MANIFESTS and file.parent not in hook_dirs:
                        hook_dirs.append(file.parent)
            elif not self._parse(path, manifests, result):
                result.errors.append(f"{path}: not a supported manifest, lockfile or archive")
            elif path.name in _HOOK_MANIFESTS and path.parent not in hook_dirs:
                hook_dirs.append(path.parent)

        result.dependencies.extend(d for m in manifests for d in m.dependencies)
        result.findings.extend(self.check_dependencies(result.dependencies))

        if manifests:
            confusion = ConfusionChecker(self.config.internal, self.registry)
            result.findings.extend(confusion.check(manifests))
            result.errors.extend(confusion.errors)

        if self.config.hooks:
            for directory in hook_dirs:
                reviewed = review_tree(DirectoryTree(directory), third_party=False)
                result.findings.extend(reviewed.findings)
        result.findings = _dedupe(result.findings)
        return result

    def _parse(self, path: Path, manifests: list[ParsedManifest], result: ScanResult) -> bool:
        manifest = parse_file(path)
        if manifest is None:
            return False
        manifests.append(manifest)
        result.files.append(str(path))
        result.errors.extend(manifest.errors)
        return True

    # ----------------------------------------------------------- name checks

    def check_dependencies(self, deps: Iterable[Dependency]) -> list[Finding]:
        """Typosquat and name-validity findings, one per unique registry name."""
        groups: dict[tuple[Ecosystem, str], list[Dependency]] = {}
        for dep in deps:
            if dep.source_type is not SourceType.REGISTRY:
                continue
            name = dep.registry_name
            if self.config.internal.is_internal(dep.ecosystem, name):
                continue
            groups.setdefault((dep.ecosystem, name), []).append(dep)
        findings: list[Finding] = []
        for (ecosystem, name), group in groups.items():
            ordered = sorted(group, key=lambda d: d.kind is DependencyKind.LOCKED)
            locations = list(dict.fromkeys(d.location for d in ordered))
            invalid = self._validity(ecosystem, name, locations[0])
            if invalid is not None:
                findings.append(invalid)
            verdict = self.checker(ecosystem).check(name)
            if verdict is not None:
                findings.append(verdict_finding(verdict, locations[0], also=len(locations) - 1))
        return findings

    def check_name(self, ecosystem: Ecosystem, name: str) -> list[Finding]:
        """Findings for a single name typed on the command line."""
        dep = Dependency(name=name, ecosystem=ecosystem, location=Location("<command line>"))
        return self.check_dependencies([dep])

    @staticmethod
    def _validity(ecosystem: Ecosystem, name: str, location: Location) -> Finding | None:
        if is_valid_name(name, ecosystem):
            return None
        glyphs = inspect_glyphs(name)
        if glyphs.non_ascii:
            chars = ", ".join(f"{c!r} (U+{ord(c):04X})" for c in glyphs.non_ascii)
            return Finding(
                rule="SW106",
                severity=Severity.HIGH,
                title="non-ASCII characters in package name",
                message=f"{name!r} contains {chars}; registries reject these, so the name "
                "is either mistyped or pointed at a mirror that accepts it",
                location=location,
                package=name,
                ecosystem=ecosystem,
                evidence={"scripts": list(glyphs.scripts)},
            )
        return Finding(
            rule="SW106",
            severity=Severity.MEDIUM,
            title="invalid package name",
            message=f"{name!r} is not a valid {ecosystem} package name",
            location=location,
            package=name,
            ecosystem=ecosystem,
        )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str, int | None, str]] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=Finding.sort_key):
        loc = f.location
        key = (
            f.rule,
            match_key(f.package, f.ecosystem) if f.package and f.ecosystem else f.package,
            loc.path if loc else "",
            loc.line if loc else None,
            f.message,
        )
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
