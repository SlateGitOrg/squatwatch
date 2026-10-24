"""Dependency-confusion analysis.

Dependency confusion happens when a build that expects a package from a private
index can be served a same-named package from the public registry instead:
pip's ``--extra-index-url`` merges indexes and picks the highest version, an
npm package outside a scope mapped to the private registry resolves publicly,
and so on. squatwatch checks three things for every dependency the
:class:`InternalPolicy` marks as internal:

1. **Proof** (SW203): a lockfile shows the internal package was resolved from a
   public registry host.
2. **Exposure** (SW201/SW202): the name is already taken on the public registry
   (critical if its newest public version outranks the internal one) or is still
   unclaimed (anyone can register it).
3. **Configuration** (SW204-SW206): index settings that let a public package win
   (merged extra indexes, unmapped npm scopes, unscoped internal npm names).

Registry access goes through :class:`squatwatch.registry.RegistryClient`, so the
check runs offline against fixtures in tests and demos.
"""

from __future__ import annotations

import fnmatch
import logging
import urllib.parse
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from squatwatch.errors import RegistryError
from squatwatch.models import Dependency, Ecosystem, Finding, Location, Severity, SourceType
from squatwatch.names import match_key, split_scope
from squatwatch.parsers.base import ParsedManifest
from squatwatch.registry import RegistryClient
from squatwatch.versions import is_newer, max_version

log = logging.getLogger(__name__)

PUBLIC_HOSTS: frozenset[str] = frozenset(
    {
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "registry.npmjs.com",
        "registry.yarnpkg.com",
        "registry.npmmirror.com",
    }
)
_MERGING_ROLES = frozenset({"extra", "supplemental", "secondary"})


@dataclass(frozen=True, slots=True)
class InternalPolicy:
    """Which package names belong to the organisation (never public)."""

    names: frozenset[str] = frozenset()
    patterns: tuple[str, ...] = ()
    npm_scopes: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        """True when nothing is declared internal."""
        return not (self.names or self.patterns or self.npm_scopes)

    def is_internal(self, ecosystem: Ecosystem, name: str) -> bool:
        """Whether ``name`` is declared internal for ``ecosystem``."""
        key = match_key(name, ecosystem)
        if key in {match_key(n, ecosystem) for n in self.names}:
            return True
        if any(fnmatch.fnmatchcase(key, match_key(p, ecosystem)) for p in self.patterns):
            return True
        if ecosystem is Ecosystem.NPM:
            scope, _ = split_scope(key)
            return scope is not None and scope in {s.lower() for s in self.npm_scopes}
        return False


def host_of(url: str) -> str:
    """Lower-case host of ``url`` ('' if none)."""
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def is_public_url(url: str) -> bool:
    """Whether ``url`` points at a public registry host."""
    return host_of(url) in PUBLIC_HOSTS


@dataclass(slots=True)
class _Internal:
    ecosystem: Ecosystem
    name: str
    locations: list[Location] = field(default_factory=list)
    versions: list[str] = field(default_factory=list)


class ConfusionChecker:
    """Runs the dependency-confusion checks over parsed manifests."""

    def __init__(self, policy: InternalPolicy, client: RegistryClient | None = None) -> None:
        self.policy = policy
        self.client = client
        self.errors: list[str] = []

    def check(self, manifests: Sequence[ParsedManifest]) -> list[Finding]:
        """All confusion findings for the given manifests."""
        findings: list[Finding] = []
        deps = [d for m in manifests for d in m.dependencies]
        internal = self._internal_deps(deps)
        findings.extend(self._resolved_publicly(deps))
        if self.client is not None:
            for item in internal.values():
                findings.extend(self._exposure(self.client, item))
        findings.extend(self._index_config(manifests, internal))
        return findings

    def _internal_deps(self, deps: Iterable[Dependency]) -> dict[tuple[Ecosystem, str], _Internal]:
        out: dict[tuple[Ecosystem, str], _Internal] = {}
        for dep in deps:
            name = dep.registry_name
            if dep.source_type is not SourceType.REGISTRY:
                continue
            if not self.policy.is_internal(dep.ecosystem, name):
                continue
            key = (dep.ecosystem, match_key(name, dep.ecosystem))
            item = out.setdefault(key, _Internal(dep.ecosystem, name))
            item.locations.append(dep.location)
            if dep.version:
                item.versions.append(dep.version)
        return out

    def _resolved_publicly(self, deps: Iterable[Dependency]) -> Iterable[Finding]:
        for dep in deps:
            if dep.resolved is None or not self.policy.is_internal(
                dep.ecosystem, dep.registry_name
            ):
                continue
            if is_public_url(dep.resolved):
                yield Finding(
                    rule="SW203",
                    severity=Severity.CRITICAL,
                    title="internal package resolved from a public registry",
                    message=(
                        f"{dep.registry_name} is declared internal but the lockfile resolved it "
                        f"from {host_of(dep.resolved)}; the installed artifact may be an "
                        "attacker's public package"
                    ),
                    location=dep.location,
                    package=dep.registry_name,
                    ecosystem=dep.ecosystem,
                    evidence={"resolved": dep.resolved, "version": dep.version},
                )

    def _exposure(self, client: RegistryClient, item: _Internal) -> Iterable[Finding]:
        try:
            record = client.lookup(item.ecosystem, item.name)
        except RegistryError as exc:
            self.errors.append(f"registry lookup for {item.name}: {exc}")
            return
        location = item.locations[0]
        internal_version = max_version(item.ecosystem, item.versions)
        if not record.exists:
            yield Finding(
                rule="SW202",
                severity=Severity.MEDIUM,
                title="internal package name is unclaimed on the public registry",
                message=(
                    f"{item.name} does not exist on the public {item.ecosystem} registry; "
                    "anyone can register it. Reserve the name or pin the private index."
                ),
                location=location,
                package=item.name,
                ecosystem=item.ecosystem,
            )
            return
        latest = record.latest
        outranks = (
            latest is None
            or internal_version is None
            or is_newer(item.ecosystem, latest, internal_version) is not False
        )
        severity = Severity.CRITICAL if outranks else Severity.HIGH
        why = (
            f"public latest {latest} outranks internal {internal_version or 'unpinned'}"
            if outranks
            else f"public latest {latest} is below internal {internal_version} today"
        )
        yield Finding(
            rule="SW201",
            severity=severity,
            title="internal package name exists on the public registry",
            message=(
                f"{item.name} is declared internal but a public package of that name "
                f"exists ({why}); a resolver that consults the public index may install it"
            ),
            location=location,
            package=item.name,
            ecosystem=item.ecosystem,
            evidence={
                "public_versions": list(record.versions[-10:]),
                "public_latest": latest,
                "internal_version": internal_version,
            },
        )

    def _index_config(
        self,
        manifests: Sequence[ParsedManifest],
        internal: dict[tuple[Ecosystem, str], _Internal],
    ) -> Iterable[Finding]:
        has_internal_pypi = any(eco is Ecosystem.PYPI for eco, _ in internal)
        for manifest in manifests:
            if manifest.ecosystem is not Ecosystem.PYPI:
                continue
            for idx in manifest.indexes:
                if idx.role not in _MERGING_ROLES:
                    continue
                severity = Severity.HIGH if has_internal_pypi else Severity.MEDIUM
                yield Finding(
                    rule="SW204",
                    severity=severity,
                    title="package indexes are merged (dependency-confusion prone)",
                    message=(
                        f"index {idx.url} is consulted alongside the default index "
                        f"(role {idx.role!r}); pip-style resolvers take the highest version "
                        "from any index, so a public package can shadow a private one. Use a "
                        "single proxying index or uv's first-index strategy."
                    ),
                    location=idx.location,
                    evidence={"url": idx.url, "role": idx.role},
                )

        scope_maps = {
            (idx.scope or "").lower()
            for m in manifests
            for idx in m.indexes
            if m.ecosystem is Ecosystem.NPM and idx.role == "scope"
        }
        reported_scopes: set[str] = set()
        for (eco, key), item in sorted(internal.items(), key=lambda kv: kv[0][1]):
            if eco is not Ecosystem.NPM:
                continue
            scope, _ = split_scope(key)
            if scope is None:
                yield Finding(
                    rule="SW206",
                    severity=Severity.LOW,
                    title="internal npm package is unscoped",
                    message=(
                        f"{item.name} has no scope, so no .npmrc scope mapping can pin it to "
                        "the private registry; publish internal packages under an owned scope"
                    ),
                    location=item.locations[0],
                    package=item.name,
                    ecosystem=eco,
                )
            elif scope not in scope_maps and scope not in reported_scopes:
                reported_scopes.add(scope)
                yield Finding(
                    rule="SW205",
                    severity=Severity.MEDIUM,
                    title="internal npm scope is not mapped to a private registry",
                    message=(
                        f"no .npmrc maps {scope}:registry=..., so packages such as {item.name} "
                        "resolve from the default registry"
                    ),
                    location=item.locations[0],
                    package=item.name,
                    ecosystem=eco,
                    evidence={"scope": scope},
                )
