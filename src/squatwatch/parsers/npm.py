"""npm manifests and lockfiles: ``package.json``, ``package-lock.json`` /
``npm-shrinkwrap.json`` (lockfile v1, v2, v3), ``yarn.lock`` (classic v1 and
Berry) and ``.npmrc`` registry settings."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, SourceType
from squatwatch.parsers.base import IndexSetting, LineFinder, ParsedManifest

_DEP_FIELDS: tuple[tuple[str, DependencyKind], ...] = (
    ("dependencies", DependencyKind.RUNTIME),
    ("devDependencies", DependencyKind.DEV),
    ("optionalDependencies", DependencyKind.OPTIONAL),
    ("peerDependencies", DependencyKind.PEER),
)
_GITHUB_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$")


def split_name_spec(text: str) -> tuple[str, str]:
    """Split ``name@spec`` where ``name`` may itself start with ``@scope/``."""
    at = text.find("@", 1)
    if at == -1:
        return text, ""
    return text[:at], text[at + 1 :]


def classify_spec(spec: str) -> tuple[SourceType, str | None]:
    """Classify a package.json version spec; returns (source type, alias target)."""
    if spec.startswith("npm:"):
        target, _ = split_name_spec(spec[4:])
        return SourceType.REGISTRY, target
    if spec.startswith("workspace:"):
        return SourceType.WORKSPACE, None
    if spec.startswith(("file:", "link:", "./", "../", "/", "~/")):
        return SourceType.PATH, None
    if spec.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:")):
        return SourceType.GIT, None
    if spec.startswith(("http://", "https://")):
        return SourceType.URL, None
    if _GITHUB_SHORTHAND.match(spec) and not spec.startswith("@"):
        return SourceType.GIT, None
    return SourceType.REGISTRY, None


def _load_json(path: Path, result: ParsedManifest) -> tuple[dict[str, Any], LineFinder] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
        return None
    return _json_text(text, str(path), result)


def _json_text(
    text: str, path: str, result: ParsedManifest
) -> tuple[dict[str, Any], LineFinder] | None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        result.errors.append(f"{path}: invalid JSON: {exc}")
        return None
    if not isinstance(data, dict):
        result.errors.append(f"{path}: expected a JSON object")
        return None
    return data, LineFinder(text)


def parse_package_json(path: Path) -> ParsedManifest:
    """Parse ``package.json`` dependencies, lifecycle scripts and publish registry."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result = ParsedManifest(path=str(path), ecosystem=Ecosystem.NPM)
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    return parse_package_json_text(text, str(path))


def parse_package_json_text(text: str, path: str) -> ParsedManifest:
    """Parse package.json content; ``path`` is used for locations only."""
    result = ParsedManifest(path=path, ecosystem=Ecosystem.NPM)
    loaded = _json_text(text, path, result)
    if loaded is None:
        return result
    data, lines = loaded
    if isinstance(data.get("name"), str):
        result.package_name = data["name"]
    for field, kind in _DEP_FIELDS:
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec_s = spec if isinstance(spec, str) else ""
            source_type, alias = classify_spec(spec_s)
            result.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=Ecosystem.NPM,
                    location=Location(path, lines.find(f'"{name}"', after=f'"{field}"')),
                    spec=spec_s,
                    kind=kind,
                    source_type=source_type,
                    alias_of=alias,
                )
            )
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        result.scripts = {k: v for k, v in scripts.items() if isinstance(v, str)}
    publish = data.get("publishConfig")
    if isinstance(publish, dict) and isinstance(publish.get("registry"), str):
        url = publish["registry"]
        result.indexes.append(
            IndexSetting(url=url, role="publish", location=Location(path, lines.find(url)))
        )
    return result


def _lock_name(key: str) -> str:
    """``node_modules/a/node_modules/@s/b`` -> ``@s/b``."""
    return key.rsplit("node_modules/", 1)[-1]


def parse_package_lock(path: Path) -> ParsedManifest:
    """Parse ``package-lock.json`` / ``npm-shrinkwrap.json`` (v1, v2, v3)."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.NPM)
    loaded = _load_json(path, result)
    if loaded is None:
        return result
    data, lines = loaded
    if isinstance(data.get("name"), str):
        result.package_name = data["name"]
    seen: set[tuple[str, str | None]] = set()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if key == "" or not isinstance(entry, dict) or "node_modules/" not in key:
                continue
            name = _lock_name(key)
            real = entry.get("name")
            alias = real if isinstance(real, str) and real != name else None
            dep = _locked_dep(path, lines, name, entry, f'"{key}"', alias)
            if (dep.name, dep.version) not in seen:
                seen.add((dep.name, dep.version))
                result.dependencies.append(dep)
        return result
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        _walk_v1(path, lines, deps, result, seen)
    return result


def _walk_v1(
    path: Path,
    lines: LineFinder,
    deps: dict[str, Any],
    result: ParsedManifest,
    seen: set[tuple[str, str | None]],
) -> None:
    for name, entry in deps.items():
        if not isinstance(entry, dict):
            continue
        alias = None
        locked = entry
        version = entry.get("version")
        if isinstance(version, str) and version.startswith("npm:"):
            alias, real_version = split_name_spec(version[4:])
            locked = {**entry, "version": real_version}
        dep = _locked_dep(path, lines, name, locked, f'"{name}": {{', alias)
        if (dep.name, dep.version) not in seen:
            seen.add((dep.name, dep.version))
            result.dependencies.append(dep)
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(path, lines, nested, result, seen)


def _locked_dep(
    path: Path,
    lines: LineFinder,
    name: str,
    entry: dict[str, Any],
    needle: str,
    alias: str | None,
) -> Dependency:
    version = entry.get("version") if isinstance(entry.get("version"), str) else None
    resolved = entry.get("resolved") if isinstance(entry.get("resolved"), str) else None
    if entry.get("link") is True:
        source_type = SourceType.WORKSPACE
    elif resolved is not None and resolved.startswith(("git+", "git://", "github:")):
        source_type = SourceType.GIT
    elif resolved is not None and resolved.startswith("file:"):
        source_type = SourceType.PATH
    else:
        source_type = SourceType.REGISTRY
    kind = DependencyKind.DEV if entry.get("dev") is True else DependencyKind.LOCKED
    return Dependency(
        name=name,
        ecosystem=Ecosystem.NPM,
        location=Location(str(path), lines.find(needle)),
        spec=version or "",
        kind=kind,
        source_type=source_type,
        version=version,
        resolved=resolved,
        alias_of=alias,
    )


_YARN_KV = re.compile(r'^\s{2}([A-Za-z]+):?\s+"?([^"]*)"?\s*$')


def parse_yarn_lock(path: Path) -> ParsedManifest:
    """Parse ``yarn.lock`` (classic v1 and Berry share the block structure)."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.NPM)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    header: tuple[int, list[str]] | None = None
    fields: dict[str, str] = {}

    def flush() -> None:
        if header is None:
            return
        lineno, specs = header
        if not specs:
            return
        name, spec = split_name_spec(specs[0])
        alias = None
        source_type = SourceType.REGISTRY
        if spec.startswith("npm:"):
            target, _ = split_name_spec(spec[4:])
            # Berry writes every registry entry as name@npm:range; only a different
            # name is an alias.
            if target and not target[0].isdigit() and target[0] not in "^~<>=*":
                alias = target if target != name else None
        elif spec.startswith(("workspace:", "link:", "portal:", "file:", "patch:")):
            source_type = SourceType.WORKSPACE if spec.startswith("workspace:") else SourceType.PATH
        elif spec.startswith(("git", "github:", "http")):
            source_type = SourceType.GIT if "git" in spec[:10] else SourceType.URL
        resolved = fields.get("resolved") or fields.get("resolution")
        result.dependencies.append(
            Dependency(
                name=name,
                ecosystem=Ecosystem.NPM,
                location=Location(str(path), lineno),
                spec=spec,
                kind=DependencyKind.LOCKED,
                source_type=source_type,
                version=fields.get("version"),
                resolved=resolved,
                alias_of=alias,
            )
        )

    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            flush()
            fields = {}
            body = line.rstrip()[:-1]
            if body == "__metadata":
                header = None
                continue
            specs = [s.strip().strip('"') for s in body.split(",") if s.strip()]
            header = (lineno, specs)
            continue
        m = _YARN_KV.match(line)
        if m and header is not None:
            fields.setdefault(m.group(1), m.group(2))
    flush()
    return result


def parse_npmrc(path: Path) -> ParsedManifest:
    """Parse ``.npmrc`` for ``registry=`` and ``@scope:registry=`` settings."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.NPM)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"')
        loc = Location(str(path), lineno)
        if key == "registry":
            result.indexes.append(IndexSetting(url=value, role="primary", location=loc))
        elif key.startswith("@") and key.endswith(":registry"):
            scope = key[: -len(":registry")]
            result.indexes.append(IndexSetting(url=value, role="scope", location=loc, scope=scope))
    return result
