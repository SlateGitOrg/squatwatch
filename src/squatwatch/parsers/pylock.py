"""Python lockfiles: ``poetry.lock``, ``uv.lock`` and ``Pipfile.lock``.

Locked entries carry the resolved version and, where the format records it, the
index or URL the artifact came from. That origin is what proves (rather than
suggests) dependency confusion: an internal package resolved from pypi.org.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, SourceType
from squatwatch.parsers.base import IndexSetting, LineFinder, ParsedManifest

PYPI_DEFAULT_INDEX = "https://pypi.org/simple"


def _read_toml(path: Path, result: ParsedManifest) -> tuple[dict[str, Any], LineFinder] | None:
    try:
        text = path.read_text(encoding="utf-8")
        return tomllib.loads(text), LineFinder(text)
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
    except tomllib.TOMLDecodeError as exc:
        result.errors.append(f"{path}: invalid TOML: {exc}")
    return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _packages(data: dict[str, Any]) -> list[dict[str, Any]]:
    pkgs = data.get("package")
    return [p for p in pkgs if isinstance(p, dict)] if isinstance(pkgs, list) else []


def parse_poetry_lock(path: Path) -> ParsedManifest:
    """Parse ``poetry.lock``. Packages without a ``[package.source]`` came from PyPI."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
    loaded = _read_toml(path, result)
    if loaded is None:
        return result
    data, lines = loaded
    for pkg in _packages(data):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str):
            continue
        source = _dict(pkg.get("source"))
        stype = str(source.get("type", ""))
        url = source.get("url")
        source_type = {
            "git": SourceType.GIT,
            "directory": SourceType.PATH,
            "file": SourceType.PATH,
            "url": SourceType.URL,
        }.get(stype, SourceType.REGISTRY)
        resolved = str(url) if isinstance(url, str) else None
        if source_type is SourceType.REGISTRY and resolved is None:
            resolved = PYPI_DEFAULT_INDEX
        result.dependencies.append(
            Dependency(
                name=name,
                ecosystem=Ecosystem.PYPI,
                location=Location(str(path), lines.find(f'name = "{name}"')),
                spec=f"=={version}" if isinstance(version, str) else "",
                kind=DependencyKind.LOCKED,
                source_type=source_type,
                version=version if isinstance(version, str) else None,
                resolved=resolved,
            )
        )
    return result


def parse_uv_lock(path: Path) -> ParsedManifest:
    """Parse ``uv.lock``; ``source = { registry = URL }`` records the index used."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
    loaded = _read_toml(path, result)
    if loaded is None:
        return result
    data, lines = loaded
    for pkg in _packages(data):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str):
            continue
        source = _dict(pkg.get("source"))
        if any(k in source for k in ("editable", "virtual", "directory", "path")):
            source_type, resolved = SourceType.PATH, None
        elif "git" in source:
            source_type, resolved = SourceType.GIT, str(source["git"])
        elif "url" in source:
            source_type, resolved = SourceType.URL, str(source["url"])
        else:
            source_type = SourceType.REGISTRY
            registry = source.get("registry")
            resolved = str(registry) if isinstance(registry, str) else None
        result.dependencies.append(
            Dependency(
                name=name,
                ecosystem=Ecosystem.PYPI,
                location=Location(str(path), lines.find(f'name = "{name}"')),
                spec=f"=={version}" if isinstance(version, str) else "",
                kind=DependencyKind.LOCKED,
                source_type=source_type,
                version=version if isinstance(version, str) else None,
                resolved=resolved,
            )
        )
    return result


def parse_pipfile_lock(path: Path) -> ParsedManifest:
    """Parse ``Pipfile.lock`` (JSON). Each entry may name its ``index``."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    except json.JSONDecodeError as exc:
        result.errors.append(f"{path}: invalid JSON: {exc}")
        return result
    if not isinstance(data, dict):
        result.errors.append(f"{path}: expected a JSON object")
        return result
    lines = LineFinder(text)
    meta = _dict(data.get("_meta"))
    sources: dict[str, str] = {}
    raw_sources = meta.get("sources")
    for i, src in enumerate(raw_sources if isinstance(raw_sources, list) else []):
        if isinstance(src, dict) and isinstance(src.get("url"), str):
            name = str(src.get("name", f"source-{i}"))
            sources[name] = src["url"]
            role = "primary" if i == 0 else "extra"
            loc = Location(str(path), lines.find(src["url"]))
            result.indexes.append(IndexSetting(url=src["url"], role=role, location=loc))
    for section, kind in (("default", DependencyKind.LOCKED), ("develop", DependencyKind.DEV)):
        entries = data.get(section)
        for name, entry in entries.items() if isinstance(entries, dict) else []:
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if "git" in entry:
                source_type, resolved = SourceType.GIT, str(entry["git"])
            elif "path" in entry or "file" in entry:
                source_type, resolved = SourceType.PATH, None
            else:
                source_type = SourceType.REGISTRY
                index = entry.get("index")
                resolved = sources.get(str(index)) if index is not None else None
            result.dependencies.append(
                Dependency(
                    name=name,
                    ecosystem=Ecosystem.PYPI,
                    location=Location(str(path), lines.find(f'"{name}": {{')),
                    spec=str(version) if isinstance(version, str) else "",
                    kind=kind,
                    source_type=source_type,
                    version=version.lstrip("=") if isinstance(version, str) else None,
                    resolved=resolved,
                )
            )
    return result
