"""``pyproject.toml``: PEP 621 metadata, PEP 735 groups, build system, Poetry and
uv dependency tables, and the package indexes configured by Poetry and uv."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, SourceType
from squatwatch.parsers.base import (
    BuildBackend,
    IndexSetting,
    LineFinder,
    ParsedManifest,
    non_ascii_name,
)


def parse_pyproject(path: Path) -> ParsedManifest:
    """Parse one pyproject.toml file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    return parse_pyproject_text(text, str(path))


def parse_pyproject_text(text: str, path: str) -> ParsedManifest:
    """Parse pyproject.toml content; ``path`` is used for locations only."""
    result = ParsedManifest(path=path, ecosystem=Ecosystem.PYPI)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        result.errors.append(f"{path}: invalid TOML: {exc}")
        return result
    _PyprojectParser(path, result, LineFinder(text)).run(data)
    return result


class _PyprojectParser:
    def __init__(self, path: str, result: ParsedManifest, lines: LineFinder) -> None:
        self.path = path
        self.result = result
        self.lines = lines

    def loc(self, needle: str, after: str | None = None) -> Location:
        return Location(self.path, self.lines.find(needle, after=after))

    def run(self, data: dict[str, Any]) -> None:
        project = _table(data.get("project"))
        if isinstance(project.get("name"), str):
            self.result.package_name = project["name"]
        for spec in _strings(project.get("dependencies")):
            self.add_pep508(spec, DependencyKind.RUNTIME, "[project]")
        for _extra, specs in _table(project.get("optional-dependencies")).items():
            for spec in _strings(specs):
                self.add_pep508(spec, DependencyKind.OPTIONAL, "optional-dependencies")
        for _group, specs in _table(data.get("dependency-groups")).items():
            for spec in _strings(specs):
                self.add_pep508(spec, DependencyKind.DEV, "[dependency-groups]")

        build = _table(data.get("build-system"))
        if build:
            requires = tuple(_strings(build.get("requires")))
            for spec in requires:
                self.add_pep508(spec, DependencyKind.BUILD, "[build-system]")
            backend = build.get("build-backend")
            self.result.build = BuildBackend(
                backend=backend if isinstance(backend, str) else None,
                backend_path=tuple(_strings(build.get("backend-path"))),
                requires=requires,
                location=self.loc("build-backend", after="[build-system]"),
            )

        tool = _table(data.get("tool"))
        self.poetry(_table(tool.get("poetry")))
        self.uv(_table(tool.get("uv")))

    def add_pep508(self, spec: str, kind: DependencyKind, section: str) -> None:
        try:
            req = Requirement(spec)
        except InvalidRequirement as exc:
            odd = non_ascii_name(spec)
            if odd is not None:
                self.result.dependencies.append(
                    Dependency(
                        name=odd, ecosystem=Ecosystem.PYPI, location=self.loc(spec), kind=kind
                    )
                )
                return
            line = self.lines.find(spec)
            self.result.errors.append(
                f"{self.path}:{line or '?'}: invalid requirement {spec!r}: {exc}"
            )
            return
        source = SourceType.REGISTRY
        if req.url is not None:
            source = SourceType.GIT if req.url.startswith("git+") else SourceType.URL
        self.result.dependencies.append(
            Dependency(
                name=req.name,
                ecosystem=Ecosystem.PYPI,
                location=self.loc(f'"{spec}', after=section) if spec else self.loc(spec),
                spec=str(req.specifier) or (req.url or ""),
                kind=kind,
                source_type=source,
            )
        )

    def poetry(self, poetry: dict[str, Any]) -> None:
        if not poetry:
            return
        tables: list[tuple[dict[str, Any], DependencyKind]] = [
            (_table(poetry.get("dependencies")), DependencyKind.RUNTIME),
            (_table(poetry.get("dev-dependencies")), DependencyKind.DEV),
        ]
        for group in _table(poetry.get("group")).values():
            tables.append((_table(_table(group).get("dependencies")), DependencyKind.DEV))
        for table, kind in tables:
            for name, value in table.items():
                if name.lower() == "python":
                    continue
                self.result.dependencies.append(self.poetry_dep(name, value, kind))
        for source in poetry.get("source", []) if isinstance(poetry.get("source"), list) else []:
            src = _table(source)
            url = src.get("url")
            if isinstance(url, str):
                role = str(src.get("priority", "primary"))
                if src.get("secondary") is True:
                    role = "secondary"
                self.result.indexes.append(IndexSetting(url=url, role=role, location=self.loc(url)))

    def poetry_dep(self, name: str, value: object, kind: DependencyKind) -> Dependency:
        spec = ""
        source = SourceType.REGISTRY
        if isinstance(value, str):
            spec = value
        elif isinstance(value, dict):
            if "git" in value:
                source, spec = SourceType.GIT, str(value["git"])
            elif "path" in value:
                source, spec = SourceType.PATH, str(value["path"])
            elif "url" in value:
                source, spec = SourceType.URL, str(value["url"])
            else:
                spec = str(value.get("version", ""))
            if value.get("optional") is True and kind is DependencyKind.RUNTIME:
                kind = DependencyKind.OPTIONAL
        return Dependency(
            name=name,
            ecosystem=Ecosystem.PYPI,
            location=self.loc(f"{name} =", after="[tool.poetry"),
            spec=spec,
            kind=kind,
            source_type=source,
        )

    def uv(self, uv: dict[str, Any]) -> None:
        """uv consults indexes in order and, by default (``first-index``), stops at the
        first index that has the package, which defeats dependency confusion. Only
        ``index-strategy = "unsafe-best-match"`` restores pip's merge-all behaviour,
        so uv's extra indexes are reported as ``priority`` unless that is set."""
        if not uv:
            return
        for spec in _strings(uv.get("dev-dependencies")):
            self.add_pep508(spec, DependencyKind.DEV, "[tool.uv]")
        merged = uv.get("index-strategy") == "unsafe-best-match"
        extra_role = "extra" if merged else "priority"
        index_url = uv.get("index-url")
        if isinstance(index_url, str):
            self.result.indexes.append(
                IndexSetting(url=index_url, role="primary", location=self.loc(index_url))
            )
        for url in _strings(uv.get("extra-index-url")):
            self.result.indexes.append(
                IndexSetting(url=url, role=extra_role, location=self.loc(url))
            )
        indexes = uv.get("index")
        for item in indexes if isinstance(indexes, list) else []:
            entry = _table(item)
            index = entry.get("url")
            if not isinstance(index, str):
                continue
            if entry.get("explicit") is True:
                role = "explicit"
            elif entry.get("default") is True:
                role = "primary"
            else:
                role = extra_role
            self.result.indexes.append(IndexSetting(url=index, role=role, location=self.loc(index)))


def _table(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]
