"""Static extraction of dependencies from ``setup.py`` without running it.

Only literal values are understood: ``install_requires=[...]`` written inline, or
a module-level name bound once to a literal list. Anything computed at run time
is reported as unresolved rather than guessed.
"""

from __future__ import annotations

import ast
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, SourceType
from squatwatch.parsers.base import ParsedManifest, non_ascii_name

_KEYWORDS: dict[str, DependencyKind] = {
    "install_requires": DependencyKind.RUNTIME,
    "setup_requires": DependencyKind.BUILD,
    "tests_require": DependencyKind.DEV,
    "extras_require": DependencyKind.OPTIONAL,
}


def _is_setup_call(node: ast.Call) -> bool:
    func = node.func
    return (isinstance(func, ast.Name) and func.id == "setup") or (
        isinstance(func, ast.Attribute) and func.attr == "setup"
    )


def _string_nodes(node: ast.expr, bindings: dict[str, ast.expr]) -> list[ast.Constant] | None:
    """String constants of a literal list/tuple/dict-of-lists, or None if dynamic."""
    if isinstance(node, ast.Name) and node.id in bindings:
        node = bindings[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out: list[ast.Constant] = []
        for elt in node.elts:
            sub = _string_nodes(elt, bindings)
            if sub is None:
                return None
            out.extend(sub)
        return out
    if isinstance(node, ast.Dict):
        out = []
        for value in node.values:
            sub = _string_nodes(value, bindings)
            if sub is None:
                return None
            out.extend(sub)
        return out
    return None


def parse_setup_source(source: str, path: str) -> ParsedManifest:
    """Extract literal dependency lists from setup.py ``source``."""
    result = ParsedManifest(path=path, ecosystem=Ecosystem.PYPI)
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        result.errors.append(f"{path}:{exc.lineno or '?'}: not parseable as Python 3: {exc.msg}")
        return result
    bindings: dict[str, ast.expr] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name):
                bindings[target.id] = stmt.value
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_setup_call(node)):
            continue
        for kw in node.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                result.package_name = str(kw.value.value)
            if kw.arg not in _KEYWORDS:
                continue
            strings = _string_nodes(kw.value, bindings)
            if strings is None:
                result.errors.append(
                    f"{path}:{kw.value.lineno}: {kw.arg} is computed at run time; not analysed"
                )
                continue
            for const in strings:
                _add(result, str(const.value), const.lineno, _KEYWORDS[kw.arg], path)
    return result


def _add(result: ParsedManifest, spec: str, line: int, kind: DependencyKind, path: str) -> None:
    try:
        req = Requirement(spec)
    except InvalidRequirement as exc:
        odd = non_ascii_name(spec)
        if odd is not None:
            result.dependencies.append(
                Dependency(
                    name=odd, ecosystem=Ecosystem.PYPI, location=Location(path, line), kind=kind
                )
            )
            return
        result.errors.append(f"{path}:{line}: invalid requirement {spec!r}: {exc}")
        return
    result.dependencies.append(
        Dependency(
            name=req.name,
            ecosystem=Ecosystem.PYPI,
            location=Location(path, line),
            spec=str(req.specifier) or (req.url or ""),
            kind=kind,
            source_type=SourceType.REGISTRY if req.url is None else SourceType.URL,
        )
    )


def parse_setup_py(path: Path) -> ParsedManifest:
    """Read and parse a ``setup.py`` file."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
        result.errors.append(f"{path}: cannot read: {exc}")
        return result
    return parse_setup_source(source, str(path))
