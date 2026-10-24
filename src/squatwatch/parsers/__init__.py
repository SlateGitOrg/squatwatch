"""Manifest/lockfile detection and dispatch.

:func:`parser_for` maps a file name to its parser; :func:`discover` walks a
directory tree for supported files while skipping vendored and build output.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Callable, Iterator
from pathlib import Path

from squatwatch.parsers.base import BuildBackend, IndexSetting, ParsedManifest
from squatwatch.parsers.npm import (
    parse_npmrc,
    parse_package_json,
    parse_package_lock,
    parse_yarn_lock,
)
from squatwatch.parsers.pylock import parse_pipfile_lock, parse_poetry_lock, parse_uv_lock
from squatwatch.parsers.pyproject import parse_pyproject
from squatwatch.parsers.requirements import parse_requirements
from squatwatch.parsers.setuppy import parse_setup_py

__all__ = [
    "BuildBackend",
    "IndexSetting",
    "ParsedManifest",
    "discover",
    "parse_file",
    "parser_for",
]

log = logging.getLogger(__name__)

Parser = Callable[[Path], ParsedManifest]

_EXACT: dict[str, Parser] = {
    "pyproject.toml": parse_pyproject,
    "setup.py": parse_setup_py,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    ".npmrc": parse_npmrc,
}
_PATTERNS: tuple[tuple[str, Parser], ...] = (
    ("requirements*.txt", parse_requirements),
    ("*requirements.txt", parse_requirements),
    ("constraints*.txt", parse_requirements),
)
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)


def parser_for(path: Path) -> Parser | None:
    """The parser for ``path`` judged by its file name, or ``None``."""
    name = path.name
    if name in _EXACT:
        return _EXACT[name]
    for pattern, parser in _PATTERNS:
        if fnmatch.fnmatch(name, pattern):
            return parser
    if path.suffix == ".txt" and path.parent.name == "requirements":
        return parse_requirements
    return None


def parse_file(path: Path) -> ParsedManifest | None:
    """Parse ``path`` if it is a supported manifest/lockfile."""
    parser = parser_for(path)
    if parser is None:
        return None
    log.debug("parsing %s with %s", path, parser.__name__)
    return parser(path)


def discover(root: Path, *, max_depth: int = 8) -> Iterator[Path]:
    """Yield supported files under ``root`` in a deterministic order."""
    if root.is_file():
        if parser_for(root) is not None:
            yield root
        return
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        depth = len(current.parts) - base_depth
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and depth < max_depth)
        for name in sorted(filenames):
            candidate = current / name
            if parser_for(candidate) is not None:
                yield candidate
