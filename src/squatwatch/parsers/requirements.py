"""pip requirements files (``requirements*.txt``, constraints files).

Supports line continuations, comments, ``-r``/``-c`` includes (relative to the
including file, cycle-safe), editable installs, direct URL references,
``#egg=`` fragments, per-requirement options such as ``--hash`` and the index
options ``--index-url``/``-i`` and ``--extra-index-url``.
"""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, SourceType
from squatwatch.parsers.base import IndexSetting, ParsedManifest

log = logging.getLogger(__name__)

_EGG = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")
_URL_PREFIXES = ("http://", "https://", "file:", "git+", "hg+", "svn+", "bzr+")
_PATH_PREFIXES = (".", "/", "~")
_MAX_INCLUDE_DEPTH = 10


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join ``\\`` continuations and drop comments; keep the first line number."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = "" if raw.lstrip().startswith("#") else re.sub(r"(^|\s)#.*$", "", raw)
        if not buf:
            start = lineno
        if line.endswith("\\"):
            buf.append(line[:-1])
            continue
        buf.append(line)
        joined = " ".join(part.strip() for part in buf).strip()
        buf = []
        if joined:
            out.append((start, joined))
    if buf:
        joined = " ".join(part.strip() for part in buf).strip()
        if joined:
            out.append((start, joined))
    return out


def _source_type_for_url(url: str) -> SourceType:
    if url.startswith(("git+", "git://")) or url.split("#", 1)[0].endswith(".git"):
        return SourceType.GIT
    if url.startswith(("file:", *_PATH_PREFIXES)):
        return SourceType.PATH
    return SourceType.URL


def parse_requirements(
    path: Path, *, kind: DependencyKind = DependencyKind.RUNTIME
) -> ParsedManifest:
    """Parse a requirements file and everything it includes."""
    result = ParsedManifest(path=str(path), ecosystem=Ecosystem.PYPI)
    _parse_into(path, result, kind=kind, seen=set(), depth=0)
    return result


def _parse_into(
    path: Path,
    result: ParsedManifest,
    *,
    kind: DependencyKind,
    seen: set[Path],
    depth: int,
) -> None:
    resolved = path.resolve()
    if resolved in seen:
        log.debug("skipping already-included %s", path)
        return
    if depth > _MAX_INCLUDE_DEPTH:
        result.errors.append(f"{path}: include depth exceeds {_MAX_INCLUDE_DEPTH}")
        return
    seen.add(resolved)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        result.errors.append(f"{path}: cannot read: {exc}")
        return
    if depth > 0:
        result.included.append(str(path))

    for lineno, line in _logical_lines(text):
        loc = Location(str(path), lineno)
        if line.startswith("-"):
            _handle_option(path, line, loc, result, kind=kind, seen=seen, depth=depth)
            continue
        dep = _parse_requirement_line(line, loc, kind, result)
        if dep is not None:
            result.dependencies.append(dep)


def _handle_option(
    path: Path,
    line: str,
    loc: Location,
    result: ParsedManifest,
    *,
    kind: DependencyKind,
    seen: set[Path],
    depth: int,
) -> None:
    try:
        parts = shlex.split(line)
    except ValueError as exc:
        result.errors.append(f"{loc}: cannot tokenise option line: {exc}")
        return
    opt, value = parts[0], parts[1] if len(parts) > 1 else ""
    if "=" in opt and opt.startswith("--"):
        opt, _, value = opt.partition("=")
    if opt in ("-r", "--requirement", "-c", "--constraint"):
        if not value:
            result.errors.append(f"{loc}: {opt} needs a file argument")
            return
        child_kind = DependencyKind.LOCKED if opt in ("-c", "--constraint") else kind
        _parse_into(path.parent / value, result, kind=child_kind, seen=seen, depth=depth + 1)
    elif opt in ("-i", "--index-url"):
        result.indexes.append(IndexSetting(url=value, role="primary", location=loc))
    elif opt == "--extra-index-url":
        result.indexes.append(IndexSetting(url=value, role="extra", location=loc))
    elif opt in ("-e", "--editable"):
        dep = _parse_requirement_line(value, loc, kind, result)
        if dep is not None:
            result.dependencies.append(dep)
    else:
        log.debug("%s: ignoring pip option %s", loc, opt)


def _parse_requirement_line(
    line: str, loc: Location, kind: DependencyKind, result: ParsedManifest
) -> Dependency | None:
    # Drop per-requirement options (``--hash=...``, ``--global-option``).
    spec = re.split(r"\s+--?[a-zA-Z]", line, maxsplit=1)[0].strip()
    if not spec:
        return None
    if spec.startswith(_URL_PREFIXES) or spec.startswith(_PATH_PREFIXES):
        egg = _EGG.search(spec)
        if egg is None:
            log.debug("%s: unnamed direct reference %s", loc, spec)
            return None
        return Dependency(
            name=egg.group(1),
            ecosystem=Ecosystem.PYPI,
            location=loc,
            spec=spec,
            kind=kind,
            source_type=_source_type_for_url(spec),
        )
    try:
        req = Requirement(spec)
    except InvalidRequirement as exc:
        result.errors.append(f"{loc}: invalid requirement {spec!r}: {exc}")
        return None
    source = SourceType.REGISTRY if req.url is None else _source_type_for_url(req.url)
    pinned = None
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "==="):
        pinned = specs[0].version
    return Dependency(
        name=req.name,
        ecosystem=Ecosystem.PYPI,
        location=loc,
        spec=str(req.specifier) or (req.url or ""),
        kind=kind,
        source_type=source,
        version=pinned,
    )
