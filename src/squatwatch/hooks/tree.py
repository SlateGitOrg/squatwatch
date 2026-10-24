"""Read-only views of a package source: a directory or an archive.

Archives are *never extracted to disk*. Members are indexed in memory with hard
limits on member count, per-file size and total bytes read, which bounds the work
an archive bomb can cause. Entries with absolute paths, ``..`` components, links
or device nodes are not readable and are reported as unsafe (SW311): a package
archive has no legitimate reason to contain them.

sdists (``name-1.0/...``) and npm tarballs (``package/...``) wrap everything in
one top-level directory; it is stripped so callers can ask for ``setup.py`` or
``package.json`` directly.
"""

from __future__ import annotations

import logging
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Protocol

from squatwatch.errors import ArchiveError
from squatwatch.models import Finding, Location, Severity

log = logging.getLogger(__name__)

ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".tar.gz",
    ".tgz",
    ".tar",
    ".tar.bz2",
    ".tar.xz",
    ".zip",
    ".whl",
)
MAX_MEMBERS = 20_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def is_archive(path: Path) -> bool:
    """Whether ``path`` has a supported archive suffix."""
    return path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES)


class SourceTree(Protocol):
    """Minimal read interface the reviewers need."""

    label: str
    issues: list[Finding]

    def root_files(self) -> list[str]:
        """Names of regular files at the top level."""
        ...

    def read_text(self, rel: str) -> str | None:
        """UTF-8 text of a file (``None`` if absent, unsafe or too large)."""
        ...


def _clean(rel: str) -> str | None:
    """Normalise a relative path; ``None`` if it escapes the root."""
    parts: list[str] = []
    for part in PurePosixPath(rel.replace("\\", "/")).parts:
        if part in ("", "."):
            continue
        if part == ".." or part.startswith("/"):
            return None
        parts.append(part)
    return "/".join(parts) if parts else None


class DirectoryTree:
    """A source directory on disk, confined to its root."""

    def __init__(self, root: Path, *, max_file_bytes: int = MAX_FILE_BYTES) -> None:
        self.root = root.resolve()
        self.label = str(root)
        self.issues: list[Finding] = []
        self._max = max_file_bytes

    def root_files(self) -> list[str]:
        try:
            return sorted(p.name for p in self.root.iterdir() if p.is_file())
        except OSError as exc:
            log.warning("cannot list %s: %s", self.root, exc)
            return []

    def read_text(self, rel: str) -> str | None:
        clean = _clean(rel)
        if clean is None:
            return None
        target = (self.root / clean).resolve()
        if not target.is_relative_to(self.root) or not target.is_file():
            return None
        try:
            if target.stat().st_size > self._max:
                log.warning("skipping %s: larger than %d bytes", target, self._max)
                return None
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


class ArchiveTree:
    """An sdist/npm tarball or zip/wheel, indexed in memory."""

    def __init__(
        self,
        path: Path,
        *,
        max_members: int = MAX_MEMBERS,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_total_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        self.path = path
        self.label = str(path)
        self.issues: list[Finding] = []
        self._max_file = max_file_bytes
        self._budget = max_total_bytes
        self._files: dict[str, bytes | None] = {}
        self._sizes: dict[str, int] = {}
        name = path.name.lower()
        try:
            if name.endswith((".zip", ".whl")):
                self._load_zip(max_members)
            else:
                self._load_tar(max_members)
        except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
            raise ArchiveError(f"{path}: cannot read archive: {exc}") from exc
        self._prefix = self._common_prefix()

    # ---------------------------------------------------------------- loading

    def _unsafe(self, member: str, why: str, severity: Severity = Severity.HIGH) -> None:
        self.issues.append(
            Finding(
                rule="SW311",
                severity=severity,
                title="unsafe archive entry",
                message=f"archive entry {member!r} {why}; it was not read",
                location=Location(self.label),
                evidence={"member": member},
            )
        )

    def _admit(self, name: str, size: int) -> str | None:
        clean = _clean(name)
        if clean is None or name.startswith(("/", "\\")) or (len(name) > 1 and name[1] == ":"):
            self._unsafe(name, "has an absolute path or escapes the archive root")
            return None
        self._sizes[clean] = size
        return clean

    def _load_tar(self, max_members: int) -> None:
        with tarfile.open(self.path, mode="r:*") as tar:
            for count, member in enumerate(tar):
                if count >= max_members:
                    self._unsafe(
                        member.name, f"exceeds the {max_members}-member limit", Severity.MEDIUM
                    )
                    break
                if member.issym() or member.islnk():
                    self._unsafe(member.name, f"is a link to {member.linkname!r}", Severity.MEDIUM)
                    continue
                if not member.isfile():
                    if not member.isdir():
                        self._unsafe(member.name, "is a device or special file")
                    continue
                clean = self._admit(member.name, member.size)
                if clean is None:
                    continue
                if member.size <= self._max_file and self._budget >= member.size:
                    fh = tar.extractfile(member)
                    data = fh.read(self._max_file + 1) if fh is not None else b""
                    self._budget -= len(data)
                    self._files[clean] = data if len(data) <= self._max_file else None
                else:
                    self._files[clean] = None

    def _load_zip(self, max_members: int) -> None:
        with zipfile.ZipFile(self.path) as zf:
            for count, info in enumerate(zf.infolist()):
                if count >= max_members:
                    self._unsafe(
                        info.filename, f"exceeds the {max_members}-member limit", Severity.MEDIUM
                    )
                    break
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    self._unsafe(info.filename, "is a symbolic link", Severity.MEDIUM)
                    continue
                clean = self._admit(info.filename, info.file_size)
                if clean is None:
                    continue
                if info.file_size <= self._max_file and self._budget >= info.file_size:
                    with zf.open(info) as fh:
                        data = fh.read(self._max_file + 1)
                    self._budget -= len(data)
                    self._files[clean] = data if len(data) <= self._max_file else None
                else:
                    self._files[clean] = None

    def _common_prefix(self) -> str:
        tops = {name.split("/", 1)[0] for name in self._files}
        if len(tops) == 1 and all("/" in n for n in self._files):
            return tops.pop() + "/"
        return ""

    # ---------------------------------------------------------------- reading

    def members(self) -> list[str]:
        """All readable member paths with the wrapper directory stripped."""
        return sorted(n[len(self._prefix) :] for n in self._files)

    def root_files(self) -> list[str]:
        return [m for m in self.members() if "/" not in m]

    def read_text(self, rel: str) -> str | None:
        clean = _clean(rel)
        if clean is None:
            return None
        data = self._files.get(self._prefix + clean)
        if data is None:
            if self._prefix + clean in self._files:
                log.warning("%s: %s skipped (over size budget)", self.label, clean)
            return None
        return data.decode("utf-8", errors="replace")
