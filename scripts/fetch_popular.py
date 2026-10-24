"""Regenerate the bundled popular-package snapshots and the benign evaluation lists.

Downloads two pinned public sources, verifies their SHA-256, and writes:

* ``src/squatwatch/data/popular-pypi.txt``  PyPI ranks 1..PYPI_CUTOFF
* ``src/squatwatch/data/popular-npm.txt``   npm  ranks 1..NPM_CUTOFF
* ``data/eval/benign-pypi.txt``             PyPI ranks after the cutoff
* ``data/eval/benign-npm.txt``              npm  ranks after the cutoff

The names after the cutoff are real, widely downloaded packages that are *not*
in the snapshot, so they act as realistic negatives for the evaluation: a
detector that flags them is producing false positives.

Usage: ``uv run python scripts/fetch_popular.py`` (needs network; not part of make check).
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PYPI_URL = (
    "https://raw.githubusercontent.com/hugovk/top-pypi-packages/"
    "e6b5b398c1fcc783f593031f99bc2c772d64c6ef/top-pypi-packages.min.json"
)
PYPI_SHA256 = "55fee05ed02b628f05350a51780ec436efae39ea0810df5d5419e15b850c7041"
NPM_URL = "https://registry.npmjs.org/npm-high-impact/-/npm-high-impact-1.13.0.tgz"
NPM_SHA256 = "63ed31dacc861ac10c95b47af242a984f210f0170eaea8eaa66ba4a9b8f9d30b"

PYPI_CUTOFF = 12_000
NPM_CUTOFF = 14_000


def fetch(url: str, sha256: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        body: bytes = resp.read()
    digest = hashlib.sha256(body).hexdigest()
    if digest != sha256:
        raise SystemExit(f"checksum mismatch for {url}: {digest}")
    return body


def pypi_names(body: bytes) -> list[str]:
    rows = json.loads(body)["rows"]
    return [str(r["project"]) for r in rows]


def npm_names(body: bytes) -> list[str]:
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        member = tar.extractfile("package/lib/top.js")
        if member is None:
            raise SystemExit("package/lib/top.js missing from npm-high-impact tarball")
        source = member.read().decode("utf-8")
    return re.findall(r"^\s*'([^']+)',?$", source, flags=re.MULTILINE)


def write_list(path: Path, header: list[str], names: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# {h}" for h in header] + names
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(names)} names)")


def main() -> int:
    pypi = pypi_names(fetch(PYPI_URL, PYPI_SHA256))
    npm = npm_names(fetch(NPM_URL, NPM_SHA256))
    for eco, names, url, sha, cutoff, licence in (
        ("pypi", pypi, PYPI_URL, PYPI_SHA256, PYPI_CUTOFF, "no licence file; names only"),
        ("npm", npm, NPM_URL, NPM_SHA256, NPM_CUTOFF, "MIT (npm-high-impact)"),
    ):
        common = [f"ecosystem: {eco}", f"source: {url}", f"source-sha256: {sha}"]
        common.append(f"licence: {licence}")
        write_list(
            ROOT / "src" / "squatwatch" / "data" / f"popular-{eco}.txt",
            ["squatwatch popular-package snapshot", *common, f"ranks: 1-{cutoff}"],
            names[:cutoff],
        )
        write_list(
            ROOT / "data" / "eval" / f"benign-{eco}.txt",
            [
                "squatwatch benign evaluation names (popular, but outside the snapshot)",
                *common,
                f"ranks: {cutoff + 1}-{len(names)}",
            ],
            names[cutoff:],
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
