"""Manifest and lockfile parsers."""

from __future__ import annotations

import json
from pathlib import Path

from squatwatch.models import DependencyKind, Ecosystem, SourceType
from squatwatch.parsers import discover, parse_file, parser_for
from squatwatch.parsers.npm import (
    classify_spec,
    parse_npmrc,
    parse_package_json,
    parse_package_lock,
    parse_yarn_lock,
    split_name_spec,
)
from squatwatch.parsers.pylock import parse_pipfile_lock, parse_poetry_lock, parse_uv_lock
from squatwatch.parsers.pyproject import parse_pyproject, parse_pyproject_text
from squatwatch.parsers.requirements import parse_requirements
from squatwatch.parsers.setuppy import parse_setup_source


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------------ requirements


def test_requirements_full_syntax(tmp_path: Path) -> None:
    write(tmp_path / "base.txt", "numpy==2.1.0\n-r requirements.txt  # cycle is ignored\n")
    write(tmp_path / "constraints.txt", "urllib3<3\n")
    req = write(
        tmp_path / "requirements.txt",
        "\n".join(
            [
                "# comment",
                "--index-url https://pypi.example/simple",
                "--extra-index-url=https://extra.example/simple",
                "requests[socks]==2.32.3 ; python_version >= '3.8' --hash=sha256:abc",
                "flask \\",
                "  >=3.0",
                "-e git+https://github.com/org/repo.git#egg=editable-pkg",
                "https://files.example/pkg-1.0.tar.gz#egg=urlpkg",
                "./local/path",
                "pkg @ https://files.example/pkg.whl",
                "-r base.txt",
                "-c constraints.txt",
                "-r missing.txt",
                "--no-binary :all:",
                "not a valid requirement !!",
                "-r",
            ]
        ),
    )
    m = parse_requirements(req)
    by_name = {d.name: d for d in m.dependencies}
    assert set(by_name) == {
        "requests",
        "flask",
        "editable-pkg",
        "urlpkg",
        "pkg",
        "numpy",
        "urllib3",
    }
    assert by_name["requests"].version == "2.32.3"
    assert by_name["requests"].location.line == 4
    assert by_name["flask"].spec == ">=3.0"
    assert by_name["editable-pkg"].source_type is SourceType.GIT
    assert by_name["urlpkg"].source_type is SourceType.URL
    assert by_name["pkg"].source_type is SourceType.URL
    assert by_name["urllib3"].kind is DependencyKind.LOCKED
    assert by_name["numpy"].location.path.endswith("base.txt")
    assert [(i.role, i.url) for i in m.indexes] == [
        ("primary", "https://pypi.example/simple"),
        ("extra", "https://extra.example/simple"),
    ]
    assert len(m.errors) == 3  # missing include, invalid requirement, -r without file
    assert any("missing.txt" in e for e in m.errors)


def test_requirements_unreadable(tmp_path: Path) -> None:
    m = parse_requirements(tmp_path / "nope.txt")
    assert m.errors and "cannot read" in m.errors[0]


def test_requirements_trailing_continuation(tmp_path: Path) -> None:
    m = parse_requirements(write(tmp_path / "requirements.txt", "six \\"))
    assert [d.name for d in m.dependencies] == ["six"]


# ------------------------------------------------------------------- pyproject


PYPROJECT = """
[project]
name = "demo"
dependencies = ["requests>=2", "bad req !!"]

[project.optional-dependencies]
docs = ["sphinx"]

[dependency-groups]
dev = ["pytest", {include-group = "docs"}]

[build-system]
requires = ["setuptools>=69", "wheel"]
build-backend = "setuptools.build_meta"
backend-path = ["."]

[tool.poetry.dependencies]
python = "^3.11"
flask = "^3.0"
mylib = {git = "https://github.com/x/y.git"}
localpkg = {path = "../local"}
urlpkg = {url = "https://x/y.whl"}
extra = {version = "^1", optional = true}

[tool.poetry.group.test.dependencies]
hypothesis = "*"

[[tool.poetry.source]]
name = "private"
url = "https://pypi.corp.example/simple"
priority = "supplemental"

[tool.uv]
dev-dependencies = ["ruff"]
index-url = "https://mirror.example/simple"
extra-index-url = ["https://extra.example/simple"]

[[tool.uv.index]]
url = "https://explicit.example/simple"
explicit = true

[[tool.uv.index]]
url = "https://default.example/simple"
default = true

[[tool.uv.index]]
url = "https://other.example/simple"

[[tool.uv.index]]
name = "no-url"
"""


def test_pyproject_everything() -> None:
    m = parse_pyproject_text(PYPROJECT, "pyproject.toml")
    kinds = {d.name: d.kind for d in m.dependencies}
    assert kinds["requests"] is DependencyKind.RUNTIME
    assert kinds["sphinx"] is DependencyKind.OPTIONAL
    assert kinds["pytest"] is DependencyKind.DEV
    assert kinds["setuptools"] is DependencyKind.BUILD
    assert kinds["hypothesis"] is DependencyKind.DEV
    assert kinds["extra"] is DependencyKind.OPTIONAL
    assert kinds["ruff"] is DependencyKind.DEV
    assert "python" not in kinds
    types = {d.name: d.source_type for d in m.dependencies}
    assert types["mylib"] is SourceType.GIT
    assert types["localpkg"] is SourceType.PATH
    assert types["urlpkg"] is SourceType.URL
    assert m.package_name == "demo"
    assert m.build is not None and m.build.backend_path == (".",)
    roles = [(i.role, i.url.split("//")[1].split("/")[0]) for i in m.indexes]
    assert roles == [
        ("supplemental", "pypi.corp.example"),
        ("primary", "mirror.example"),
        ("priority", "extra.example"),
        ("explicit", "explicit.example"),
        ("primary", "default.example"),
        ("priority", "other.example"),
    ]
    assert len(m.errors) == 1 and "bad req" in m.errors[0]


def test_uv_unsafe_best_match_merges_indexes() -> None:
    text = '[tool.uv]\nindex-strategy = "unsafe-best-match"\nextra-index-url = ["https://x.example/s"]\n'
    m = parse_pyproject_text(text, "pyproject.toml")
    assert [i.role for i in m.indexes] == ["extra"]


def test_pyproject_errors(tmp_path: Path) -> None:
    assert parse_pyproject_text("not = [toml", "p.toml").errors
    assert parse_pyproject(tmp_path / "missing.toml").errors


# --------------------------------------------------------------------- setup.py


def test_setup_py_literal_extraction() -> None:
    source = """
from setuptools import setup
REQS = ["requests>=2", "numpy"]
setup(
    name="demo",
    install_requires=REQS,
    setup_requires=("wheel",),
    extras_require={"docs": ["sphinx"]},
    tests_require=compute(),
)
"""
    m = parse_setup_source(source, "setup.py")
    assert {d.name: d.kind for d in m.dependencies} == {
        "requests": DependencyKind.RUNTIME,
        "numpy": DependencyKind.RUNTIME,
        "wheel": DependencyKind.BUILD,
        "sphinx": DependencyKind.OPTIONAL,
    }
    assert m.package_name == "demo"
    assert any("computed at run time" in e for e in m.errors)


def test_setup_py_python2_and_bad_requirement() -> None:
    assert "not parseable" in parse_setup_source("print 'hi'\n", "setup.py").errors[0]
    m = parse_setup_source("import setuptools\nsetuptools.setup(install_requires=['!!'])\n", "s.py")
    assert m.errors and not m.dependencies


# -------------------------------------------------------------------- lockfiles


def test_poetry_lock(tmp_path: Path) -> None:
    lock = write(
        tmp_path / "poetry.lock",
        """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "internal"
version = "1.0"
[package.source]
type = "legacy"
url = "https://pypi.corp.example/simple"

[[package]]
name = "gitdep"
version = "0.1"
[package.source]
type = "git"
url = "https://github.com/x/y.git"
""",
    )
    deps = {d.name: d for d in parse_poetry_lock(lock).dependencies}
    assert deps["requests"].resolved == "https://pypi.org/simple"
    assert deps["internal"].resolved == "https://pypi.corp.example/simple"
    assert deps["gitdep"].source_type is SourceType.GIT
    assert deps["requests"].kind is DependencyKind.LOCKED


def test_uv_lock(tmp_path: Path) -> None:
    lock = write(
        tmp_path / "uv.lock",
        """
version = 1
[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "myproj"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "g"
version = "1"
source = { git = "https://github.com/x/g" }

[[package]]
name = "u"
version = "1"
source = { url = "https://x/u.whl" }
""",
    )
    deps = {d.name: d for d in parse_uv_lock(lock).dependencies}
    assert deps["requests"].resolved == "https://pypi.org/simple"
    assert deps["myproj"].source_type is SourceType.PATH
    assert deps["g"].source_type is SourceType.GIT
    assert deps["u"].source_type is SourceType.URL
    assert parse_uv_lock(write(tmp_path / "bad" / "uv.lock", "[[")).errors


def test_pipfile_lock(tmp_path: Path) -> None:
    data = {
        "_meta": {
            "sources": [
                {"name": "pypi", "url": "https://pypi.org/simple"},
                {"name": "corp", "url": "https://pypi.corp.example/simple"},
            ]
        },
        "default": {
            "requests": {"version": "==2.32.3", "index": "pypi"},
            "internal": {"version": "==1.0", "index": "corp"},
            "g": {"git": "https://github.com/x/g"},
            "p": {"path": "."},
            "junk": "not a dict",
        },
        "develop": {"pytest": {"version": "==8.0"}},
    }
    lock = write(tmp_path / "Pipfile.lock", json.dumps(data, indent=2))
    m = parse_pipfile_lock(lock)
    deps = {d.name: d for d in m.dependencies}
    assert deps["internal"].resolved == "https://pypi.corp.example/simple"
    assert deps["requests"].version == "2.32.3"
    assert deps["g"].source_type is SourceType.GIT
    assert deps["p"].source_type is SourceType.PATH
    assert deps["pytest"].kind is DependencyKind.DEV
    assert [i.role for i in m.indexes] == ["primary", "extra"]
    assert parse_pipfile_lock(write(tmp_path / "x" / "Pipfile.lock", "[]")).errors
    assert parse_pipfile_lock(write(tmp_path / "y" / "Pipfile.lock", "{bad")).errors
    assert parse_pipfile_lock(tmp_path / "none" / "Pipfile.lock").errors


# ------------------------------------------------------------------------- npm


def test_spec_classification() -> None:
    assert split_name_spec("@types/node@^20") == ("@types/node", "^20")
    assert split_name_spec("lodash") == ("lodash", "")
    assert classify_spec("npm:@scope/real@^1") == (SourceType.REGISTRY, "@scope/real")
    assert classify_spec("workspace:*")[0] is SourceType.WORKSPACE
    assert classify_spec("file:../x")[0] is SourceType.PATH
    assert classify_spec("github:user/repo")[0] is SourceType.GIT
    assert classify_spec("user/repo#main")[0] is SourceType.GIT
    assert classify_spec("https://x/y.tgz")[0] is SourceType.URL
    assert classify_spec("^1.2.3") == (SourceType.REGISTRY, None)


def test_package_json(tmp_path: Path) -> None:
    pj = write(
        tmp_path / "package.json",
        json.dumps(
            {
                "name": "demo",
                "dependencies": {"lodash": "^4", "alias": "npm:real-pkg@^1", "weird": 5},
                "devDependencies": {"jest": "^29"},
                "peerDependencies": {"react": ">=18"},
                "optionalDependencies": {"fsevents": "*"},
                "scripts": {"postinstall": "node x.js", "bad": 1},
                "publishConfig": {"registry": "https://npm.corp.example/"},
            },
            indent=2,
        ),
    )
    m = parse_package_json(pj)
    deps = {d.name: d for d in m.dependencies}
    assert deps["alias"].alias_of == "real-pkg" and deps["alias"].registry_name == "real-pkg"
    assert deps["jest"].kind is DependencyKind.DEV
    assert deps["react"].kind is DependencyKind.PEER
    assert deps["fsevents"].kind is DependencyKind.OPTIONAL
    assert deps["lodash"].location.line == 4
    assert m.scripts == {"postinstall": "node x.js"}
    assert m.indexes[0].role == "publish"
    assert parse_package_json(write(tmp_path / "a" / "package.json", "[1]")).errors
    assert parse_package_json(write(tmp_path / "b" / "package.json", "{")).errors
    assert parse_package_json(tmp_path / "c" / "package.json").errors


def test_package_lock_v3_and_v1(tmp_path: Path) -> None:
    v3 = {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            },
            "node_modules/a/node_modules/@s/b": {"version": "2.0.0", "dev": True},
            "node_modules/alias": {"name": "real", "version": "1.0.0"},
            "node_modules/ws-link": {"link": True},
            "node_modules/g": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/g.git"},
            "node_modules/f": {"version": "1.0.0", "resolved": "file:../f"},
            "packages/x": {"version": "1.0.0"},
        },
    }
    deps = {
        d.name: d
        for d in parse_package_lock(
            write(tmp_path / "package-lock.json", json.dumps(v3))
        ).dependencies
    }
    assert set(deps) == {"a", "@s/b", "alias", "ws-link", "g", "f"}
    assert deps["@s/b"].kind is DependencyKind.DEV
    assert deps["alias"].alias_of == "real"
    assert deps["ws-link"].source_type is SourceType.WORKSPACE
    assert deps["g"].source_type is SourceType.GIT
    assert deps["f"].source_type is SourceType.PATH

    v1 = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "al": {"version": "npm:real@1.2.3"},
            "junk": 3,
        },
    }
    deps1 = {
        d.name: d
        for d in parse_package_lock(
            write(tmp_path / "v1" / "package-lock.json", json.dumps(v1))
        ).dependencies
    }
    assert set(deps1) == {"a", "b", "al"}
    assert deps1["al"].alias_of == "real" and deps1["al"].version == "1.2.3"


YARN_V1 = """# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.12.13.tgz"
  dependencies:
    "@babel/highlight" "^7.12.13"

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

my-alias@npm:real-thing@^1.0.0:
  version "1.0.0"
"""

YARN_BERRY = """__metadata:
  version: 6

"lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"dep@https://example.com/dep.tgz":
  version: 1.0.0
"""


def test_yarn_lock_v1_and_berry(tmp_path: Path) -> None:
    deps = {d.name: d for d in parse_yarn_lock(write(tmp_path / "yarn.lock", YARN_V1)).dependencies}
    assert deps["@babel/code-frame"].version == "7.12.13"
    assert deps["@babel/code-frame"].location.line == 4
    assert deps["lodash"].resolved is not None and "yarnpkg" in deps["lodash"].resolved
    assert deps["my-alias"].alias_of == "real-thing"
    berry = {
        d.name: d
        for d in parse_yarn_lock(write(tmp_path / "b" / "yarn.lock", YARN_BERRY)).dependencies
    }
    assert berry["lodash"].alias_of is None and berry["lodash"].version == "4.17.21"
    assert berry["app"].source_type is SourceType.WORKSPACE
    assert berry["dep"].source_type is SourceType.URL
    assert parse_yarn_lock(tmp_path / "missing" / "yarn.lock").errors


def test_npmrc(tmp_path: Path) -> None:
    rc = write(
        tmp_path / ".npmrc",
        "; comment\nregistry=https://registry.npmjs.org/\n@acme:registry=https://npm.acme.example/\n"
        "//npm.acme.example/:_authToken=${NPM_TOKEN}\nnoequals\n",
    )
    m = parse_npmrc(rc)
    assert [(i.role, i.scope) for i in m.indexes] == [("primary", None), ("scope", "@acme")]
    assert parse_npmrc(tmp_path / "none" / ".npmrc").errors


# -------------------------------------------------------------------- discovery


def test_parser_dispatch_and_discovery(tmp_path: Path) -> None:
    for rel in (
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "constraints.txt",
        "requirements/base.txt",
        "app/package.json",
        "app/node_modules/x/package.json",
        ".venv/lib/pyproject.toml",
        "notes.txt",
        "uv.lock",
    ):
        write(tmp_path / rel, "")
    found = [p.relative_to(tmp_path).as_posix() for p in discover(tmp_path)]
    assert found == [
        "constraints.txt",
        "dev-requirements.txt",
        "requirements-dev.txt",
        "requirements.txt",
        "uv.lock",
        "app/package.json",
        "requirements/base.txt",
    ]
    assert list(discover(tmp_path / "requirements.txt")) == [tmp_path / "requirements.txt"]
    assert list(discover(tmp_path / "notes.txt")) == []
    assert parser_for(Path("x/setup.py")) is not None
    assert parse_file(tmp_path / "notes.txt") is None
    parsed = parse_file(tmp_path / "requirements.txt")
    assert parsed is not None and parsed.ecosystem is Ecosystem.PYPI
