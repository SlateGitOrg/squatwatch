"""Build-hook review of one package source (directory or archive).

For Python packages: ``setup.py`` (module code, setuptools command subclasses,
``cmdclass``), the ``[build-system]`` table and any in-tree PEP 517 backend, and
``.pth`` files (wheels: executed by ``site`` at every interpreter start-up).
For npm packages: install lifecycle scripts and the JavaScript files they run.
Literal dependency lists are extracted on the way so they can be name-checked.
"""

from __future__ import annotations

import logging
from pathlib import Path

from squatwatch.errors import ArchiveError
from squatwatch.hooks.common import Hit, finalise
from squatwatch.hooks.pyast import review_python
from squatwatch.hooks.shell import INSTALL_HOOKS, review_script
from squatwatch.hooks.tree import ArchiveTree, DirectoryTree, SourceTree, is_archive
from squatwatch.models import Ecosystem, Finding, Location, ScanResult, Severity
from squatwatch.parsers.npm import parse_package_json_text
from squatwatch.parsers.pyproject import parse_pyproject_text
from squatwatch.parsers.setuppy import parse_setup_source

log = logging.getLogger(__name__)

KNOWN_BACKENDS = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "hatchling.build",
        "flit_core.buildapi",
        "flit.buildapi",
        "poetry.core.masonry.api",
        "poetry.masonry.api",
        "pdm.backend",
        "pdm.pep517.api",
        "maturin",
        "scikit_build_core.build",
        "mesonpy",
        "uv_build",
        "sipbuild.api",
        "enscons.api",
        "whey",
        "pbr.build",
    }
)


def review_path(path: Path, *, third_party: bool = True) -> ScanResult:
    """Review a directory or archive; archive read errors become result errors."""
    if is_archive(path):
        try:
            tree: SourceTree = ArchiveTree(path)
        except ArchiveError as exc:
            return ScanResult(errors=[str(exc)])
    elif path.is_dir():
        tree = DirectoryTree(path)
    else:
        return ScanResult(errors=[f"{path}: not a directory or supported archive"])
    return review_tree(tree, third_party=third_party)


def review_tree(tree: SourceTree, *, third_party: bool = True) -> ScanResult:
    """Run every applicable reviewer over ``tree``."""
    result = ScanResult(findings=list(tree.issues), files=[tree.label])
    files = set(tree.root_files())
    if "setup.py" in files:
        _review_setup_py(tree, result)
    if "pyproject.toml" in files:
        _review_pyproject(tree, result)
    for name in sorted(f for f in files if f.endswith(".pth")):
        _review_pth(tree, name, result)
    if "package.json" in files:
        _review_package_json(tree, result, third_party=third_party)
    return result


def _join(tree: SourceTree, rel: str) -> str:
    return f"{tree.label}/{rel}"


def _review_setup_py(tree: SourceTree, result: ScanResult) -> None:
    source = tree.read_text("setup.py")
    if source is None:
        return
    path = _join(tree, "setup.py")
    manifest = parse_setup_source(source, path)
    result.dependencies.extend(manifest.dependencies)
    package = manifest.package_name
    review = review_python(source, path, entry_context="module")
    if review.syntax_error is not None:
        result.findings.append(
            Finding(
                rule="SW300",
                severity=Severity.MEDIUM,
                title="build script could not be reviewed",
                message=(
                    f"setup.py is not valid Python 3 ({review.syntax_error}); it runs at "
                    "install time and could not be statically reviewed"
                ),
                location=Location(path),
                package=package,
                ecosystem=Ecosystem.PYPI,
            )
        )
        return
    result.findings.extend(finalise(review.hits, path, package=package))
    hooks = sorted(set(review.cmdclass) | set(review.hook_classes))
    if hooks:
        result.findings.append(
            Finding(
                rule="SW307",
                severity=Severity.LOW,
                title="custom install-time commands",
                message="setup.py overrides setuptools commands: " + ", ".join(hooks),
                location=Location(path),
                package=package,
                ecosystem=Ecosystem.PYPI,
                evidence={"commands": hooks},
            )
        )


def _review_pyproject(tree: SourceTree, result: ScanResult) -> None:
    text = tree.read_text("pyproject.toml")
    if text is None:
        return
    path = _join(tree, "pyproject.toml")
    manifest = parse_pyproject_text(text, path)
    result.dependencies.extend(manifest.dependencies)
    result.errors.extend(manifest.errors)
    build = manifest.build
    if build is None or build.backend is None:
        return
    package = manifest.package_name
    if build.backend_path:
        result.findings.append(
            Finding(
                rule="SW308",
                severity=Severity.MEDIUM,
                title="in-tree build backend",
                message=(
                    f"build-backend {build.backend!r} is loaded from the package itself "
                    f"(backend-path {list(build.backend_path)}); its code runs at build time"
                ),
                location=build.location,
                package=package,
                ecosystem=Ecosystem.PYPI,
            )
        )
        module = build.backend.split(":", 1)[0].replace(".", "/")
        for base in build.backend_path:
            for candidate in (f"{base}/{module}.py", f"{base}/{module}/__init__.py"):
                source = tree.read_text(candidate)
                if source is None:
                    continue
                backend_path = _join(tree, candidate.removeprefix("./"))
                review = review_python(source, backend_path, entry_context="build-backend")
                result.findings.extend(finalise(review.hits, backend_path, package=package))
    elif build.backend not in KNOWN_BACKENDS:
        result.findings.append(
            Finding(
                rule="SW308",
                severity=Severity.LOW,
                title="uncommon build backend",
                message=f"build-backend {build.backend!r} is not one of the widely used backends",
                location=build.location,
                package=package,
                ecosystem=Ecosystem.PYPI,
            )
        )


def _review_pth(tree: SourceTree, name: str, result: ScanResult) -> None:
    text = tree.read_text(name)
    if text is None:
        return
    path = _join(tree, name)
    hits: list[Hit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.startswith(("import ", "import\t")):
            continue
        result.findings.append(
            Finding(
                rule="SW312",
                severity=Severity.HIGH,
                title="executable .pth file",
                message=(
                    f"{name} line {lineno} starts with 'import', so Python executes it at "
                    "every interpreter start-up once the package is installed"
                ),
                location=Location(path, lineno),
                ecosystem=Ecosystem.PYPI,
                evidence={"line": line[:200]},
            )
        )
        review = review_python(line, path, entry_context="module")
        for hit in review.hits:
            hit.line = lineno
            hits.append(hit)
    result.findings.extend(finalise(hits, path))


def _review_package_json(tree: SourceTree, result: ScanResult, *, third_party: bool) -> None:
    text = tree.read_text("package.json")
    if text is None:
        return
    path = _join(tree, "package.json")
    manifest = parse_package_json_text(text, path)
    result.dependencies.extend(manifest.dependencies)
    result.errors.extend(manifest.errors)
    package = manifest.package_name
    hooks = {k: v for k, v in manifest.scripts.items() if k in INSTALL_HOOKS}
    if not hooks:
        return
    result.findings.append(
        Finding(
            rule="SW307",
            severity=Severity.LOW if third_party else Severity.INFO,
            title="install-time lifecycle scripts",
            message="package.json runs scripts at install: "
            + "; ".join(f"{k}: {v}" for k, v in sorted(hooks.items())),
            location=Location(path),
            package=package,
            ecosystem=Ecosystem.NPM,
            evidence={"scripts": hooks},
        )
    )
    hits: list[Hit] = []
    for hook, command in sorted(hooks.items()):
        hits.extend(review_script(hook, command, read_file=tree.read_text))
    for hit in hits:
        if hit.path is not None:
            hit.path = _join(tree, hit.path.removeprefix("./"))
    result.findings.extend(finalise(hits, path, package=package))
