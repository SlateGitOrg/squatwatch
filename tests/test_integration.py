"""Config, scanner, reports and CLI against the bundled example projects."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from squatwatch.cli import EXIT_FINDINGS, EXIT_INPUT, EXIT_INTERNAL, EXIT_OK, main
from squatwatch.config import Config, load_config, parse_config
from squatwatch.errors import ConfigError
from squatwatch.models import Ecosystem, Finding, Location, ScanResult, Severity
from squatwatch.registry import FixtureRegistry
from squatwatch.report import render_json, render_sarif, render_text
from squatwatch.scanner import Scanner, severity_for_score
from tests.conftest import EXAMPLES, ROOT

CONFIG = EXAMPLES / "squatwatch.toml"

# ------------------------------------------------------------------- config


def test_load_example_config() -> None:
    cfg = load_config(CONFIG)
    assert cfg.fail_on is Severity.HIGH
    assert cfg.min_score == 0.6
    assert cfg.allow[Ecosystem.PYPI] == frozenset({"requests-mock"})
    assert cfg.allow[Ecosystem.NPM] == frozenset()
    assert cfg.registry_fixture == EXAMPLES / "registry.json"
    assert cfg.internal.npm_scopes == ("@acme",)
    assert cfg.checker_settings(Ecosystem.PYPI).allow == frozenset({"requests-mock"})


def test_config_discovery(tmp_path: Path) -> None:
    assert load_config(None, search_dir=tmp_path).source is None
    (tmp_path / "pyproject.toml").write_text(
        '[tool.squatwatch]\nfail-on = "medium"\nallow = ["x"]\n'
    )
    cfg = load_config(None, search_dir=tmp_path)
    assert cfg.fail_on is Severity.MEDIUM and cfg.allow[Ecosystem.NPM] == frozenset({"x"})
    assert load_config(tmp_path / "pyproject.toml").fail_on is Severity.MEDIUM
    (tmp_path / "squatwatch.toml").write_text('fail-on = "low"\n')
    assert load_config(None, search_dir=tmp_path).fail_on is Severity.LOW
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "pyproject.toml").write_text("[[broken")
    assert load_config(None, search_dir=bad).source is None


@pytest.mark.parametrize(
    "data",
    [
        {"unknown": 1},
        {"fail-on": 3},
        {"fail-on": "severe"},
        {"min-score": 2},
        {"min-score": True},
        {"hooks": "yes"},
        {"registry-fixture": 1},
        {"allow": "x"},
        {"internal": []},
        {"internal": {"nope": []}},
        {"internal": {"npm-scopes": ["acme"]}},
        {"internal": {"names": [1]}},
    ],
)
def test_config_validation(data: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_config(data, base_dir=Path(), source="t")


def test_config_file_errors(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")
    (tmp_path / "x.toml").write_text("= nope")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "x.toml")
    (tmp_path / "pyproject.toml").write_text("[tool]\nsquatwatch = 3\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "pyproject.toml")


# ------------------------------------------------------------------ scanner


@pytest.fixture(scope="module")
def example_result() -> ScanResult:
    cfg = load_config(CONFIG)
    assert cfg.registry_fixture is not None
    scanner = Scanner(cfg, registry=FixtureRegistry.from_file(cfg.registry_fixture))
    return scanner.scan([EXAMPLES / "webapp-py", EXAMPLES / "webapp-js"])


def rules_for(result: ScanResult, package: str) -> set[str]:
    return {f.rule for f in result.findings if f.package == package}


def test_example_scan_finds_every_planted_issue(example_result: ScanResult) -> None:
    r = example_result
    assert rules_for(r, "reqeusts") == {"SW101"}
    assert rules_for(r, "jeIlyfish") == {"SW102"}
    assert rules_for(r, "python3-dateutil") == {"SW101"}
    assert rules_for(r, "colourama") == {"SW101"}
    assert rules_for(r, "pytset") == {"SW101"}
    assert rules_for(r, "crossenv") == {"SW103"}
    assert rules_for(r, "lodahs") == {"SW101"}
    assert rules_for(r, "@typess/node") == {"SW104"}
    assert rules_for(r, "left-padd") == {"SW101"}  # alias target is what gets installed
    assert rules_for(r, "acme-billing") == {"SW201"}
    assert rules_for(r, "acme-auth") == {"SW202", "SW203"}
    assert rules_for(r, "@acme/ui-kit") == {"SW202", "SW203", "SW205"}
    assert any(f.rule == "SW204" for f in r.findings)
    assert any(f.rule == "SW307" and f.severity is Severity.INFO for f in r.findings)


def test_example_scan_has_no_false_alarms(example_result: ScanResult) -> None:
    flagged = {f.package for f in example_result.findings if f.rule.startswith("SW1")}
    for legit in (
        "requests",
        "flask",
        "urllib3",
        "numpy",
        "django",
        "express",
        "typescript",
        "requests-mock",
        "pytest",
        "sphinx",
    ):
        assert legit not in flagged
    assert example_result.errors == []


def test_scanner_errors_and_single_files(tmp_path: Path) -> None:
    scanner = Scanner(Config(hooks=False))
    result = scanner.scan([tmp_path / "missing", EXAMPLES / "squatwatch.toml"])
    assert len(result.errors) == 2
    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts\nrеquests\nnot valid !!\n")
    result = scanner.scan([req])
    assert {f.rule for f in result.findings} == {"SW101", "SW102", "SW106"}
    assert result.errors  # the invalid line
    assert scanner.check_name(Ecosystem.NPM, "lodahs")


def test_scan_archive_and_setup_hooks(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "setup.py").write_text(
        "import os\nos.system('make')\nfrom setuptools import setup\nsetup()\n"
    )
    result = Scanner(Config()).scan([proj, EXAMPLES / "archives" / "hooked-sdist-0.1.0.tar.gz"])
    assert any(f.rule == "SW302" and "proj" in str(f.location) for f in result.findings)
    assert any(f.rule == "SW309" for f in result.findings)
    assert any(f.package == "reqeusts" for f in result.findings)
    no_hooks = Scanner(Config(hooks=False)).scan([proj])
    assert no_hooks.findings == []


def test_internal_names_are_not_name_checked() -> None:
    cfg = load_config(CONFIG)
    findings = Scanner(cfg).check_name(Ecosystem.PYPI, "acme-requests")
    assert findings == []


def test_severity_bands() -> None:
    assert severity_for_score(0.9) is Severity.HIGH
    assert severity_for_score(0.7) is Severity.MEDIUM
    assert severity_for_score(0.6) is Severity.LOW


# ------------------------------------------------------------------ reports


def test_reports_render(example_result: ScanResult) -> None:
    doc = json.loads(render_json(example_result, fail_on=Severity.HIGH))
    assert doc["schema"] == 1
    assert doc["summary"]["findings"] == len(example_result.findings)
    severities = [f["severity"] for f in doc["findings"]]
    order = ["critical", "high", "medium", "low", "info"]
    assert severities == sorted(severities, key=order.index)
    sarif = json.loads(render_sarif(example_result))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {
        f.rule for f in example_result.findings
    }
    assert all(res["level"] in ("error", "warning", "note") for res in run["results"])
    text = render_text(example_result, fail_on=Severity.HIGH, verbose=True)
    assert "evidence:" in text and "at or above fail-on=high" in text


def test_text_report_lists_errors() -> None:
    result = ScanResult(
        findings=[Finding("SW101", Severity.LOW, "t", "m", location=None)],
        errors=["boom"],
    )
    text = render_text(result, fail_on=Severity.HIGH)
    assert "errors:\n  boom" in text and "1 low" in text
    assert json.loads(render_sarif(result))["runs"][0]["results"][0].get("locations") is None
    loc_only = ScanResult(
        findings=[Finding("SW204", Severity.HIGH, "t", "m", location=Location("f"))]
    )
    assert "region" not in render_sarif(loc_only)


# ---------------------------------------------------------------------- cli


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_cli_scan_exit_codes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    py = str(EXAMPLES / "webapp-py")
    code, out, _ = run(capsys, "scan", py, "--config", str(CONFIG))
    assert code == EXIT_FINDINGS and "SW201" in out
    code, out, _ = run(
        capsys, "scan", py, "--config", str(CONFIG), "--fail-on", "critical", "--format", "json"
    )
    assert code == EXIT_FINDINGS and json.loads(out)["summary"]["fail_on"] == "critical"
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "requirements.txt").write_text("requests==2.32.3\nflask\n")
    assert run(capsys, "scan", str(clean))[0] == EXIT_OK
    (clean / "requirements.txt").write_text("requests==2.32.3\nnot valid !!\n")
    assert run(capsys, "scan", str(clean))[0] == EXIT_INPUT
    assert run(capsys, "scan", str(clean), "--ignore-errors")[0] == EXIT_OK
    out_file = tmp_path / "r.sarif"
    assert (
        run(
            capsys, "scan", str(clean), "--ignore-errors", "--format", "sarif", "-o", str(out_file)
        )[0]
        == 0
    )
    assert json.loads(out_file.read_text())["version"] == "2.1.0"


def test_cli_scan_options(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    js = str(EXAMPLES / "webapp-js")
    code, out, _ = run(
        capsys,
        "scan",
        js,
        "--internal-scope",
        "@acme",
        "--internal",
        "acme-x",
        "--registry",
        str(EXAMPLES / "registry.json"),
        "--no-hooks",
        "--min-score",
        "0.9",
        "--format",
        "json",
    )
    doc = json.loads(out)
    rules = {f["rule"] for f in doc["findings"]}
    assert "SW202" in rules and "SW307" not in rules
    assert {f["package"] for f in doc["findings"] if f["rule"].startswith("SW1")} == {
        "@typess/node"
    }
    code, _, err = run(capsys, "scan", js, "--config", str(tmp_path / "nope.toml"))
    assert code == EXIT_INPUT and "cannot read config" in err


def test_cli_check_review_snapshot(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "check", "-e", "pypi", "reqeusts", "requests")
    assert code == EXIT_FINDINGS and "reqeusts" in out
    assert run(capsys, "check", "-e", "npm", "lodash")[0] == EXIT_OK
    code, out, _ = run(capsys, "review", str(EXAMPLES / "archives" / "clean-sdist-1.0.0.tar.gz"))
    assert code == EXIT_OK
    code, out, _ = run(capsys, "review", str(EXAMPLES / "archives" / "inert-npm-fixture-0.1.0.tgz"))
    assert code == EXIT_FINDINGS and "SW310" in out
    code, out, _ = run(capsys, "snapshot")
    assert code == EXIT_OK and "pypi: 11999 names" in out


def test_cli_usage_and_internal_errors(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["check", "-e", "pypi", "x", "--min-score", "7"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit):
        main(["check", "-e", "pypi", "x", "--min-score", "abc"])
    with pytest.raises(SystemExit):
        main(["scan", ".", "--fail-on", "severe"])

    def boom(*_: object, **__: object) -> ScanResult:
        raise RuntimeError("bug")

    monkeypatch.setattr(Scanner, "scan", boom)
    assert main(["scan", str(EXAMPLES)]) == EXIT_INTERNAL
    capsys.readouterr()


def test_cli_eval_small_dataset(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    data = tmp_path / "eval"
    data.mkdir()
    shutil.copy(ROOT / "data" / "eval" / "incidents.csv", data / "incidents.csv")
    (data / "benign-pypi.txt").write_text("# header\nflask-cors\npytest-xdist\n")
    (data / "benign-npm.txt").write_text("left-pad\n")
    out = tmp_path / "RESULTS.md"
    assert main(["eval", "--data-dir", str(data), "-o", str(out)]) == EXIT_OK
    report = out.read_text()
    assert "Threshold sweep (dev split only)" in report and "Historical incidents" in report
