"""Golden tests: the demo scan's JSON report and the fixture archives are stable.

Regenerate the golden file deliberately with:
    SQUATWATCH_UPDATE_GOLDEN=1 uv run pytest tests/test_golden.py
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from squatwatch.cli import main
from tests.conftest import ROOT

GOLDEN = ROOT / "tests" / "golden" / "examples-scan.json"


def test_demo_scan_matches_golden(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(ROOT)
    code = main(
        [
            "scan",
            "examples/webapp-py",
            "examples/webapp-js",
            "--config",
            "examples/squatwatch.toml",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    assert code == 1
    doc = json.loads(out)
    doc["tool"]["version"] = "<version>"
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    if os.environ.get("SQUATWATCH_UPDATE_GOLDEN"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(rendered, encoding="utf-8")
    assert rendered == GOLDEN.read_text(encoding="utf-8")


def _load_build_archives() -> object:
    spec = importlib.util.spec_from_file_location(
        "build_archives", ROOT / "scripts" / "build_archives.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_archives_are_reproducible() -> None:
    module = _load_build_archives()
    archives = module.build()  # type: ignore[attr-defined]
    for name, data in archives.items():
        committed = Path(ROOT / "examples" / "archives" / name).read_bytes()
        assert committed == data, f"{name} differs; run scripts/build_archives.py"
