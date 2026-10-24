"""Evaluation harness: splits, variant generation, metrics and report."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from squatwatch.checker import CheckerSettings, NameChecker
from squatwatch.errors import DataError
from squatwatch.evaluation import (
    EXPOSED_FILE,
    EXPOSED_SPLIT,
    MAX_DEV_FPR,
    TECHNIQUES,
    EvalItem,
    Metrics,
    Scored,
    best_threshold,
    build_dataset,
    default_thresholds,
    generate_variants,
    load_benign,
    load_exposed,
    load_incidents,
    metrics_at,
    render_markdown,
    score_items,
    split_of,
    target_correct,
)
from squatwatch.models import Ecosystem
from squatwatch.popular import PopularIndex
from tests.conftest import ROOT


def item(name: str, malicious: bool, split: str = "test", target: str = "") -> EvalItem:
    return EvalItem(
        name, Ecosystem.PYPI, malicious, target, "t", "generated" if malicious else "benign", split
    )


def test_split_is_deterministic_and_balanced() -> None:
    assert split_of("pypi:requests") == split_of("pypi:requests")
    splits = [split_of(f"k{i}") for i in range(2000)]
    assert 0.45 < splits.count("dev") / len(splits) < 0.55


def test_metrics_and_threshold_selection() -> None:
    scored = [
        Scored(item("a", True), 0.9, "x", ()),
        Scored(item("b", True), 0.5, "x", ()),
        Scored(item("c", False), 0.7, "y", ()),
        Scored(item("d", False), 0.1, None, ()),
    ]
    m = metrics_at(scored, 0.6)
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert m.precision == 0.5 and m.recall == 0.5 and m.f1 == 0.5 and m.fpr == 0.5
    empty = Metrics(0.5, 0, 0, 0, 0)
    assert empty.precision == empty.recall == empty.f1 == empty.fpr == 0.0
    rows = [Metrics(0.4, 10, 5, 0, 95), Metrics(0.6, 9, 2, 1, 98), Metrics(0.8, 5, 0, 5, 100)]
    assert best_threshold(rows).threshold == 0.6  # 0.4 has FPR 5% > cap
    assert best_threshold([Metrics(0.4, 1, 50, 0, 50)]).threshold == 0.4  # nothing eligible
    with pytest.raises(ValueError):
        best_threshold([])
    assert MAX_DEV_FPR == 0.03
    assert default_thresholds()[0] == 0.4 and default_thresholds()[-1] == 0.9


def test_target_correct() -> None:
    s = Scored(item("reqeusts", True, target="Requests"), 0.8, "requests", ())
    assert target_correct(s)
    assert not target_correct(Scored(item("x", True), 0.8, "requests", ()))


def test_generate_variants_properties() -> None:
    idx = PopularIndex.bundled(Ecosystem.NPM)
    items = generate_variants(idx, targets_per_ecosystem=60, exclude=["lodahs"])
    again = generate_variants(idx, targets_per_ecosystem=60, exclude=["lodahs"])
    assert items == again  # deterministic
    assert {i.technique for i in items} <= set(TECHNIQUES)
    assert all(i.name not in idx for i in items)
    by_target: dict[str, set[str]] = {}
    for i in items:
        by_target.setdefault(i.target, set()).add(i.split)
        if i.target.startswith("@"):
            assert i.technique == "scope"
    assert all(len(s) == 1 for s in by_target.values())  # no target straddles splits


def test_loaders_and_errors(tmp_path: Path) -> None:
    incidents = load_incidents(ROOT / "data" / "eval" / "incidents.csv")
    assert all(i.split == "test" and i.malicious for i in incidents)
    assert {i.name for i in incidents} >= {"jeIlyfish", "crossenv", "colourama"}
    assert "torchtriton" not in {i.name for i in incidents}  # confusion, not a typosquat
    with pytest.raises(DataError):
        load_incidents(tmp_path / "missing.csv")
    bad = tmp_path / "bad.csv"
    bad.write_text("name,ecosystem,kind\nx,cargo,typosquat\n")
    with pytest.raises(DataError):
        load_incidents(bad)
    with pytest.raises(DataError):
        load_benign(tmp_path / "missing.txt", Ecosystem.NPM)
    assert load_exposed(tmp_path / "missing.txt") == frozenset()
    with pytest.raises(DataError):
        load_exposed(tmp_path)  # a directory, not a file
    listed = tmp_path / "exposed.txt"
    listed.write_text("# header\ncrossenv   # reason\n\n")
    assert load_exposed(listed) == {"crossenv"}
    split = {
        i.name: i.split for i in load_incidents(ROOT / "data/eval/incidents.csv", {"crossenv"})
    }
    assert split["crossenv"] == EXPOSED_SPLIT and split["colourama"] == "test"


_DATA_PROVENANCE = ("src/squatwatch/data/", "src/squatwatch/hooks/")
_SCANNED = (
    "src/squatwatch/",
    "tests/",
    "examples/",
    "scripts/demo.sh",
    "scripts/build_archives.py",
)


def test_dev_exposed_list_is_complete() -> None:
    """Every incident name that appears where it could shape the detector (code,
    tests, fixtures, rule examples) must be in the exposed list, so it is never
    counted as held out; and every listed name must be a real incident name."""
    names = {i.name for i in load_incidents(ROOT / "data" / "eval" / "incidents.csv")}
    exposed = load_exposed(ROOT / "data" / "eval" / EXPOSED_FILE)
    assert exposed <= names
    token = re.compile(r"[@\w][\w@/.\-]*")
    files = [ROOT / "docs" / "RULES.md"]
    for prefix in _SCANNED:
        path = ROOT / prefix
        files += sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    seen: dict[str, str] = {}
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        if rel.startswith(_DATA_PROVENANCE) or "__pycache__" in rel:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # fixture archives
        for tok in token.findall(text):
            for cand in (tok, tok.rstrip(".")):
                if cand in names:
                    seen.setdefault(cand, rel)
    missing = {n: where for n, where in seen.items() if n not in exposed}
    assert not missing, f"incident names used in development but not in {EXPOSED_FILE}: {missing}"


def test_end_to_end_report(tmp_path: Path) -> None:
    (tmp_path / "incidents.csv").write_text(
        "name,ecosystem,target,kind,incident\n"
        "reqeusts,pypi,requests,typosquat,demo\n"
        "zzzzzz,pypi,,typosquat,demo\n"
        "crossenv,npm,cross-env,typosquat,demo2\n"
    )
    (tmp_path / "benign-pypi.txt").write_text("flask-cors\n")
    (tmp_path / "benign-npm.txt").write_text("left-pad\n")
    (tmp_path / EXPOSED_FILE).write_text("crossenv  # used in a test\n")
    indexes = {eco: PopularIndex.bundled(eco) for eco in Ecosystem}
    items = build_dataset(tmp_path, indexes)
    checkers = {eco: NameChecker(indexes[eco], CheckerSettings(min_score=0.0)) for eco in Ecosystem}
    scored = score_items(items, checkers)
    report = render_markdown(
        scored,
        shipped_threshold=0.6,
        in_snapshot=lambda i: bool(i.target) and i.target in indexes[i.ecosystem],
    )
    assert "| demo | 2 | 50.0% |" in report
    assert "demo2" not in report.split("## Development-exposed")[0]  # excluded from results
    assert "| `crossenv` | demo2 |" in report
    assert "| development-exposed only | 1 |" in report
    assert "`zzzzzz`" in report
    assert "Selection rule" in report
