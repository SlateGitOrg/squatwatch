"""Typosquat signals and scoring."""

from __future__ import annotations

import pytest

from squatwatch.checker import CheckerSettings, NameChecker, allowed_distance
from squatwatch.models import Ecosystem
from squatwatch.popular import PopularIndex


@pytest.mark.parametrize(
    ("name", "target", "technique"),
    [
        ("reqeusts", "requests", "transposition"),
        ("urlib3", "urllib3", "omission"),
        ("requestss", "requests", "repetition"),
        ("reqzuests", "requests", "insertion"),
        ("requesrs", "requests", "keyboard"),
        ("requexts", "requests", "keyboard"),
        ("djanga", "django", "substitution"),
        ("jeIlyfish", "jellyfish", "homoglyph"),
        ("r3quests", "requests", "keyboard"),
        ("num0y", "numpy", "keyboard"),
        ("nump0", "numpy", "substitution"),
        ("t0ml", "toml", "homoglyph"),
        ("setup-tools", "setuptools", "separator"),
        ("pythondateutil", "python-dateutil", "separator"),
        ("dateutil-python", "python-dateutil", "token-order"),
        ("python3-dateutil", "python-dateutil", "combo"),
        ("requests-dev", "requests", "combo"),
        ("numpy2", "numpy", "version-digit"),
        ("pyrequests", "requests", "combo"),
        ("tensoflw", "tensorflow", "edit-2"),
    ],
)
def test_pypi_techniques(pypi_checker: NameChecker, name: str, target: str, technique: str) -> None:
    verdict = pypi_checker.best(name)
    assert verdict is not None
    assert verdict.target.name == target
    assert technique in verdict.techniques


@pytest.mark.parametrize(
    ("name", "target", "technique"),
    [
        ("crossenv", "cross-env", "separator"),
        ("cross_env", "cross-env", "separator"),
        ("cross-env.js", "cross-env", "combo"),
        ("nodesass", "node-sass", "separator"),
        ("jquery.js", "jquery", "combo"),
        ("electorn", "electron", "transposition"),
        ("twilio-npm", "twilio", "combo"),
        ("@typess/node", "@types/node", "scope"),
        ("types-node", "@types/node", "scope-flatten"),
        ("babelcore", "@babel/core", "scope-flatten"),
        ("@evil/lodash", "lodash", "re-scope"),
        ("yaml-js", "js-yaml", "token-order"),
        ("nodelodash", "lodash", "combo"),
        ("reactjs", "react", "combo"),
    ],
)
def test_npm_techniques(npm_checker: NameChecker, name: str, target: str, technique: str) -> None:
    verdict = npm_checker.best(name)
    assert verdict is not None
    assert verdict.target.name == target
    assert technique in verdict.techniques


def test_popular_names_and_case_variants_are_not_flagged(pypi_checker: NameChecker) -> None:
    for name in ("requests", "Requests", "python_dateutil", "Django"):
        assert pypi_checker.best(name) is None


def test_unrelated_names_are_not_flagged(pypi_checker: NameChecker) -> None:
    assert pypi_checker.best("totally-unrelated-name") is None
    assert pypi_checker.best("") is None


def test_non_ascii_lookalike_of_popular_is_flagged(pypi_checker: NameChecker) -> None:
    verdict = pypi_checker.best("rеquests")  # Cyrillic e
    assert verdict is not None
    assert verdict.primary.technique == "homoglyph"
    assert verdict.score >= 0.9
    assert "mixes scripts" in verdict.primary.detail


def test_names_under_a_popular_scope_are_trusted(npm_checker: NameChecker) -> None:
    # Only @babel's owners can publish @babel/*, so look-alikes there are not squats.
    assert npm_checker.best("@babel/cor") is None


def test_threshold_and_allowlist(pypi_index: PopularIndex) -> None:
    strict = NameChecker(pypi_index, CheckerSettings(min_score=0.99))
    assert strict.check("reqeusts") is None
    allowed = NameChecker(pypi_index, CheckerSettings(min_score=0.0, allow=frozenset({"Reqeusts"})))
    assert allowed.check("reqeusts") is None
    loose = NameChecker(pypi_index, CheckerSettings(min_score=0.0))
    assert set(loose.check_many(["reqeusts", "requests", "zzzzzz"])) == {"reqeusts"}


def test_rank_and_short_name_adjustments() -> None:
    idx = PopularIndex(
        Ecosystem.PYPI, ["requests", *[f"filler{i}" for i in range(6000)], "obscurelib"]
    )
    checker = NameChecker(idx, CheckerSettings(min_score=0.0))
    popular = checker.best("reqeusts")
    rare = checker.best("obscurleib")
    assert popular is not None and rare is not None
    assert popular.score > rare.score  # rank 1 vs rank 6002
    short = NameChecker(PopularIndex(Ecosystem.PYPI, ["toml"]), CheckerSettings(min_score=0.0))
    verdict = short.best("tmol")
    # transposition weight 0.72 + top-100 bonus 0.12 - 4-character penalty 0.14
    assert verdict is not None and verdict.score == pytest.approx(0.70)


def test_multiple_families_add_a_bonus(pypi_checker: NameChecker) -> None:
    verdict = pypi_checker.best("python3-dateutil")
    assert verdict is not None
    assert {"combo", "insertion"} <= set(verdict.techniques)
    single = pypi_checker.best("requests-dev")
    assert single is not None
    assert verdict.score > single.score - 0.2


def test_allowed_distance_bands() -> None:
    assert [allowed_distance(n) for n in (3, 4, 7, 8, 20)] == [0, 1, 1, 2, 2]


def test_bundled_snapshot_flags_documented_incident_names(
    bundled_pypi: NameChecker, bundled_npm: NameChecker
) -> None:
    for name in ("jeIlyfish", "python3-dateutil", "colourama", "dajngo", "urlib3", "setup-tools"):
        assert bundled_pypi.check(name) is not None, name
    for name in ("crossenv", "electorn", "twilio-npm", "jquery.js", "mongose"):
        assert bundled_npm.check(name) is not None, name
    for name in ("requests", "numpy", "flask-cors", "pytest-xdist"):
        assert bundled_pypi.check(name) is None, name
