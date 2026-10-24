from __future__ import annotations

from pathlib import Path

import pytest

from squatwatch.checker import CheckerSettings, NameChecker
from squatwatch.models import Ecosystem
from squatwatch.popular import PopularIndex

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"

PYPI_NAMES = [
    "requests",
    "urllib3",
    "python-dateutil",
    "setuptools",
    "numpy",
    "django",
    "jellyfish",
    "colorama",
    "pytest",
    "tensorflow",
    "beautifulsoup4",
    "flask",
    "toml",
]
NPM_NAMES = [
    "lodash",
    "react",
    "cross-env",
    "express",
    "@types/node",
    "@babel/core",
    "@babel/cli",
    "node-sass",
    "js-yaml",
    "jquery",
    "electron",
    "twilio",
    "eslint",
]


@pytest.fixture(scope="session")
def pypi_index() -> PopularIndex:
    return PopularIndex(Ecosystem.PYPI, PYPI_NAMES, source="test")


@pytest.fixture(scope="session")
def npm_index() -> PopularIndex:
    return PopularIndex(Ecosystem.NPM, NPM_NAMES, source="test")


@pytest.fixture(scope="session")
def pypi_checker(pypi_index: PopularIndex) -> NameChecker:
    return NameChecker(pypi_index, CheckerSettings(min_score=0.0))


@pytest.fixture(scope="session")
def npm_checker(npm_index: PopularIndex) -> NameChecker:
    return NameChecker(npm_index, CheckerSettings(min_score=0.0))


@pytest.fixture(scope="session")
def bundled_pypi() -> NameChecker:
    return NameChecker(PopularIndex.bundled(Ecosystem.PYPI))


@pytest.fixture(scope="session")
def bundled_npm() -> NameChecker:
    return NameChecker(PopularIndex.bundled(Ecosystem.NPM))
