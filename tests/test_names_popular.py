"""Name rules and the popular-package index (incl. filter-vs-brute-force property)."""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from squatwatch.errors import DataError
from squatwatch.models import Ecosystem
from squatwatch.names import collapse, is_valid_name, match_key, pypi_normalize, split_scope, tokens
from squatwatch.popular import PopularIndex, snapshot_metadata
from squatwatch.text.distance import osa_distance


def test_pypi_normalisation_and_keys() -> None:
    assert pypi_normalize("Django_Rest.Framework") == "django-rest-framework"
    assert match_key("Python_Dateutil", Ecosystem.PYPI) == "python-dateutil"
    assert match_key("Cross_Env", Ecosystem.NPM) == "cross_env"


def test_npm_scope_tokens_collapse() -> None:
    assert split_scope("@types/node") == ("@types", "node")
    assert split_scope("lodash") == (None, "lodash")
    assert tokens("@babel/plugin-transform-runtime", Ecosystem.NPM) == (
        "plugin",
        "transform",
        "runtime",
    )
    assert collapse("@types/node", Ecosystem.NPM) == "typesnode"
    assert collapse("python-date_util", Ecosystem.PYPI) == "pythondateutil"


@pytest.mark.parametrize(
    ("name", "eco", "valid"),
    [
        ("requests", Ecosystem.PYPI, True),
        ("zope.interface", Ecosystem.PYPI, True),
        ("-bad", Ecosystem.PYPI, False),
        ("rеquests", Ecosystem.PYPI, False),
        ("@types/node", Ecosystem.NPM, True),
        ("lodash", Ecosystem.NPM, True),
        ("_private", Ecosystem.NPM, False),
        ("has space", Ecosystem.NPM, False),
        ("@bad scope/x", Ecosystem.NPM, False),
        ("", Ecosystem.NPM, False),
        ("a" * 215, Ecosystem.NPM, False),
    ],
)
def test_validity(name: str, eco: Ecosystem, valid: bool) -> None:
    assert is_valid_name(name, eco) is valid


def test_index_basics(npm_index: PopularIndex) -> None:
    assert len(npm_index) == 13
    assert "@types/node" in npm_index
    assert "LODASH" in npm_index
    assert 3 not in npm_index
    entry = npm_index.get("lodash")
    assert entry is not None and entry.rank == 1
    assert npm_index.scope_rank("@babel") == 6
    assert set(npm_index.scopes()) == {"@types", "@babel"}
    assert [e.name for e in npm_index.scoped_with_base("cli")] == ["@babel/cli"]
    assert [e.name for e in npm_index.by_collapsed("nodesass")] == ["node-sass"]
    assert [e.name for e in npm_index.by_token_set(("yaml", "js"))] == ["js-yaml"]
    assert [e.name for e in npm_index.by_tokens(("js", "yaml"))] == ["js-yaml"]
    assert npm_index.within("lodash", 0) == []


def test_index_dedupes_and_rejects_empty() -> None:
    idx = PopularIndex(Ecosystem.PYPI, ["Requests", "requests", " ", "numpy"])
    assert [e.name for e in idx] == ["Requests", "numpy"]
    with pytest.raises(DataError):
        PopularIndex(Ecosystem.PYPI, ["", "  "])


def test_within_finds_neighbours(pypi_index: PopularIndex) -> None:
    hits = pypi_index.within("reqeusts", 2)
    assert [(e.name, d) for e, d in hits] == [("requests", 1)]
    assert pypi_index.within("zzzzzzzz", 2) == []


ALPHA = st.text(alphabet="abcde-", min_size=1, max_size=8)


@settings(max_examples=150, deadline=None)
@given(st.lists(ALPHA, min_size=1, max_size=40, unique=True), ALPHA, st.integers(1, 2))
def test_within_equals_brute_force(names: list[str], query: str, k: int) -> None:
    idx = PopularIndex(Ecosystem.NPM, names)
    expected = sorted(
        (osa_distance(query, e.key), e.rank) for e in idx if 0 < osa_distance(query, e.key) <= k
    )
    got = sorted((d, e.rank) for e, d in idx.within(query, k))
    assert got == expected


def test_bundled_snapshots_load_with_metadata() -> None:
    for eco in Ecosystem:
        idx = PopularIndex.bundled(eco)
        assert len(idx) > 10_000
        assert PopularIndex.bundled(eco) is idx  # cached
        meta = snapshot_metadata(eco)
        assert meta["ecosystem"] == eco.value
        assert len(meta["source-sha256"]) == 64
    assert PopularIndex.bundled(Ecosystem.PYPI).get("requests") is not None
    assert PopularIndex.bundled(Ecosystem.NPM).get("lodash") is not None


def test_from_text_skips_comments() -> None:
    idx = PopularIndex.from_text(Ecosystem.PYPI, "# header\nrequests\n\nnumpy\n", source="t")
    assert [e.name for e in idx] == ["requests", "numpy"]
    assert idx.source == "t"
    assert string.ascii_lowercase  # keep import used
