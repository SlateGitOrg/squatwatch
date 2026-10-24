"""Edit distance, keyboard adjacency and confusable skeletons (incl. property tests)."""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from squatwatch.text.distance import EditOp, edit_script, osa_distance
from squatwatch.text.homoglyph import confusable_chars, inspect_glyphs, skeleton
from squatwatch.text.keyboard import is_adjacent, neighbours

names = st.text(alphabet=string.ascii_lowercase[:6] + "-", max_size=9)


def apply(source: str, ops: list[EditOp]) -> str:
    """Apply an edit script (positions refer to the original source)."""
    out: list[str] = []
    i = 0
    for op in ops:
        out.append(source[i : op.position])
        i = op.position
        if op.kind == "insert":
            out.append(op.target)
        elif op.kind == "delete":
            i += 1
        elif op.kind == "substitute":
            out.append(op.target)
            i += 1
        else:
            out.append(op.target)
            i += 2
    out.append(source[i:])
    return "".join(out)


def full_osa(a: str, b: str) -> int:
    """Independent textbook OSA implementation used as the oracle."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + c)
    return d[len(a)][len(b)]


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("requests", "requests", 0),
        ("requests", "reqeusts", 1),
        ("requests", "requets", 1),
        ("requests", "requestss", 1),
        ("requests", "rewuests", 1),
        ("ca", "abc", 3),  # OSA (restricted) differs from unrestricted DL (2) here
        ("", "abc", 3),
        ("abc", "", 3),
        ("kitten", "sitting", 3),
    ],
)
def test_osa_known_values(a: str, b: str, expected: int) -> None:
    assert osa_distance(a, b) == expected


def test_osa_bound_reports_k_plus_one() -> None:
    assert osa_distance("abcdef", "uvwxyz", 2) == 3
    assert osa_distance("abc", "abcdef", 1) == 2
    assert osa_distance("ab", "", 5) == 2
    with pytest.raises(ValueError, match="non-negative"):
        osa_distance("a", "b", -1)


@settings(max_examples=300, deadline=None)
@given(names, names, st.integers(min_value=0, max_value=4))
def test_bounded_osa_matches_oracle(a: str, b: str, k: int) -> None:
    exact = full_osa(a, b)
    assert osa_distance(a, b) == exact
    assert osa_distance(a, b, k) == min(exact, k + 1)


@settings(max_examples=200, deadline=None)
@given(names, names)
def test_osa_symmetric_and_bounded_by_lengths(a: str, b: str) -> None:
    d = osa_distance(a, b)
    assert d == osa_distance(b, a)
    assert abs(len(a) - len(b)) <= d <= max(len(a), len(b))


@settings(max_examples=200, deadline=None)
@given(names, names)
def test_edit_script_is_minimal_and_correct(a: str, b: str) -> None:
    ops = edit_script(a, b)
    assert len(ops) == osa_distance(a, b)
    assert apply(a, ops) == b


def test_edit_script_kinds() -> None:
    assert edit_script("requests", "reqeusts") == [EditOp("transpose", 3, "ue", "eu")]
    assert edit_script("urllib3", "urlib3")[0].kind == "delete"
    assert edit_script("numpy", "numpyy")[0].kind == "insert"
    assert edit_script("flask", "flaak") == [EditOp("substitute", 3, "s", "a")]


def test_keyboard_neighbours() -> None:
    assert neighbours("g") == frozenset("tyfhvb")
    assert is_adjacent("r", "t")
    assert is_adjacent("Q", "w")
    assert not is_adjacent("a", "a")
    assert not is_adjacent("a", "p")
    assert neighbours("é") == frozenset()


@pytest.mark.parametrize(
    ("raw", "genuine"),
    [
        ("jeIlyfish", "jellyfish"),
        ("pyth0n", "python"),
        ("reqиests", "reqиests"),
        ("rеquests", "requests"),  # Cyrillic e
        ("ｒｅｑｕｅｓｔｓ", "requests"),  # full-width
        ("modern", "modem"),  # rn -> m
    ],
)
def test_skeleton_collapses_confusables(raw: str, genuine: str) -> None:
    assert skeleton(raw) == skeleton(genuine)


def test_skeleton_keeps_distinct_names_apart() -> None:
    assert skeleton("django") != skeleton("djanga")
    assert skeleton("python-dateutil") != skeleton("pythondateutil")


def test_glyph_inspection() -> None:
    report = inspect_glyphs("rеquests")
    assert report.non_ascii == ("е",)
    assert report.mixed_script
    assert not inspect_glyphs("requests").mixed_script
    assert confusable_chars("jeIlyfish", "jellyfish") == [("I", "l")]
    assert confusable_chars("Requests", "requests") == []
