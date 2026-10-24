"""Restricted Damerau-Levenshtein (optimal string alignment) distance.

squatwatch measures name similarity with the *restricted* Damerau-Levenshtein
distance, also called optimal string alignment (OSA): the minimum number of
single-character insertions, deletions, substitutions and transpositions of two
adjacent characters, where no substring is edited more than once. That matches the
typo model the detector cares about: one slip of the finger is one operation.

Two entry points:

* :func:`osa_distance` — banded, early-exit dynamic programme used on the hot path.
  With a bound ``k`` it only fills the diagonal band ``|i - j| <= k`` and stops as
  soon as a whole row exceeds ``k``: ``O(k * min(m, n))`` time, ``O(n)`` space.
* :func:`edit_script` — full ``O(m * n)`` table with traceback, used only for the
  handful of pairs that are reported, to explain *which* edits turn one name into
  the other (omission, repetition, transposition, keyboard slip, ...).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OpKind = Literal["insert", "delete", "substitute", "transpose"]


@dataclass(frozen=True, slots=True)
class EditOp:
    """One edit that transforms the *source* string into the *target* string.

    ``position`` is the index in the source string where the edit applies. For an
    insertion it is the index the new character is inserted before.
    """

    kind: OpKind
    position: int
    source: str
    target: str


def osa_distance(a: str, b: str, max_distance: int | None = None) -> int:
    """Return the OSA distance between ``a`` and ``b``.

    When ``max_distance`` is given the result is exact if it is ``<= max_distance``
    and ``max_distance + 1`` otherwise, which lets callers reject far-apart pairs
    in time proportional to the band width rather than the full table.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    k = max(la, lb) if max_distance is None else max_distance
    if k < 0:
        raise ValueError("max_distance must be non-negative")
    inf = k + 1
    if abs(la - lb) > k:
        return inf
    if la == 0 or lb == 0:
        return min(max(la, lb), inf)

    prev2: list[int] = []
    prev = [j if j <= k else inf for j in range(lb + 1)]
    for i in range(1, la + 1):
        cur = [inf] * (lb + 1)
        cur[0] = i if i <= k else inf
        row_min = cur[0]
        ai = a[i - 1]
        lo = max(1, i - k)
        hi = min(lb, i + k)
        for j in range(lo, hi + 1):
            bj = b[j - 1]
            cost = 0 if ai == bj else 1
            v = prev[j - 1] + cost
            if prev[j] + 1 < v:
                v = prev[j] + 1
            if cur[j - 1] + 1 < v:
                v = cur[j - 1] + 1
            if i > 1 and j > 1 and ai == b[j - 2] and a[i - 2] == bj:
                t = prev2[j - 2] + cost
                if t < v:
                    v = t
            if v > inf:
                v = inf
            cur[j] = v
            if v < row_min:
                row_min = v
        if row_min > k:
            return inf
        prev2, prev = prev, cur
    return min(prev[lb], inf)


def _full_table(a: str, b: str) -> list[list[int]]:
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, d[i - 2][j - 2] + cost)
            d[i][j] = v
    return d


def edit_script(source: str, target: str) -> list[EditOp]:
    """Return a minimal list of OSA edits turning ``source`` into ``target``.

    Ties are broken deterministically (match/substitute, then transpose, delete,
    insert), so the same pair always yields the same explanation.
    """
    d = _full_table(source, target)
    i, j = len(source), len(target)
    ops: list[EditOp] = []
    while i > 0 or j > 0:
        here = d[i][j]
        if i > 0 and j > 0:
            same = source[i - 1] == target[j - 1]
            if same and here == d[i - 1][j - 1]:
                i, j = i - 1, j - 1
                continue
            if (
                i > 1
                and j > 1
                and source[i - 1] == target[j - 2]
                and source[i - 2] == target[j - 1]
                and here == d[i - 2][j - 2] + 1
            ):
                ops.append(EditOp("transpose", i - 2, source[i - 2 : i], target[j - 2 : j]))
                i, j = i - 2, j - 2
                continue
            if not same and here == d[i - 1][j - 1] + 1:
                ops.append(EditOp("substitute", i - 1, source[i - 1], target[j - 1]))
                i, j = i - 1, j - 1
                continue
        if i > 0 and here == d[i - 1][j] + 1:
            ops.append(EditOp("delete", i - 1, source[i - 1], ""))
            i -= 1
            continue
        ops.append(EditOp("insert", i, "", target[j - 1]))
        j -= 1
    ops.reverse()
    return ops
