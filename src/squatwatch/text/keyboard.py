"""QWERTY keyboard geometry used to recognise fat-finger substitutions.

A substitution of ``a`` by ``b`` is a *keyboard-adjacent* typo when the two keys
touch on a standard US QWERTY layout. Rows are staggered, so key ``(r, c)``
touches ``(r, c±1)``, ``(r-1, c)``, ``(r-1, c+1)``, ``(r+1, c-1)`` and ``(r+1, c)``.
"""

from __future__ import annotations

from functools import cache

_ROWS: tuple[str, ...] = (
    "1234567890-",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)

_POSITIONS: dict[str, tuple[int, int]] = {
    ch: (r, c) for r, row in enumerate(_ROWS) for c, ch in enumerate(row)
}


@cache
def neighbours(key: str) -> frozenset[str]:
    """Return the keys physically adjacent to ``key`` (lower-cased).

    Unknown characters (punctuation other than ``-``, non-ASCII) have no neighbours.
    """
    pos = _POSITIONS.get(key.lower())
    if pos is None:
        return frozenset()
    r, c = pos
    candidates = (
        (r, c - 1),
        (r, c + 1),
        (r - 1, c),
        (r - 1, c + 1),
        (r + 1, c - 1),
        (r + 1, c),
    )
    out: set[str] = set()
    for rr, cc in candidates:
        if 0 <= rr < len(_ROWS) and 0 <= cc < len(_ROWS[rr]):
            out.add(_ROWS[rr][cc])
    return frozenset(out)


def is_adjacent(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` are distinct, adjacent QWERTY keys."""
    a, b = a.lower(), b.lower()
    return a != b and b in neighbours(a)
