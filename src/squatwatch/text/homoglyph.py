"""Visual-confusable folding ("skeletons") for package names.

Two names are *homoglyph-confusable* when they render alike but differ as
strings: ``jeIlyfish`` (capital I) vs ``jellyfish``, ``pyth0n`` vs ``python``, or a
name containing Cyrillic ``а`` (U+0430) in place of Latin ``a``.

:func:`skeleton` maps a raw name to a canonical form where confusable glyphs
collapse to one representative. It works on the *raw* spelling because case
matters for confusability: ``I`` looks like ``l`` but ``i`` does not, and package
indexes lower-case names before comparison, which hides the trick.

The table is a deliberately small, hand-curated subset of Unicode TR39
``confusables.txt`` limited to characters that look like the ASCII letters and
digits allowed in package names. It is not exhaustive (see docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

# Non-ASCII glyph -> ASCII lookalike (applied after NFKC normalisation).
_UNICODE_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "һ": "h",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ѕ": "s",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ɡ": "g",
    "А": "a",
    "В": "b",
    "Е": "e",
    "К": "k",
    "М": "m",
    "Н": "h",
    "О": "o",
    "Р": "p",
    "С": "c",
    "Т": "t",
    "Х": "x",
    # Greek
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "Α": "a",
    "Β": "b",
    "Ε": "e",
    "Ζ": "z",
    "Η": "h",
    "Ι": "l",
    "Κ": "k",
    "Μ": "m",
    "Ν": "n",
    "Ο": "o",
    "Ρ": "p",
    "Τ": "t",
    "Υ": "y",
    "Χ": "x",
    # Latin extensions that survive NFKC
    "ı": "i",
    "ȷ": "j",
    "ł": "l",
    "ℓ": "l",
    "ß": "b",
    "ø": "o",
}

# ASCII glyphs that are confusable with one another, case-sensitive.
_ASCII_CONFUSABLES: dict[str, str] = {
    "I": "l",
    "1": "l",
    "|": "l",
    "0": "o",
    "O": "o",
}

# Multi-character ASCII sequences that render like a single letter.
_SEQUENCES: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
)


@dataclass(frozen=True, slots=True)
class GlyphReport:
    """Summary of unusual characters in a raw name."""

    non_ascii: tuple[str, ...]
    scripts: tuple[str, ...]

    @property
    def mixed_script(self) -> bool:
        """True when letters from more than one Unicode script are present."""
        return len(self.scripts) > 1


def _script_of(ch: str) -> str:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "COMMON"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    return name.split(" ", 1)[0]


def inspect_glyphs(raw: str) -> GlyphReport:
    """Report non-ASCII characters and the scripts used by letters in ``raw``."""
    non_ascii = tuple(sorted({ch for ch in raw if not ch.isascii()}))
    scripts = sorted({_script_of(ch) for ch in raw if ch.isalpha()})
    return GlyphReport(non_ascii=non_ascii, scripts=tuple(scripts))


def skeleton(raw: str) -> str:
    """Fold ``raw`` into its confusable skeleton.

    Steps: NFKC (folds full-width and compatibility forms), Unicode confusables to
    ASCII, case-sensitive ASCII confusables (``I``/``1``/``0``), lower-casing, and
    finally multi-character sequences (``rn`` -> ``m``). Separators are kept, so
    separator tricks are reported by their own signal rather than here.
    """
    text = unicodedata.normalize("NFKC", raw)
    folded = []
    for ch in text:
        mapped = _UNICODE_CONFUSABLES.get(ch, ch)
        mapped = _ASCII_CONFUSABLES.get(mapped, mapped)
        folded.append(mapped.lower())
    out = "".join(folded)
    for seq, rep in _SEQUENCES:
        out = out.replace(seq, rep)
    return out


def confusable_chars(raw: str, genuine: str) -> list[tuple[str, str]]:
    """Return (glyph, intended) pairs where ``raw`` differs from ``genuine``.

    Case-only differences are ignored. Positions are compared pairwise, so the
    result is exact for equal-length names (the single-glyph substitutions this
    is used for) and a best effort otherwise.
    """
    return [
        (got, want) for got, want in zip(raw, genuine, strict=False) if got.lower() != want.lower()
    ]
