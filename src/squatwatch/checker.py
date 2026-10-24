"""Typosquat name analysis: compare one package name with the popular snapshot.

For a query name the :class:`NameChecker` gathers *signals* against every
popular name it resembles, then scores each (query, target) pair:

==============  ======  =====================================================
technique        rule    example (query -> target)
==============  ======  =====================================================
omission         SW101   ``urlib3`` -> ``urllib3``
repetition       SW101   ``requestss`` -> ``requests``
insertion        SW101   ``reqzuests`` -> ``requests``
transposition    SW101   ``reqeusts`` -> ``requests``
keyboard         SW101   ``requesrs`` -> ``requests`` (``t``/``r`` adjacent)
substitution     SW101   ``djanga`` -> ``django``
edit-2           SW101   two of the above on a long name
homoglyph        SW102   ``jeIlyfish`` -> ``jellyfish``, ``pyth0n`` -> ``python``
separator        SW103   ``python-dateutil`` -> ``pythondateutil``, ``cross_env``
token-order      SW103   ``dateutil-python`` -> ``python-dateutil``
scope            SW104   ``@typess/node`` -> ``@types/node``, ``types-node``
combo            SW105   ``twilio-npm`` -> ``twilio``, ``python3-dateutil``
==============  ======  =====================================================

The score of a pair is the strongest signal weight, plus a small bonus per extra
independent technique, adjusted by how attractive the target is (its popularity
rank) and how noisy short names are. Weights are fixed constants documented in
docs/ARCHITECTURE.md; only the reporting threshold was chosen on the dev split.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from squatwatch.models import Ecosystem
from squatwatch.names import SEPARATORS, collapse, match_key, split_scope, tokens
from squatwatch.popular import PopularEntry, PopularIndex
from squatwatch.text.distance import EditOp, edit_script, osa_distance
from squatwatch.text.homoglyph import confusable_chars, inspect_glyphs, skeleton
from squatwatch.text.keyboard import is_adjacent

log = logging.getLogger(__name__)

#: Generic words attackers bolt onto a popular name (combosquatting). These are
#: ecosystem-neutral filler words, not domain words like "cors" or "redis", so
#: that legitimate plugin names (``flask-cors``) are not combos of ``flask``.
COMBO_TERMS: frozenset[str] = frozenset(
    {
        "api",
        "cli",
        "client",
        "core",
        "dev",
        "fix",
        "fixed",
        "helper",
        "helpers",
        "js",
        "latest",
        "lib",
        "libs",
        "new",
        "next",
        "node",
        "nodejs",
        "npm",
        "official",
        "package",
        "pkg",
        "proxy",
        "py",
        "py3",
        "python",
        "python3",
        "safe",
        "sdk",
        "secure",
        "src",
        "tool",
        "tools",
        "update",
        "updated",
        "util",
        "utils",
    }
)

#: Affixes glued on without a separator (``noderequest``, ``mysqljs``).
GLUED_AFFIXES: tuple[str, ...] = ("node", "nodejs", "js", "py", "python", "python3", "lib")

#: Digit/letter pairs that look alike in common monospace and sans fonts.
_LOOKALIKE_PAIRS: frozenset[frozenset[str]] = frozenset(
    frozenset(p) for p in (("0", "o"), ("1", "l"), ("1", "i"), ("5", "s"), ("i", "l"))
)

_VERSION_TOKEN = re.compile(r"^v?\d+$")
_TRAILING_DIGITS = re.compile(r"^([a-z]+?)\d+$")

RULE_FOR_TECHNIQUE: dict[str, str] = {
    "omission": "SW101",
    "repetition": "SW101",
    "insertion": "SW101",
    "transposition": "SW101",
    "keyboard": "SW101",
    "substitution": "SW101",
    "edit-2": "SW101",
    "version-digit": "SW105",
    "homoglyph": "SW102",
    "separator": "SW103",
    "token-order": "SW103",
    "scope": "SW104",
    "scope-flatten": "SW104",
    "re-scope": "SW104",
    "combo": "SW105",
}

_BASE_WEIGHT: dict[str, float] = {
    "omission": 0.70,
    "repetition": 0.72,
    "insertion": 0.64,
    "transposition": 0.72,
    "keyboard": 0.68,
    "substitution": 0.62,
    "edit-2": 0.50,
    "version-digit": 0.50,
    "homoglyph": 0.90,
    "separator": 0.70,
    "token-order": 0.62,
    "scope": 0.85,
    "scope-flatten": 0.62,
    "re-scope": 0.50,
    "combo": 0.62,
}

#: Techniques in one family describe the same change; only distinct families
#: add the multi-signal bonus.
FAMILY: dict[str, str] = {
    "omission": "typo",
    "repetition": "typo",
    "insertion": "typo",
    "transposition": "typo",
    "keyboard": "typo",
    "substitution": "typo",
    "edit-2": "typo",
    "version-digit": "combo",
    "homoglyph": "homoglyph",
    "separator": "layout",
    "token-order": "layout",
    "scope": "scope",
    "scope-flatten": "layout",
    "re-scope": "scope",
    "combo": "combo",
}
MULTI_FAMILY_BONUS = 0.05
SHORT_NAME_PENALTY: tuple[tuple[int, float], ...] = ((4, 0.14), (5, 0.08))


@dataclass(frozen=True, slots=True)
class Signal:
    """Evidence that a query imitates one popular target."""

    technique: str
    weight: float
    detail: str

    @property
    def rule(self) -> str:
        """Rule id reported for this technique."""
        return RULE_FOR_TECHNIQUE[self.technique]


@dataclass(frozen=True, slots=True)
class NameVerdict:
    """The best-scoring explanation of why a name looks like a squat."""

    name: str
    ecosystem: Ecosystem
    target: PopularEntry
    score: float
    signals: tuple[Signal, ...]

    @property
    def primary(self) -> Signal:
        """The strongest signal (determines the rule id)."""
        return self.signals[0]

    @property
    def techniques(self) -> tuple[str, ...]:
        """Distinct techniques, strongest first."""
        seen: dict[str, None] = {}
        for s in self.signals:
            seen.setdefault(s.technique, None)
        return tuple(seen)


@dataclass(slots=True)
class CheckerSettings:
    """Tunables for :class:`NameChecker`.

    ``min_score`` is the reporting threshold; the default was picked by a
    threshold sweep on the *dev* split only (see ``make eval`` and DECISIONS.md).
    """

    min_score: float = 0.60
    allow: frozenset[str] = field(default_factory=frozenset)


def allowed_distance(length: int) -> int:
    """Edit budget by name length: short names collide by accident too often."""
    if length < 4:
        return 0
    if length < 8:
        return 1
    return 2


def _rank_adjustment(rank: int) -> float:
    if rank <= 100:
        return 0.12
    if rank <= 1000:
        return 0.06
    if rank <= 5000:
        return 0.0
    return -0.06


def _short_penalty(length: int) -> float:
    for limit, penalty in SHORT_NAME_PENALTY:
        if length <= limit:
            return penalty
    return 0.0


class NameChecker:
    """Scores names against a :class:`PopularIndex` for one ecosystem."""

    def __init__(
        self,
        index: PopularIndex,
        settings: CheckerSettings | None = None,
    ) -> None:
        self.index = index
        self.ecosystem = index.ecosystem
        self.settings = settings or CheckerSettings()
        self._allow = {match_key(a, self.ecosystem) for a in self.settings.allow}

    # ------------------------------------------------------------------ public

    def check(self, name: str) -> NameVerdict | None:
        """Return a verdict if ``name`` scores at least ``min_score``."""
        verdict = self.best(name)
        if verdict is None or verdict.score < self.settings.min_score:
            return None
        return verdict

    def best(self, name: str) -> NameVerdict | None:
        """Highest-scoring verdict regardless of threshold (used by evaluation)."""
        key = match_key(name, self.ecosystem)
        if not key or key in self._allow:
            return None
        glyphs = inspect_glyphs(name)
        if key in self.index and not glyphs.non_ascii:
            return None
        scope, _ = split_scope(key)
        if scope is not None and self.index.scope_rank(scope) is not None:
            # Only a scope's owner can publish under it, and this scope belongs to
            # an organisation that already ships popular packages.
            return None
        signals: dict[str, list[Signal]] = {}
        targets: dict[str, PopularEntry] = {}
        for entry, signal in self._collect(name, key):
            if entry.key == key:
                continue
            targets[entry.key] = entry
            signals.setdefault(entry.key, []).append(signal)
        best: NameVerdict | None = None
        for tkey, sigs in signals.items():
            verdict = self._score(name, key, targets[tkey], sigs)
            if best is None or (verdict.score, -verdict.target.rank) > (
                best.score,
                -best.target.rank,
            ):
                best = verdict
        return best

    def check_many(self, names: Iterable[str]) -> dict[str, NameVerdict]:
        """Check several names; returns only those over the threshold."""
        out: dict[str, NameVerdict] = {}
        for n in names:
            v = self.check(n)
            if v is not None:
                out[n] = v
        return out

    # ----------------------------------------------------------------- signals

    def _collect(self, raw: str, key: str) -> Iterable[tuple[PopularEntry, Signal]]:
        yield from self._homoglyph(raw)
        yield from self._edits(key)
        yield from self._separators(key)
        yield from self._combos(key)
        if self.ecosystem is Ecosystem.NPM:
            yield from self._scopes(key)

    def _homoglyph(self, raw: str) -> Iterable[tuple[PopularEntry, Signal]]:
        skel = skeleton(raw)
        glyphs = inspect_glyphs(raw)
        for entry in self.index.by_skeleton(skel):
            pairs = confusable_chars(raw, entry.name)
            shown = ", ".join(f"{g!r} for {w!r}" for g, w in pairs) or "confusable glyphs"
            weight = _BASE_WEIGHT["homoglyph"]
            if glyphs.non_ascii:
                weight += 0.05
            detail = f"homoglyph: renders like {entry.name!r} ({shown})"
            if glyphs.mixed_script:
                detail += f"; mixes scripts {', '.join(glyphs.scripts)}"
            yield entry, Signal("homoglyph", weight, detail)

    def _edits(self, key: str) -> Iterable[tuple[PopularEntry, Signal]]:
        budget = allowed_distance(len(key))
        for entry, dist in self.index.within(key, budget):
            ops = edit_script(entry.key, key)
            yield entry, self._classify_edits(entry, dist, ops)

    def _classify_edits(self, entry: PopularEntry, dist: int, ops: list[EditOp]) -> Signal:
        target = entry.key
        kinds = [_technique_of(op, target) for op in ops]
        described = "; ".join(_describe(op) for op in ops)
        if all(k == "separator" for k in kinds):
            detail = f"separator: {described} of {entry.name!r}"
            return Signal("separator", _BASE_WEIGHT["separator"], detail)
        if dist >= 2 or len(ops) != 1:
            detail = f"{dist} edits from {entry.name!r}: {described}"
            return Signal("edit-2", _BASE_WEIGHT["edit-2"], detail)
        technique = kinds[0]
        detail = f"{technique}: {described} of {entry.name!r}"
        return Signal(technique, _BASE_WEIGHT[technique], detail)

    def _separators(self, key: str) -> Iterable[tuple[PopularEntry, Signal]]:
        scope, _ = split_scope(key)
        col = collapse(key, self.ecosystem)
        if len(col) >= 4:
            for entry in self.index.by_collapsed(col):
                target_scope, _ = split_scope(entry.key)
                if target_scope is not None and scope is None:
                    technique = "scope-flatten"
                    detail = f"scope-flatten: flattens the scoped package {entry.name!r}"
                else:
                    technique = "separator"
                    detail = f"separator: same letters as {entry.name!r}, separators changed"
                yield entry, Signal(technique, _BASE_WEIGHT[technique], detail)
        toks = tokens(key, self.ecosystem)
        if len(toks) >= 2:
            for entry in self.index.by_token_set(toks):
                if split_scope(entry.key)[0] != scope:
                    continue
                if tokens(entry.key, self.ecosystem) != toks:
                    detail = f"token-order: reorders the words of {entry.name!r}"
                    yield entry, Signal("token-order", _BASE_WEIGHT["token-order"], detail)

    def _combos(self, key: str) -> Iterable[tuple[PopularEntry, Signal]]:
        scope, _ = split_scope(key)
        toks = tokens(key, self.ecosystem)
        weight = _BASE_WEIGHT["combo"]
        if len(toks) >= 2:
            for i, tok in enumerate(toks):
                rest = toks[:i] + toks[i + 1 :]
                if tok in COMBO_TERMS:
                    for entry in self._lookup_tokens(rest, scope):
                        yield (
                            entry,
                            Signal("combo", weight, f"combo: adds {tok!r} to {entry.name!r}"),
                        )
                elif _VERSION_TOKEN.match(tok):
                    for entry in self._lookup_tokens(rest, scope):
                        detail = f"version-digit: adds {tok!r} to {entry.name!r}"
                        yield entry, Signal("version-digit", _BASE_WEIGHT["version-digit"], detail)
                m = _TRAILING_DIGITS.match(tok)
                if m and len(m.group(1)) >= 2:
                    swapped = (*toks[:i], m.group(1), *toks[i + 1 :])
                    for entry in self._lookup_tokens(swapped, scope):
                        detail = f"combo: uses {tok!r} instead of {m.group(1)!r} in {entry.name!r}"
                        yield entry, Signal("combo", weight, detail)
        if scope is None:
            col = collapse(key, self.ecosystem)
            for affix in GLUED_AFFIXES:
                for stripped in {col.removeprefix(affix), col.removesuffix(affix)}:
                    if stripped != col and len(stripped) >= 3:
                        for entry in self.index.by_collapsed(stripped):
                            if split_scope(entry.key)[0] is None:
                                detail = f"combo: glues {affix!r} onto {entry.name!r}"
                                yield entry, Signal("combo", weight - 0.04, detail)

    def _lookup_tokens(self, toks: tuple[str, ...], scope: str | None) -> list[PopularEntry]:
        if not toks or sum(len(t) for t in toks) < 3:
            return []
        return [e for e in self.index.by_tokens(toks) if split_scope(e.key)[0] == scope]

    def _scopes(self, key: str) -> Iterable[tuple[PopularEntry, Signal]]:
        scope, base = split_scope(key)
        if scope is None:
            return
        for other in self.index.scopes():
            if other != scope and osa_distance(scope, other, 1) == 1:
                entry = self.index.get(f"{other}/{base}")
                if entry is not None:
                    detail = f"scope: scope {scope!r} imitates {other!r} for {entry.name!r}"
                    yield entry, Signal("scope", _BASE_WEIGHT["scope"], detail)
        entry = self.index.get(base)
        if entry is not None and len(base) >= 4:
            detail = f"re-scope: re-publishes popular {entry.name!r} under unknown scope {scope!r}"
            yield entry, Signal("re-scope", _BASE_WEIGHT["re-scope"], detail)

    # ----------------------------------------------------------------- scoring

    def _score(self, raw: str, key: str, target: PopularEntry, sigs: list[Signal]) -> NameVerdict:
        unique: dict[str, Signal] = {}
        for s in sorted(sigs, key=lambda s: -s.weight):
            unique.setdefault(s.technique, s)
        ordered = tuple(unique.values())
        families = {FAMILY[s.technique] for s in ordered}
        score = ordered[0].weight + MULTI_FAMILY_BONUS * (len(families) - 1)
        score += _rank_adjustment(target.rank)
        shortest = min(
            len(collapse(target.key, self.ecosystem)), len(collapse(key, self.ecosystem))
        )
        score -= _short_penalty(shortest)
        score = round(min(1.0, max(0.0, score)), 3)
        return NameVerdict(
            name=raw,
            ecosystem=self.ecosystem,
            target=target,
            score=score,
            signals=ordered,
        )


def _technique_of(op: EditOp, target: str) -> str:
    """Name the typo behind one edit op (``op`` turns ``target`` into the query)."""
    if op.kind == "transpose":
        return "transposition"
    at_end = op.position >= len(target) - 1
    if op.kind == "delete":
        if op.source in SEPARATORS or op.source in "@/":
            return "separator"
        return "version-digit" if op.source.isdigit() and at_end else "omission"
    if op.kind == "insert":
        if op.target in SEPARATORS or op.target in "@/":
            return "separator"
        if op.target.isdigit() and op.position >= len(target):
            return "version-digit"
        before = target[op.position - 1] if op.position > 0 else ""
        after = target[op.position] if op.position < len(target) else ""
        return "repetition" if op.target in (before, after) else "insertion"
    # substitute
    if (op.source in SEPARATORS or op.source in "@/") and (
        op.target in SEPARATORS or op.target in "@/"
    ):
        return "separator"
    if op.source.isdigit() and op.target.isdigit():
        return "version-digit"
    if frozenset((op.source, op.target)) in _LOOKALIKE_PAIRS:
        return "homoglyph"
    if is_adjacent(op.source, op.target):
        return "keyboard"
    return "substitution"


def _describe(op: EditOp) -> str:
    if op.kind == "delete":
        return f"drops {op.source!r} at {op.position}"
    if op.kind == "insert":
        return f"inserts {op.target!r} at {op.position}"
    if op.kind == "transpose":
        return f"swaps {op.source!r} to {op.target!r} at {op.position}"
    return f"replaces {op.source!r} with {op.target!r} at {op.position}"
