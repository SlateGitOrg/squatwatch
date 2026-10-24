"""Labelled evaluation of the name checker with a held-out split.

Data (all names only, see DATA.md):

* **incidents** — malicious names from documented incidents
  (``data/eval/incidents.csv``). They are *all* held out in the test split and
  were never used to choose weights or the threshold.
* **generated** — synthetic squats of popular names, one per technique, made by
  :func:`generate_variants`. The split is by *target*, so a target's variants
  never straddle dev and test.
* **benign** — real, widely downloaded packages ranked just below the snapshot
  cutoff (``data/eval/benign-*.txt``). Assumed benign; split by name hash.

The dev split is used for the threshold sweep; numbers quoted as results come
from the test split only.
"""

from __future__ import annotations

import csv
import hashlib
import random
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from squatwatch.checker import COMBO_TERMS, NameChecker
from squatwatch.errors import DataError
from squatwatch.models import Ecosystem
from squatwatch.names import collapse, match_key, split_scope
from squatwatch.popular import PopularIndex
from squatwatch.text.keyboard import neighbours

SPLIT_SALT = "squatwatch-eval-v1"
TECHNIQUES: tuple[str, ...] = (
    "omission",
    "repetition",
    "insertion",
    "transposition",
    "keyboard",
    "substitution",
    "double-edit",
    "homoglyph",
    "separator",
    "combo",
    "scope",
)
_ASCII_LOOKALIKE = {"l": "1", "o": "0", "i": "1"}
_UNICODE_LOOKALIKE = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р"}
_LETTERS = "abcdefghijklmnopqrstuvwxyz"
_SINGLE_EDITS = ("omission", "repetition", "insertion", "transposition", "keyboard", "substitution")
_GEN_COMBO = ("js", "dev", "utils", "lib", "py", "sdk", "cli", "python3", "node", "2")


@dataclass(frozen=True, slots=True)
class EvalItem:
    """One labelled name."""

    name: str
    ecosystem: Ecosystem
    malicious: bool
    target: str
    technique: str
    source: str
    split: str


@dataclass(frozen=True, slots=True)
class Scored:
    """An item with the checker's best score and predicted target."""

    item: EvalItem
    score: float
    predicted: str | None
    techniques: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Metrics:
    """Binary-classification counts and rates at one threshold."""

    threshold: float
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0


def split_of(key: str) -> str:
    """Deterministic 50/50 dev/test assignment from a salted SHA-256."""
    digest = hashlib.sha256(f"{SPLIT_SALT}:{key}".encode()).digest()
    return "dev" if digest[0] < 128 else "test"


# ------------------------------------------------------------------- loading


def load_incidents(path: Path) -> list[EvalItem]:
    """Typosquat rows of the incidents CSV, all in the test split."""
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    except OSError as exc:
        raise DataError(f"cannot read incidents file {path}: {exc}") from exc
    items: list[EvalItem] = []
    for row in rows:
        if row.get("kind") != "typosquat":
            continue
        try:
            eco = Ecosystem(row["ecosystem"])
        except (KeyError, ValueError) as exc:
            raise DataError(f"{path}: bad ecosystem in row {row}") from exc
        items.append(
            EvalItem(
                name=row["name"],
                ecosystem=eco,
                malicious=True,
                target=row.get("target", ""),
                technique="historical",
                source=f"incident:{row.get('incident', '?')}",
                split="test",
            )
        )
    return items


def load_benign(path: Path, ecosystem: Ecosystem) -> list[EvalItem]:
    """Benign names from a list file, split by name hash."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DataError(f"cannot read benign list {path}: {exc}") from exc
    names = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
    return [
        EvalItem(n, ecosystem, False, "", "benign", "benign", split_of(f"{ecosystem}:{n}"))
        for n in names
    ]


# ------------------------------------------------------------------ variants


def _variant(target: str, technique: str, rng: random.Random, eco: Ecosystem) -> str | None:
    scope, base = split_scope(target)
    prefix = f"{scope}/" if scope else ""
    word = base
    letters = [i for i, ch in enumerate(word) if ch.isalpha()]
    if not letters:
        return None
    i = rng.choice(letters)
    if technique == "omission":
        out = word[:i] + word[i + 1 :]
    elif technique == "repetition":
        out = word[:i] + word[i] + word[i:]
    elif technique == "transposition":
        pairs = [j for j in range(len(word) - 1) if word[j] != word[j + 1] and word[j].isalnum()]
        if not pairs:
            return None
        j = rng.choice(pairs)
        out = word[:j] + word[j + 1] + word[j] + word[j + 2 :]
    elif technique == "insertion":
        out = word[:i] + rng.choice(_LETTERS) + word[i:]
    elif technique == "substitution":
        out = word[:i] + rng.choice(_LETTERS.replace(word[i], "")) + word[i + 1 :]
    elif technique == "double-edit":
        if len(word) < 8:
            return None
        once = _variant(word, rng.choice(_SINGLE_EDITS), rng, eco)
        if once is None:
            return None
        twice = _variant(once, rng.choice(_SINGLE_EDITS), rng, eco)
        return None if twice is None else prefix + twice
    elif technique == "keyboard":
        near = sorted(neighbours(word[i]) - set("-"))
        if not near:
            return None
        out = word[:i] + rng.choice(near) + word[i + 1 :]
    elif technique == "homoglyph":
        spots = [
            j for j, ch in enumerate(word) if ch in _ASCII_LOOKALIKE or ch in _UNICODE_LOOKALIKE
        ]
        if not spots:
            return None
        j = rng.choice(spots)
        ch = word[j]
        options = [m[ch] for m in (_ASCII_LOOKALIKE, _UNICODE_LOOKALIKE) if ch in m]
        if ch == "l":
            options.append("I")
        out = word[:j] + rng.choice(options) + word[j + 1 :]
    elif technique == "separator":
        seps = [j for j, ch in enumerate(word) if ch in "-_."]
        if seps:
            j = rng.choice(seps)
            replacement = "" if eco is Ecosystem.PYPI or rng.random() < 0.5 else rng.choice("_.")
            out = word[:j] + replacement + word[j + 1 :]
        else:
            j = rng.randrange(2, len(word) - 1) if len(word) > 3 else 0
            if not j:
                return None
            out = word[:j] + "-" + word[j:]
    elif technique == "combo":
        term = rng.choice(_GEN_COMBO)
        out = f"{term}-{word}" if term in ("python3", "node") else f"{word}-{term}"
    elif technique == "scope":
        if eco is not Ecosystem.NPM or scope is None:
            return None
        if rng.random() < 0.5:
            return f"{scope[1:]}-{base}"
        k = rng.randrange(1, len(scope))
        return f"{scope[:k]}{scope[k]}{scope[k:]}/{base}"
    else:
        raise ValueError(f"unknown technique {technique}")
    return prefix + out


def generate_variants(
    index: PopularIndex,
    *,
    seed: int = 1337,
    targets_per_ecosystem: int = 400,
    max_rank: int = 3000,
    exclude: Iterable[str] = (),
) -> list[EvalItem]:
    """Synthetic squats of popular names; deterministic for a given seed."""
    eco = index.ecosystem
    rng = random.Random(f"{seed}:{eco.value}")  # noqa: S311 - reproducible sampling, not crypto
    excluded = {match_key(n, eco) for n in exclude}
    pool = [e for e in index if e.rank <= max_rank and len(collapse(e.key, eco)) >= 5]
    chosen = rng.sample(pool, min(targets_per_ecosystem, len(pool)))
    items: list[EvalItem] = []
    for entry in sorted(chosen, key=lambda e: e.rank):
        split = split_of(f"{eco}:target:{entry.key}")
        scoped = split_scope(entry.key)[0] is not None
        for technique in TECHNIQUES:
            # Only a scope's owner can publish inside it, so the only squats an
            # attacker can register for a scoped target are scope tricks.
            if scoped != (technique == "scope"):
                continue
            name = _variant(entry.name, technique, rng, eco)
            if name is None:
                continue
            key = match_key(name, eco)
            if key == entry.key or key in index or key in excluded or not key:
                continue
            if technique == "combo" and set(name.split("-")) <= COMBO_TERMS:
                continue
            items.append(EvalItem(name, eco, True, entry.name, technique, "generated", split))
    return items


def build_dataset(data_dir: Path, indexes: dict[Ecosystem, PopularIndex]) -> list[EvalItem]:
    """Incidents + generated variants + benign names for both ecosystems."""
    incidents = load_incidents(data_dir / "incidents.csv")
    items: list[EvalItem] = list(incidents)
    for eco in Ecosystem:
        benign = load_benign(data_dir / f"benign-{eco.value}.txt", eco)
        known = [b.name for b in benign] + [i.name for i in incidents if i.ecosystem is eco]
        items.extend(benign)
        items.extend(generate_variants(indexes[eco], exclude=known))
    return items


# ------------------------------------------------------------------- scoring


def score_items(items: Sequence[EvalItem], checkers: dict[Ecosystem, NameChecker]) -> list[Scored]:
    """Best score for every item (no threshold applied)."""
    out: list[Scored] = []
    for item in items:
        verdict = checkers[item.ecosystem].best(item.name)
        if verdict is None:
            out.append(Scored(item, 0.0, None, ()))
        else:
            out.append(Scored(item, verdict.score, verdict.target.name, verdict.techniques))
    return out


def metrics_at(scored: Iterable[Scored], threshold: float) -> Metrics:
    """Confusion counts at ``threshold`` (flag when score >= threshold)."""
    tp = fp = fn = tn = 0
    for s in scored:
        flagged = s.score >= threshold
        if s.item.malicious:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return Metrics(threshold, tp, fp, fn, tn)


def sweep(scored: Sequence[Scored], thresholds: Iterable[float]) -> list[Metrics]:
    """Metrics for each threshold."""
    return [metrics_at(scored, t) for t in thresholds]


#: Real manifests contain very few squats, so a false-positive rate that looks
#: small on a balanced set still swamps the true hits in practice. The selection
#: rule therefore caps the dev false-positive rate before maximising F1.
MAX_DEV_FPR = 0.03


def best_threshold(rows: Sequence[Metrics], *, max_fpr: float = MAX_DEV_FPR) -> Metrics:
    """Highest F1 among thresholds with FPR <= ``max_fpr`` (ties: higher
    threshold); if none qualifies, the threshold with the lowest FPR."""
    if not rows:
        raise ValueError("no thresholds to choose from")
    eligible = [m for m in rows if m.fpr <= max_fpr]
    if not eligible:
        return min(rows, key=lambda m: (m.fpr, -m.threshold))
    return max(eligible, key=lambda m: (round(m.f1, 6), m.threshold))


def default_thresholds() -> list[float]:
    """0.40, 0.45, ... 0.90."""
    return [round(0.40 + 0.05 * k, 2) for k in range(11)]


def target_correct(s: Scored) -> bool:
    """Whether the predicted target matches the labelled one (case/separator-folded)."""
    if not s.item.target or s.predicted is None:
        return False
    eco = s.item.ecosystem
    return match_key(s.predicted, eco) == match_key(s.item.target, eco)


# ------------------------------------------------------------------- reports


def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _table(header: Sequence[str], rows: Iterable[Sequence[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return out


def _incident_row(
    name: str,
    v: Sequence[Scored],
    threshold: float,
    in_snapshot: Callable[[EvalItem], bool],
) -> tuple[str, ...]:
    known = [s for s in v if in_snapshot(s.item)]
    hit = [s for s in v if s.score >= threshold]
    known_recall = sum(s.score >= threshold for s in known) / len(known) if known else None
    return (
        name,
        str(len(v)),
        _pct(len(hit) / len(v)),
        str(len(known)),
        _pct(known_recall) if known_recall is not None else "n/a",
        _pct(sum(target_correct(s) for s in hit) / len(hit)) if hit else "n/a",
    )


def render_markdown(
    scored: Sequence[Scored],
    *,
    shipped_threshold: float,
    in_snapshot: Callable[[EvalItem], bool],
) -> str:
    """Full evaluation report: dev sweep, test results, per technique and incident."""
    dev = [s for s in scored if s.item.split == "dev"]
    test = [s for s in scored if s.item.split == "test"]
    lines: list[str] = ["# squatwatch name-check evaluation", ""]

    counts = Counter((s.item.split, s.item.source.split(":")[0], s.item.malicious) for s in scored)
    lines.append("## Dataset")
    lines.append("")
    lines += _table(
        ["split", "source", "label", "names"],
        [
            (split, src, "malicious" if mal else "benign", n)
            for (split, src, mal), n in sorted(counts.items())
        ],
    )

    sweep_rows = sweep(dev, default_thresholds())
    best = best_threshold(sweep_rows)
    lines += ["", "## Threshold sweep (dev split only)", ""]
    lines += _table(
        ["threshold", "precision", "recall", "F1", "FPR"],
        [
            (f"{m.threshold:.2f}", _pct(m.precision), _pct(m.recall), f"{m.f1:.3f}", _pct(m.fpr))
            for m in sweep_rows
        ],
    )
    note = "matches" if abs(best.threshold - shipped_threshold) < 1e-9 else "DIFFERS FROM"
    lines += [
        "",
        f"Selection rule: highest dev F1 with dev FPR <= {MAX_DEV_FPR:.0%}. "
        f"Chosen threshold {best.threshold:.2f}; the shipped default "
        f"`min-score = {shipped_threshold:.2f}` {note} it.",
    ]

    lines += ["", f"## Held-out test results at min-score {shipped_threshold:.2f}", ""]
    rows = []
    for label, subset in (
        ("all", test),
        ("pypi", [s for s in test if s.item.ecosystem is Ecosystem.PYPI]),
        ("npm", [s for s in test if s.item.ecosystem is Ecosystem.NPM]),
        ("incidents + benign", [s for s in test if s.item.source != "generated"]),
        ("generated + benign", [s for s in test if not s.item.source.startswith("incident")]),
    ):
        m = metrics_at(subset, shipped_threshold)
        rows.append(
            (
                label,
                m.tp,
                m.fp,
                m.fn,
                m.tn,
                _pct(m.precision),
                _pct(m.recall),
                f"{m.f1:.3f}",
                _pct(m.fpr),
            )
        )
    lines += _table(["subset", "TP", "FP", "FN", "TN", "precision", "recall", "F1", "FPR"], rows)

    lines += ["", "## Test recall by technique (generated variants)", ""]
    by_tech: dict[str, list[Scored]] = defaultdict(list)
    for s in test:
        if s.item.source == "generated":
            by_tech[f"{s.item.ecosystem}/{s.item.technique}"].append(s)
    lines += _table(
        ["ecosystem/technique", "n", "recall", "target correct"],
        [
            (
                k,
                len(v),
                _pct(metrics_at(v, shipped_threshold).recall),
                _pct(sum(target_correct(s) for s in v if s.score >= shipped_threshold) / len(v)),
            )
            for k, v in sorted(by_tech.items())
        ],
    )

    lines += ["", "## Historical incidents (all held out)", ""]
    by_inc: dict[str, list[Scored]] = defaultdict(list)
    for s in test:
        if s.item.source.startswith("incident:"):
            by_inc[s.item.source.removeprefix("incident:")].append(s)
    groups = sorted(by_inc.items())
    largest = max(groups, key=lambda kv: len(kv[1]))[0] if groups else ""
    groups.append(("**all incidents**", [s for _, v in groups for s in v]))
    groups.append(
        (f"**all except {largest}**", [s for k, v in by_inc.items() if k != largest for s in v])
    )
    inc_rows = [_incident_row(name, v, shipped_threshold, in_snapshot) for name, v in groups if v]
    lines += _table(
        [
            "incident",
            "names",
            "recall",
            "target in snapshot",
            "recall (target in snapshot)",
            "target correct (of flagged)",
        ],
        inc_rows,
    )

    misses = [
        s for s in test if s.item.source.startswith("incident") and s.score < shipped_threshold
    ]
    lines += ["", f"Missed incident names ({len(misses)}):", ""]
    lines.append(
        ", ".join(f"`{s.item.name}`" for s in sorted(misses, key=lambda s: s.item.name)) or "none"
    )

    fps = sorted(
        (s for s in test if not s.item.malicious and s.score >= shipped_threshold),
        key=lambda s: -s.score,
    )
    lines += ["", f"## Benign names flagged on test ({len(fps)}), highest score first", ""]
    lines += _table(
        ["name", "ecosystem", "score", "looks like", "techniques"],
        [
            (
                f"`{s.item.name}`",
                s.item.ecosystem,
                f"{s.score:.2f}",
                s.predicted,
                ", ".join(s.techniques),
            )
            for s in fps[:40]
        ],
    )
    return "\n".join(lines) + "\n"
