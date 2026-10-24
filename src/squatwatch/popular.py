"""The popular-package snapshot and its similarity indexes.

A :class:`PopularIndex` holds the ranked names of one ecosystem and answers the
queries the name checker needs in sub-millisecond time:

* exact membership by registry match key;
* every popular name within OSA distance ``k`` of a query (:meth:`within`);
* lookups by separator-collapsed form, confusable skeleton, token sequence,
  sorted token multiset, and (npm) scope/base.

``within`` avoids comparing the query with all ~10^4 names using a lossless
*character-count filter*: every OSA operation changes the multiset of characters
by at most 2 in L1 norm (insert/delete 1, substitute 2, transpose 0), so
``osa(a, b) >= L1(count(a) - count(b)) / 2``. One vectorised numpy pass over an
``N x 41`` count matrix (plus a length filter ``|len(a)-len(b)| <= k``) leaves a
few dozen candidates, which are verified with the banded OSA. The filter can only
discard pairs that are provably farther than ``k``, so results equal brute force
(this is property-tested).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import cache
from importlib import resources

import numpy as np
import numpy.typing as npt

from squatwatch.errors import DataError
from squatwatch.models import Ecosystem
from squatwatch.names import collapse, match_key, split_scope, tokens
from squatwatch.text.distance import osa_distance
from squatwatch.text.homoglyph import skeleton

log = logging.getLogger(__name__)

_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_.@/"
_SLOT = {ch: i for i, ch in enumerate(_ALPHABET)}
_OTHER = len(_ALPHABET)


@dataclass(frozen=True, slots=True)
class PopularEntry:
    """One popular package: display name, 1-based popularity rank, match key."""

    name: str
    rank: int
    key: str


def _count_vector(text: str) -> npt.NDArray[np.int16]:
    vec = np.zeros(_OTHER + 1, dtype=np.int16)
    for ch in text:
        vec[_SLOT.get(ch, _OTHER)] += 1
    return vec


class PopularIndex:
    """Ranked popular names for one ecosystem with similarity lookups."""

    def __init__(
        self,
        ecosystem: Ecosystem,
        names: Iterable[str],
        *,
        source: str = "custom",
    ) -> None:
        self.ecosystem = ecosystem
        self.source = source
        self._entries: list[PopularEntry] = []
        self._by_key: dict[str, PopularEntry] = {}
        for raw in names:
            name = raw.strip()
            if not name:
                continue
            key = match_key(name, ecosystem)
            if key in self._by_key:
                continue
            entry = PopularEntry(name=name, rank=len(self._entries) + 1, key=key)
            self._entries.append(entry)
            self._by_key[key] = entry
        if not self._entries:
            raise DataError(f"popular index for {ecosystem} is empty")

        self._counts = np.stack([_count_vector(e.key) for e in self._entries])
        self._lengths = np.array([len(e.key) for e in self._entries], dtype=np.int32)

        self._by_collapsed: dict[str, list[PopularEntry]] = defaultdict(list)
        self._by_skeleton: dict[str, list[PopularEntry]] = defaultdict(list)
        self._by_tokens: dict[tuple[str, ...], list[PopularEntry]] = defaultdict(list)
        self._by_token_set: dict[tuple[str, ...], list[PopularEntry]] = defaultdict(list)
        self._scoped_by_base: dict[str, list[PopularEntry]] = defaultdict(list)
        self._scope_rank: dict[str, int] = {}
        for e in self._entries:
            self._by_collapsed[collapse(e.key, ecosystem)].append(e)
            self._by_skeleton[skeleton(e.name)].append(e)
            toks = tokens(e.key, ecosystem)
            self._by_tokens[toks].append(e)
            self._by_token_set[tuple(sorted(toks))].append(e)
            scope, base = split_scope(e.key)
            if scope is not None:
                self._scoped_by_base[base].append(e)
                self._scope_rank.setdefault(scope, e.rank)
        log.debug("built %s popular index: %d names", ecosystem, len(self._entries))

    @classmethod
    def from_text(cls, ecosystem: Ecosystem, text: str, *, source: str) -> PopularIndex:
        """Build from the snapshot file format: one name per line, ``#`` comments."""
        names = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        return cls(ecosystem, names, source=source)

    @staticmethod
    def bundled(ecosystem: Ecosystem) -> PopularIndex:
        """The snapshot shipped inside the package (cached per process)."""
        return _load_bundled(ecosystem)

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[PopularEntry]:
        return iter(self._entries)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and match_key(name, self.ecosystem) in self._by_key

    def get(self, name: str) -> PopularEntry | None:
        """Entry for ``name`` under registry matching rules, if popular."""
        return self._by_key.get(match_key(name, self.ecosystem))

    def within(self, key: str, max_distance: int) -> list[tuple[PopularEntry, int]]:
        """Popular entries at OSA distance ``1..max_distance`` from ``key``.

        ``key`` must already be a match key. Results are sorted by distance, then
        rank. Exact matches (distance 0) are excluded.
        """
        if max_distance <= 0:
            return []
        qv = _count_vector(key)
        length_ok = np.abs(self._lengths - len(key)) <= max_distance
        l1 = np.abs(self._counts - qv).sum(axis=1)
        candidates = np.nonzero(length_ok & (l1 <= 2 * max_distance))[0]
        out: list[tuple[PopularEntry, int]] = []
        for idx in candidates.tolist():
            entry = self._entries[idx]
            d = osa_distance(key, entry.key, max_distance)
            if 0 < d <= max_distance:
                out.append((entry, d))
        out.sort(key=lambda pair: (pair[1], pair[0].rank))
        return out

    def by_collapsed(self, collapsed: str) -> list[PopularEntry]:
        """Entries whose separator-free form equals ``collapsed``."""
        return list(self._by_collapsed.get(collapsed, ()))

    def by_skeleton(self, skel: str) -> list[PopularEntry]:
        """Entries whose confusable skeleton equals ``skel``."""
        return list(self._by_skeleton.get(skel, ()))

    def by_tokens(self, toks: tuple[str, ...]) -> list[PopularEntry]:
        """Entries with exactly this token sequence."""
        return list(self._by_tokens.get(toks, ()))

    def by_token_set(self, toks: tuple[str, ...]) -> list[PopularEntry]:
        """Entries whose sorted tokens equal ``sorted(toks)``."""
        return list(self._by_token_set.get(tuple(sorted(toks)), ()))

    def scoped_with_base(self, base: str) -> list[PopularEntry]:
        """npm: popular scoped packages ``@scope/<base>``."""
        return list(self._scoped_by_base.get(base, ()))

    def scope_rank(self, scope: str) -> int | None:
        """npm: best rank of any popular package in ``scope`` (``@`` included)."""
        return self._scope_rank.get(scope)

    def scopes(self) -> list[str]:
        """npm: all scopes present in the snapshot."""
        return list(self._scope_rank)


@cache
def _load_bundled(ecosystem: Ecosystem) -> PopularIndex:
    filename = f"popular-{ecosystem.value}.txt"
    try:
        text = resources.files("squatwatch.data").joinpath(filename).read_text("utf-8")
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise DataError(f"bundled snapshot {filename} is missing") from exc
    return PopularIndex.from_text(ecosystem, text, source=f"bundled:{filename}")


def snapshot_metadata(ecosystem: Ecosystem) -> dict[str, str]:
    """Header key/values (source URL, checksum, ranks) of the bundled snapshot."""
    filename = f"popular-{ecosystem.value}.txt"
    text = resources.files("squatwatch.data").joinpath(filename).read_text("utf-8")
    meta: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        key, sep, value = line[1:].strip().partition(":")
        if sep:
            meta[key.strip()] = value.strip()
    return meta
