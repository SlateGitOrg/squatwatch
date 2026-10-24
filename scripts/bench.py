"""Name-check throughput benchmark on the bundled snapshots.

Measures (1) snapshot/index load time, (2) per-name latency of ``NameChecker.best``
over the benign evaluation names (realistic misses: the common case in real
manifests) and (3) the speed-up of the count-filtered index over brute-force
banded OSA against every popular name.

Usage: uv run python scripts/bench.py  (numbers vary by machine; see README)
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
from pathlib import Path

from squatwatch.checker import CheckerSettings, NameChecker
from squatwatch.models import Ecosystem
from squatwatch.popular import PopularIndex, _load_bundled
from squatwatch.text.distance import osa_distance

ROOT = Path(__file__).resolve().parent.parent


def names_for(eco: Ecosystem) -> list[str]:
    path = ROOT / "data" / "eval" / f"benign-{eco.value}.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [n for n in lines if n and not n.startswith("#")]


def main() -> int:
    print(f"python {platform.python_version()} on {platform.machine()} ({platform.system()})")
    for eco in Ecosystem:
        _load_bundled.cache_clear()
        t0 = time.perf_counter()
        index = PopularIndex.bundled(eco)
        load_ms = (time.perf_counter() - t0) * 1000
        checker = NameChecker(index, CheckerSettings(min_score=0.0))
        queries = names_for(eco)
        lat: list[float] = []
        t0 = time.perf_counter()
        for q in queries:
            s = time.perf_counter()
            checker.best(q)
            lat.append((time.perf_counter() - s) * 1000)
        total = time.perf_counter() - t0
        lat.sort()
        p95 = lat[int(0.95 * (len(lat) - 1))]
        print(
            f"{eco.value}: {len(index)} popular names, index load {load_ms:.0f} ms; "
            f"{len(queries)} names checked in {total:.2f} s = {len(queries) / total:.0f} names/s "
            f"(p50 {statistics.median(lat):.2f} ms, p95 {p95:.2f} ms)"
        )
        sample = queries[:200]
        keys = [e.key for e in index]
        t0 = time.perf_counter()
        for q in sample:
            index.within(q.lower(), 2)
        fast = time.perf_counter() - t0
        t0 = time.perf_counter()
        for q in sample:
            ql = q.lower()
            [k for k in keys if 0 < osa_distance(ql, k, 2) <= 2]
        slow = time.perf_counter() - t0
        print(
            f"  within(k=2) on {len(sample)} queries: "
            f"index {fast * 1000 / len(sample):.2f} ms/query, "
            f"brute force {slow * 1000 / len(sample):.1f} ms/query ({slow / fast:.0f}x faster)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
