"""Micro benchmark for the pygosqlx ctypes layer (stdlib only, no new deps).

Measures per-call latency of the public API on three fixed queries, using
timeit with a fixed loop count and the best of several repeats (the minimum is
the least noisy estimate of the cost of the code itself). Report relative
deltas between commits, not absolute numbers.

Usage (the shared library must be built; see python/README.md):

    GOSQLX_LIB_PATH=/path/to/libgosqlx.dylib python benchmarks/bench_core.py
    python benchmarks/bench_core.py --json --repeat 7 --number 2000
"""

from __future__ import annotations

import argparse
import json
import sys
import timeit
from pathlib import Path
from typing import Callable, Dict, List

QUERIES = {
    "small": "SELECT id, name FROM users WHERE id = 1",
    "medium": (
        "SELECT u.id, u.name, COUNT(o.id) AS orders, SUM(o.total) AS spent "
        "FROM users u LEFT JOIN orders o ON o.user_id = u.id "
        "WHERE u.created_at > '2024-01-01' AND u.status IN ('active', 'trial') "
        "GROUP BY u.id, u.name HAVING COUNT(o.id) > 2 ORDER BY spent DESC LIMIT 50"
    ),
    "large": (
        "SELECT " + ", ".join(["c"] * 120) + " FROM t WHERE " + " AND ".join(["a = 1"] * 80)
    ),
}

DEFAULT_REPEAT = 5
DEFAULT_NUMBER = 1000


def operations() -> Dict[str, Callable[[str], object]]:
    import pygosqlx

    return {
        "parse": pygosqlx.parse,
        "validate": pygosqlx.validate,
        "format": pygosqlx.format,
        "extract_metadata": pygosqlx.extract_metadata,
        "lint": pygosqlx.lint,
    }


def measure(fn: Callable[[], object], repeat: int, number: int) -> float:
    """Return the best per-call time in microseconds."""
    fn()  # warm up: loads the library and primes Go pools
    best = min(timeit.repeat(fn, repeat=repeat, number=number))
    return best / number * 1e6


def run(repeat: int, number: int) -> List[dict]:
    rows = []
    for op_name, op in operations().items():
        for q_name, sql in QUERIES.items():
            # A benchmark of an error path is a different benchmark.
            op(sql)
            rows.append(
                {
                    "op": op_name,
                    "query": q_name,
                    "us_per_call": round(measure(lambda: op(sql), repeat, number), 3),
                }
            )
    return rows


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repeat", type=int, default=DEFAULT_REPEAT)
    ap.add_argument("--number", type=int, default=DEFAULT_NUMBER)
    ap.add_argument("--json", action="store_true", help="print JSON rows")
    args = ap.parse_args(argv)
    if args.repeat < 1 or args.number < 1:
        ap.error("--repeat and --number must be >= 1")

    try:
        rows = run(args.repeat, args.number)
    except (ImportError, OSError, RuntimeError) as exc:
        print(f"cannot run: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print(f"{'op':<18}{'query':<8}{'us/call':>10}")
        for r in rows:
            print(f"{r['op']:<18}{r['query']:<8}{r['us_per_call']:>10.3f}")
    return 0


if __name__ == "__main__":
    # Allow running from a source checkout without installing the package. Done
    # only when run as a script so importing this module (pytest, wheel CI with
    # PYGOSQLX_TEST_INSTALLED=1) never puts the checkout on sys.path.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    sys.exit(main(sys.argv[1:]))
