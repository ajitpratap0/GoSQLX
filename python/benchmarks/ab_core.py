"""Interleave baseline/head bench_core processes using only the standard library.

Run once per decoder with the same interpreter and GOSQLX_LIB_PATH. The legacy
orjson baseline uses a disclosed runtime decoder shim, retaining its UTF-8
conversion; the baseline source files are never modified.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import sys
from pathlib import Path


_BOOTSTRAP = r'''
import json, runpy, sys, types
root, decoder = sys.argv[1:3]
sys.path.insert(0, root)
from pygosqlx import core
loads = json.loads
if decoder == "orjson":
    import orjson
    loads = orjson.loads
if hasattr(core, "_loads"):
    core._loads = loads
    core._DECODER = decoder
elif decoder == "orjson":
    core.json = types.SimpleNamespace(loads=loads, dumps=json.dumps)
sys.argv = [root + "/benchmarks/bench_core.py", "--json", "--repeat", "7", "--number", "2000"]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


def mann_whitney_p(base: list[float], head: list[float]) -> float:
    """Two-sided normal approximation, with ties and continuity correction.

    Independent subprocess runs are the samples, not timeit's inner repeats.
    """
    combined = sorted([(v, 0) for v in base] + [(v, 1) for v in head])
    rank_sum = 0.0
    ties = 0
    i = 0
    while i < len(combined):
        j = i + 1
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        rank = (i + 1 + j) / 2
        rank_sum += rank * sum(group == 0 for _, group in combined[i:j])
        ties += (j - i) ** 3 - (j - i)
        i = j
    n, m = len(base), len(head)
    total = n + m
    u = rank_sum - n * (n + 1) / 2
    variance = n * m / 12 * (total + 1 - ties / (total * (total - 1)))
    if variance == 0:
        return 1.0
    z = max(0, abs(u - n * m / 2) - 0.5) / math.sqrt(variance)
    return math.erfc(z / math.sqrt(2))


def summarize(base: list[float], head: list[float]) -> dict:
    def sample(values):
        quartiles = statistics.quantiles(values, n=4, method="inclusive")
        return {"median_us": statistics.median(values), "iqr_us": quartiles[2] - quartiles[0]}

    b, h = sample(base), sample(head)
    return {
        "base": b, "head": h,
        "delta_pct": (h["median_us"] / b["median_us"] - 1) * 100,
        "p_value": mann_whitney_p(base, head),
    }


def measure(root: Path, decoder: str) -> dict:
    completed = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP, str(root), decoder],
        cwd=root, check=True, capture_output=True, text=True,
    )
    result = {}
    for row in json.loads(completed.stdout):
        key = (row["op"], row["query"])
        value = row["us_per_call"]
        if key in result or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError("benchmark returned duplicate rows or invalid timing")
        if row.get("decoder", decoder) != decoder:
            raise ValueError("benchmark decoder differs from requested decoder")
        result[key] = value
    if not result:
        raise ValueError("benchmark returned no rows")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", type=Path, required=True, help="baseline python/ directory")
    parser.add_argument("--head", type=Path, required=True, help="candidate python/ directory")
    parser.add_argument("--runs", type=int, default=10, help="number of A/B pairs")
    parser.add_argument("--decoder", choices=("json", "orjson"), default=None)
    args = parser.parse_args(argv)
    if args.runs < 2:
        parser.error("--runs must be >= 2")
    library = os.environ.get("GOSQLX_LIB_PATH")
    if not library or not Path(library).is_absolute() or not Path(library).is_file():
        parser.error("GOSQLX_LIB_PATH must name one existing absolute shared-library path")
    if args.decoder is None:
        try:
            import orjson  # noqa: F401
        except ImportError:
            args.decoder = "json"
        else:
            args.decoder = "orjson"
    roots = {name: path.resolve() for name, path in (("base", args.base), ("head", args.head))}
    for root in roots.values():
        if not (root / "benchmarks/bench_core.py").is_file():
            parser.error(f"missing benchmark under {root}")
    samples = {"base": [], "head": []}
    try:
        for run in range(args.runs):
            for name, root in roots.items():
                print(f"pair {run + 1}/{args.runs}: {name} ({args.decoder})", file=sys.stderr, flush=True)
                rows = measure(root, args.decoder)
                if samples["base"] and rows.keys() != samples["base"][0].keys():
                    raise ValueError("benchmark row sets differ across measurements")
                samples[name].append(rows)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"cannot measure: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr, file=sys.stderr)
        return 1
    rows = []
    for key in samples["base"][0]:
        row = {"op": key[0], "query": key[1], "decoder": args.decoder}
        row.update(summarize(*[[run[key] for run in samples[name]] for name in roots]))
        row["samples_us"] = {name: [run[key] for run in samples[name]] for name in roots}
        rows.append(row)
    print(json.dumps({
        "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor(), "library": os.environ.get("GOSQLX_LIB_PATH"),
        "decoder": args.decoder, "runs": args.runs, "order": "AB" * args.runs,
        "repeat": 7, "number": 2000,
        "baseline": str(roots["base"]), "head": str(roots["head"]),
        "orjson_baseline": "synthetic runtime decoder shim; legacy UTF-8 conversion retained" if args.decoder == "orjson" else None,
        "p_method": "two-sided Mann-Whitney U, normal approximation with ties and continuity correction",
        "iqr_method": "inclusive quartiles", "rows": rows,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
