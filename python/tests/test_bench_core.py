"""The micro benchmark must keep running against the public API.

It is skipped when the shared library is not built.
"""

import importlib.util
import pathlib

import pytest

from pygosqlx import core

try:
    core._get_lib_path()
    LIB_AVAILABLE = True
except OSError:
    LIB_AVAILABLE = False

pytestmark = pytest.mark.skipif(not LIB_AVAILABLE, reason="shared library not built")


def _load_bench():
    path = pathlib.Path(__file__).resolve().parent.parent / "benchmarks" / "bench_core.py"
    spec = importlib.util.spec_from_file_location("bench_core", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_operation_and_query_is_measured():
    bench = _load_bench()
    rows = bench.run(repeat=1, number=2)
    ops = set(bench.operations())
    assert {(r["op"], r["query"]) for r in rows} == {(o, q) for o in ops for q in bench.QUERIES}
    assert all(r["us_per_call"] > 0 for r in rows)
    assert all(r["decoder"] == core._DECODER for r in rows)


def test_benchmark_queries_are_valid_sql():
    import pygosqlx

    bench = _load_bench()
    for name, sql in bench.QUERIES.items():
        assert pygosqlx.validate(sql), name


def test_main_rejects_nonpositive_counts():
    bench = _load_bench()
    with pytest.raises(SystemExit):
        bench.main(["--number", "0"])


def test_text_header_identifies_decoder(capsys):
    bench = _load_bench()
    assert bench.main(["--repeat", "1", "--number", "1"]) == 0
    assert f"decoder: {core._DECODER}" in capsys.readouterr().out


def _load_ab():
    path = pathlib.Path(__file__).resolve().parent.parent / "benchmarks" / "ab_core.py"
    spec = importlib.util.spec_from_file_location("ab_core", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ab_statistics_report_ties_and_direction():
    ab = _load_ab()
    assert ab.mann_whitney_p([1.0] * 10, [1.0] * 10) == 1.0
    base = list(range(20, 30))
    head = list(range(10, 20))
    result = ab.summarize(base, head)
    assert result["base"] == {"median_us": 24.5, "iqr_us": 4.5}
    assert result["head"] == {"median_us": 14.5, "iqr_us": 4.5}
    assert result["delta_pct"] == pytest.approx((14.5 / 24.5 - 1) * 100)
    assert result["p_value"] < 0.05
    assert ab.mann_whitney_p(base, head) == ab.mann_whitney_p(head, base)


def test_ab_driver_interleaves_independent_process_samples(tmp_path, monkeypatch, capsys):
    import json

    ab = _load_ab()
    roots = [tmp_path / name for name in ("base", "head")]
    for root in roots:
        (root / "benchmarks").mkdir(parents=True)
        (root / "benchmarks" / "bench_core.py").touch()
    calls = []

    def measure(root, decoder):
        calls.append((root, decoder))
        return {("parse", "small"): 10 if root == roots[0] else 8}

    monkeypatch.setattr(ab, "measure", measure)
    assert ab.main(["--base", str(roots[0]), "--head", str(roots[1]), "--runs", "10", "--decoder", "json"]) == 0
    assert calls == [(root, "json") for _ in range(10) for root in roots]
    report = json.loads(capsys.readouterr().out)
    assert report["order"] == "AB" * 10
    assert report["repeat"] == 7
    assert report["number"] == 2000
    assert report["orjson_baseline"] is None
    assert report["rows"][0]["delta_pct"] == pytest.approx(-20)
