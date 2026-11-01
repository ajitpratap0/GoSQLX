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


def test_benchmark_queries_are_valid_sql():
    import pygosqlx

    bench = _load_bench()
    for name, sql in bench.QUERIES.items():
        assert pygosqlx.validate(sql), name


def test_main_rejects_nonpositive_counts():
    bench = _load_bench()
    with pytest.raises(SystemExit):
        bench.main(["--number", "0"])
