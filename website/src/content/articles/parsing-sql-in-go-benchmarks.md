---
title: "Parsing SQL in Go: benchmark methodology and results"
description: "A reproducible end-to-end benchmark of five Go SQL parsers, GoSQLX, pg_query_go, Vitess, TiDB and xwb1989, with the method, raw data and honest caveats."
date: 2026-10-18
tags: [go, benchmarks, sql, parsers]
---

Benchmark claims about SQL parsers are easy to make and hard to check. Numbers get copied from old READMEs, measured on different machines, or compare a tokenizer on one side with a full parse on the other. This post describes the benchmark harness in the GoSQLX repository, which anyone can rerun, and the results of its most recent recorded run.

Every figure below is generated at build time from the harness output committed to the repository (`benchmarks/compare/results/latest.json`). None of them is typed by hand, and when the harness is rerun and the file is updated, the tables on this page change with it.

## What is measured

The harness measures the **end-to-end** cost of turning SQL text into each library's syntax tree: the input is a Go string, the output is a usable AST. For GoSQLX that is `gosqlx.Parse` (tokenize and parse) followed by `ast.ReleaseAST`. For the other libraries it is their standard parse entry point.

This run: {{bench:env}}.

### Libraries

Versions are pinned in the harness's own `go.mod`. GoSQLX is resolved from the enclosing repository through a `replace` directive, so a run always measures the checked-out commit.

{{bench:libraries}}

### Queries

Every library parses the same statements. The corpus sticks to a portable subset of SQL (no quoted identifiers, no dialect-only operators) so that MySQL-only and PostgreSQL-only parsers can take part. When a library rejects a statement, the harness records it as unsupported instead of benchmarking an error path.

{{bench:queries}}

### Method

Each benchmark runs with `go test -bench -benchmem` and `-count=10`, and the harness records the **median** of the ten samples for time, bytes and allocations. The command was:

{{bench:command}}

The raw `go test` output is committed next to the JSON (`results/latest.txt`), so you can summarise it differently, for example with `benchstat`, if you disagree with the median.

## Results

### Time per parse

Median nanoseconds per operation, rounded to the nearest nanosecond. Lower is better. "rejected" means the library could not parse that statement.

{{bench:table:ns}}

### Summary against GoSQLX

For each library, over the queries both it and GoSQLX accept: how many queries it parsed faster than GoSQLX, and the geometric mean of its time divided by GoSQLX's time. A value below 1.00x means faster than GoSQLX on average; above 1.00x means slower.

{{bench:table:summary}}

### Allocations per parse

Median heap allocations per operation. Lower is better.

{{bench:table:allocs}}

### Bytes allocated per parse

Median bytes allocated per operation. Lower is better.

{{bench:table:bytes}}

## Reading the results

The tables above are regenerated on every build. The observations in this section describe the run recorded on this page; if you are reading a later version of the data, trust the tables over the prose.

**GoSQLX is not the fastest parser on every query.** Vitess, the MySQL parser from the Vitess project, is GoSQLX's closest competitor and is faster on several statements. The two trade places depending on query shape. If you only parse MySQL and only need a syntax tree, Vitess is an excellent choice, and the summary table shows exactly how close the two are.

**Allocation counts and allocated bytes tell different stories.** In this run GoSQLX makes fewer heap allocations than the other libraries on most queries, which reflects its pooled tokenizer and zero-copy token values. Vitess allocates fewer bytes on most queries. Fewer allocations usually means less GC bookkeeping, fewer bytes means less memory traffic; which one matters more depends on your workload, so the harness reports both.

**pg_query_go pays for exactness.** pg_query_go embeds the real PostgreSQL parser through CGo and converts its tree into Go structs. That conversion, and the CGo boundary, make it the slowest library in every row. In exchange it accepts exactly what PostgreSQL accepts, which no pure-Go parser can promise. If PostgreSQL fidelity matters more than speed, it is the right tool.

**Coverage is part of the result.** xwb1989/sqlparser, an unmaintained 2018 fork of the Vitess parser, rejects the CTE and window-function statements. A parser that cannot read your query has no meaningful speed.

## What this benchmark does not tell you

- **It is not identical work.** {{bench:caveat}}
- **It is one machine.** Every figure belongs to the hardware and Go version listed above. Shared CI runners are noisy; run the harness on the machine you care about.
- **It is single-threaded.** It does not measure throughput under concurrency, contention on pools, or GC behaviour in a long-running service.
- **It is end-to-end only.** It does not separate tokenizing from parsing. GoSQLX's own stage-level benchmarks live in the main repository and are reported separately on the [benchmarks page](/benchmarks/), labelled as parse-stage numbers.
- **It does not measure correctness.** Accepting a statement is not the same as building the right tree for it. Use dialect test suites for that.

## Reproduce it

You need Go and a C toolchain (pg_query_go uses CGo).

```bash
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX/benchmarks/compare

# one quick pass over the corpus
go test -run='^$' -bench=. -benchmem ./...

# the full run used for publishing: -count=10, writes results/latest.json and latest.txt
task bench:publish
```

The corpus is in `benchmarks/compare/corpus.go` and the adapters for each library are in `parsers.go`. If you think an adapter is unfair to a library, for example because it uses a slower entry point than necessary, please open an issue or a pull request: the point of a public harness is that its mistakes can be found and fixed.

Further reading:

- [Benchmarks page](/benchmarks/): GoSQLX parse-stage numbers and the competitor comparison
- [Compare Go SQL parsers](/compare/): features, dialects and trade-offs beyond speed
- [Performance tuning](/docs/guides/performance-tuning/)
