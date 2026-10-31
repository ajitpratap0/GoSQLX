# Results JSON schema v2

`results/latest.json` is written by `go run ./cmd/publish`. `schemaVersion` is
`2`. Schema v2 only adds fields: every v1 field is still written with its v1
meaning, because the website reads this file (`website/src/data/competitor-benchmarks.json`
is a byte copy, checked by `npm run check:metrics`). Consumers that only know
v1 can ignore everything under "v2 additions".

## v1 fields (unchanged)

| Field | Meaning |
|---|---|
| `generatedAt`, `commit`, `dirty`, `goVersion` | provenance |
| `hardware` | `{cpu, goos, goarch, numCPU}` of the machine that ran it |
| `stage` | always `"e2e"` for the v1 view |
| `method` | `{command, count, statistic, rawOutput}` of the **first** configuration. `command` is a quoted, copy-pasteable `go test` line (run it in `benchmarks/compare`) that reproduces `results[]`: `BenchmarkParse` only, with a `GOGC=off ` prefix only when that configuration sets it. |
| `caveat` | the like-for-like caveat the website prints |
| `parsers[]` | the v1 parsers only: `gosqlx`, `pg_query_go`, `vitess`, `tidb`, `xwb1989` |
| `queries[]` | the 11 portable queries `{id, name, sql}` |
| `results[]` | `BenchmarkParse` medians per (query, v1 parser) of the first configuration: `{query, parser, supported, samples, nsPerOp, bytesPerOp, allocsPerOp}`; measurements are `null` when `supported` is false |

`parsers[]` entries gained `license`, `legacy` and `peerDialects`; these are
additions to the object, not changes.

Note: the first configuration is now explicit: `cmd/publish` defaults to
`-cpus=1 -gogc=default` (CI passes the same primary), so `results[]` are
measured at `-cpu 1`. Earlier files were measured at the runner's default
GOMAXPROCS (4); do not compare the two.

## v2 additions

| Field | Meaning |
|---|---|
| `peers[]` | every library under test, same shape as `parsers[]` (`id, name, module, version, dialect, cgo, license, legacy, peerDialects`). `peerDialects` lists the corpus dialects the library is a like-for-like peer for. `gosqlx_norelease` is the GoSQLX variant that skips `ReleaseAST`. |
| `ormQueries[]` | the ORM-style corpus `{id, name, shape, sql}`; `shape` is quoted, placeholders, lowercase, ddl, nesting or multistatement |
| `configs[]` | the run matrix, first entry primary: `{id, cpu, gogc, command, rawOutput}`. `cpu` is the `-cpu` value (0 = go test default), `gogc` is `default` or `off`. `id` looks like `cpu4-gogc-off`. `command` is the quoted `go test` line of that run (all selected families). |
| `cells[]` | one row per (benchmark cell, group, implementation, configuration) |
| `acceptance[]` | `{dialect, parser, accepted, total, rate}` over all of `testdata/realworld/<dialect>`, legacy parsers included |
| `commonAccept[]` | `{dialect, parsers, total, accepted, setSha256}` summarising `commonaccept/<dialect>.txt` |

### `cells[]` rows

```json
{"cell": "ParseDialect", "group": "mysql", "parser": "vitess",
 "config": "cpu1-gogc-off", "samples": 10,
 "nsPerOp": 733510.0, "bytesPerOp": 593820, "allocsPerOp": 7574}
```

- `cell`: the benchmark family without the `Benchmark` prefix: `Parse`,
  `ParseORM`, `ParseFresh`, `ParseParallel`, `ParseDialect`, `Lex`,
  `Normalize`, `Render`.
- `group`: the query ID (`Parse`, `ParseORM`, `ParseFresh`, `ParseParallel`,
  `Lex`, `Normalize`, `Render`) or the dialect (`ParseDialect`).
- `parser`: the `peers[].id` for the parse cells (`ParseFresh` and `ParseParallel` also have `gosqlx_metricson`, GoSQLX with metrics enabled), the implementation ID
  (`gosqlx_scratch`, `tidb_digest`, ...) for `Lex`, `Normalize` and `Render`.
- `config`: a `configs[].id`.
- `samples`: number of `-count` repetitions; `nsPerOp`, `bytesPerOp` and
  `allocsPerOp` are medians. A cell a parser rejects has no row (it is skipped
  in the benchmark), so absence plus `acceptance[]` explains it.
- A `ParseDialect` op parses the whole common-accept set; divide by
  `commonAccept[].accepted` for a per-statement figure.

## Compatibility rules

1. Fields are only added. A removal or a meaning change needs `schemaVersion` 3
   and a website change in the same PR.
2. `parsers[]`, `queries[]` and `results[]` describe the v1 parsers and the
   portable corpus only. New peers appear in `peers[]` and `cells[]` until the
   website opts in.
3. `results/latest.json` and the website copy are replaced together.
