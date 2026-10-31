# Competitor benchmark harness

A reproducible comparison of GoSQLX against other Go SQL parsers (issue #673).
Every competitor number on gosqlx.dev must come from `results/latest.json` in
this directory.

## What is measured

- **Stage:** end-to-end. SQL text in, the library's AST out. For GoSQLX that is
  `gosqlx.Parse` (tokenize and parse) followed by `ast.ReleaseAST`.
- **Corpus:** the same statements for every library, defined in
  [`corpus.go`](corpus.go). They stick to a portable subset (no quoted
  identifiers, no dialect-only operators). A library that rejects a statement
  is recorded as unsupported, not benchmarked.
- **Statistic:** median of `-count=10` runs of `go test -bench -benchmem`. The
  raw output is kept in `results/latest.txt` so you can re-summarise it with
  `benchstat`.
- **Run matrix:** `-cpu 1` and `-cpu 4`, each with GOGC at its default and with
  `GOGC=off`, to separate mutator CPU from GC cost. The first configuration
  (`cpu1-gogc-default`) feeds the v1 fields; the others are in `cells` of the
  v2 document and in `results/latest-<config>.txt`. Compare configurations of
  one run, not absolute numbers across machines.
- **Recorded with every run:** commit, Go version, CPU, OS/arch, the exact
  command and each library's pinned version.

## Libraries and pinned versions

Versions are pinned in this module's [`go.mod`](go.mod); GoSQLX is resolved
from the enclosing repository through a `replace` directive, so a run always
measures the checked-out commit. Licenses below were read from the `LICENSE`
file of the pinned version on 2026-11-01; re-check them when a version moves.

| ID | Library | Dialect | License | Role |
|---|---|---|---|---|
| `gosqlx` | github.com/ajitpratap0/GoSQLX | multi-dialect (default settings) | Apache-2.0 | subject |
| `gosqlx_norelease` | same, without `ReleaseAST` | same | Apache-2.0 | subject (competitors never release their ASTs, so this isolates our release step) |
| `pg_query_go` | github.com/pganalyze/pg_query_go/v6 | PostgreSQL (real parser via CGo) | BSD-3-Clause | peer |
| `vitess` | vitess.io/vitess (`go/vt/sqlparser`) | MySQL | Apache-2.0 | peer |
| `tidb` | github.com/pingcap/tidb/pkg/parser | MySQL (TiDB) | Apache-2.0 | peer |
| `dolthub_vitess` | github.com/dolthub/vitess | MySQL (Dolt fork of Vitess) | Apache-2.0 | peer |
| `rqlite_sql` | github.com/rqlite/sql | SQLite | MIT | peer |
| `aftership_clickhouse` | github.com/AfterShip/clickhouse-sql-parser | ClickHouse | MIT | peer |
| `auxten_pg` | github.com/auxten/postgresql-parser | PostgreSQL (extracted CockroachDB parser) | mixed, see below | peer |
| `xwb1989` | github.com/xwb1989/sqlparser | MySQL (2018 Vitess fork) | Apache-2.0 | legacy: benchmarked and listed, never gates a common-accept set |

**auxten/postgresql-parser licensing.** The module `LICENSE` says the source is
"variously licensed" under BSL 1.1, the CockroachDB Community License, MIT and
BSD-style licenses, and individual files (for example `pkg/sql/parser/parse.go`)
carry BSD (Vitess) plus Cockroach BSL headers, with the license texts referenced
from a `licenses/` directory that the published module does not contain. It is
a benchmark-only dependency of this separate module and nothing from it is
shipped or redistributed. Do not copy its code, and have the license reviewed
before quoting it anywhere beyond a benchmark label.

## Benchmark cells

Every cell is a Go benchmark in `compare_test.go`; names are
`Benchmark<Cell>/<group>/<implementation>`.

| Cell | Group | Implementations | What is timed |
|---|---|---|---|
| `Parse` | portable query ([`corpus.go`](corpus.go)) | every parser | SQL text to AST (the v1 cell) |
| `ParseORM` | ORM-style query ([`corpus_orm.go`](corpus_orm.go)) | every parser | same, on quoted identifiers, placeholders, lowercase, DDL, deep nesting and multi-statement text |
| `ParseFresh` | portable query | every parser | one parse on a brand-new goroutine per op (server shape; exposes stack growth) |
| `ParseParallel` | portable query | every parser | `b.RunParallel`, one parse function per worker; run at `-cpu 1,4` |
| `ParseDialect` | dialect | GoSQLX and the non-legacy peers of that dialect | one whole common-accept set per op |
| `Lex` | portable query | `gosqlx_scratch`, `gosqlx_public`, `vitess`, `pgquery_scan` | tokenisation only |
| `Normalize` | portable query | `gosqlx`, `gosqlx_fingerprint`, `tidb_digest`, `pgquery_normalize`, `pgquery_fingerprint`, `vitess_redact` | literal normalisation or fingerprint; outputs differ in form |
| `Render` | portable query | `gosqlx_sql`, `gosqlx_compact`, `vitess_string`, `tidb_restore`, `pgquery_deparse` | AST to SQL of a pre-parsed statement |

A token-mode GoSQLX normaliser does not exist yet, so `Normalize` has no
`gosqlx_tokens` entry; add it to `NormalizeImpls` when it lands.

## Acceptance and common-accept sets

Parsers accept different amounts of SQL, and timing a parser on statements it
rejects measures an early exit. So every dialect-level number is reported with
its acceptance rate, and `ParseDialect` times only a **common-accept set**: the
statements of `testdata/realworld/<dialect>` that GoSQLX and every non-legacy
peer of that dialect parse (MariaDB uses the MySQL peers; dialects with no Go
peer, such as Oracle, Snowflake and SQL Server, are timed for GoSQLX alone).

- `go test -v -run TestAcceptanceTable` prints the acceptance table: accepted
  and total statements per (parser, dialect), including legacy parsers.
- [`commonaccept/<dialect>.txt`](commonaccept) is the checked-in set: one
  SHA-256 per statement, sorted, with the gating parsers, counts and a hash of
  the whole set in the header. Repeated statements are listed once.
- `TestCommonAcceptSets` recomputes every set and fails when a library bump or
  a corpus edit changes it. Review the diff, then regenerate with
  `go test -run TestCommonAcceptSets -update`.

The acceptance table is informational. GoSQLX is tuned on this corpus (it
accepts all of it), so read the peers' rates as "how much of this corpus the
grammar covers", not as a quality ranking; some peers (rqlite, AfterShip)
parse only the first statement of a multi-statement text.

## Caveat

The libraries implement different dialects and build different ASTs.
pg_query_go runs the real PostgreSQL parser in C and converts its tree into Go
structs; the others are pure Go. The numbers compare the cost of getting a
usable tree from the same SQL on the same machine, not identical work. Shared
CI runners are noisy, so always read a figure together with the hardware it
was measured on.

## Running it

A C toolchain is required (pg_query_go uses CGo).

```bash
# One pass over the corpus
cd benchmarks/compare && go test -run='^$' -bench=. -benchmem ./...

# Full run with -count=10, as in the issue's verification step
cd benchmarks/compare && go test -bench=. -benchmem -count=10 ./...

# Publish: run -count=10, write results/latest.json and results/latest.txt,
# then print a benchstat summary
task bench:publish

# Publish the CI matrix (schema v2 cells for every configuration)
cd benchmarks/compare && go run ./cmd/publish -cpus=1,4 -gogc=default,off -benchtime=200ms
```

The results document is schema v2; see [`SCHEMA.md`](SCHEMA.md). Schema v1
fields are kept, so the website keeps working.

After publishing, copy `results/latest.json` to
`website/src/data/competitor-benchmarks.json`. The website drift check
(`npm run check:metrics`) fails when the two files differ.

## CI

`.github/workflows/bench-compare.yml` runs vet, race tests and a smoke
benchmark on every change to this directory. Running it manually
(`workflow_dispatch`) or pushing a release tag performs a full run and uploads
the JSON, the raw output of every configuration and a benchstat summary per
configuration as an artifact. The smoke run covers `-cpu 1,4`; the publish job
runs the full `-cpu 1,4` x `GOGC=default,off` matrix.
