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
- **Recorded with every run:** commit, Go version, CPU, OS/arch, the exact
  command and each library's pinned version.

## Libraries and pinned versions

Versions are pinned in this module's [`go.mod`](go.mod); GoSQLX is resolved
from the enclosing repository through a `replace` directive, so a run always
measures the checked-out commit.

| ID | Library | Dialect |
|---|---|---|
| `gosqlx` | github.com/ajitpratap0/GoSQLX | multi-dialect (default settings) |
| `pg_query_go` | github.com/pganalyze/pg_query_go/v6 | PostgreSQL (real PostgreSQL parser via CGo) |
| `vitess` | vitess.io/vitess (`go/vt/sqlparser`) | MySQL |
| `tidb` | github.com/pingcap/tidb/pkg/parser | MySQL (TiDB) |
| `xwb1989` | github.com/xwb1989/sqlparser | MySQL (2018 Vitess fork) |

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
```

After publishing, copy `results/latest.json` to
`website/src/data/competitor-benchmarks.json`. The website drift check
(`npm run check:metrics`) fails when the two files differ.

## CI

`.github/workflows/bench-compare.yml` runs vet, race tests and a smoke
benchmark on every change to this directory. Running it manually
(`workflow_dispatch`) or pushing a release tag performs a full run and uploads
the JSON, the raw output and a benchstat summary as an artifact.
