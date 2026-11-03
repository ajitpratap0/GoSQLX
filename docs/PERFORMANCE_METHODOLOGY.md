# Performance Methodology

How GoSQLX measures performance, how a pull request is judged, and what we may claim in public. Commands assume the repository root and the [Task](https://taskfile.dev) runner.

## Principles

1. **A/B, never absolute.** A change is judged by a base build and a head build measured in the same job on the same machine. Absolute ns/op numbers from different machines or days are not comparable.
2. **Deterministic metrics gate; time gates only above the noise floor.** `allocs/op` and `B/op` do not depend on machine load, so they are hard gates. Time is a gate only for a statistically significant, material change.
3. **Report relative deltas.** Publish "-12.4% (p=0.002, n=10)", not a bare nanosecond figure.
4. **Behaviour is guarded too.** The golden hashes (`testdata/goldens`) must be unchanged; a speedup that changes output is a bug.

## The benchmark matrix

Most functionality-by-dialect cells have a benchmark; lint, security and LSP are pending (#910). List them with `go test -list Benchmark ./pkg/...`. Run the whole matrix once with:

```bash
task bench:matrix                      # all pkg benchmarks, -cpu 1, GOGC=off -> .bench/matrix.txt
task bench:matrix FILTER='^BenchmarkParseRW$' BENCHTIME=200ms
```

`pkg/cbinding` needs CGO and is run by `task bench:interop`. Competitor parsers are measured separately by `task bench:compare` (single pass) and `task bench:publish` (`-count=10`, writes `benchmarks/compare/results/latest.{json,txt}`).

## Running an A/B comparison

```bash
task bench:ab                          # working tree vs origin/main, gated suite
task bench:ab BASE=v1.17.0 ROUNDS=15
task bench:ab BENCH='./pkg/gosqlx=^BenchmarkParseE2E$'    # one benchmark
task bench:gate                        # exactly what CI runs, locally
```

`scripts/perf/ab.sh` builds test binaries for both revisions with the same toolchain and runs them interleaved in ABBA order for at least 10 rounds. The primary metric uses `GOGC=off GOMAXPROCS=1` (`-cpu 1`, pinned to one CPU where `taskset` exists): garbage-collection-free mutator time has low variance and ranks queries the same way the `-cpu 4` headline does. A secondary default-GC `-cpu 1` arm (`-g`, enabled by `bench:gate`) is reported for information only; `-cpu 4` is measured only by `task bench:profile` and the competitor harness. Results go through `benchstat` at alpha 0.01. The benchmarks that are gated are listed in `scripts/perf/gate-suite.txt`.

Tips: run on an idle machine, close other benchmarks, and re-run once if the A/A control (below) reports noise. Never weaken a test or a threshold to make a result pass.

## How the gate decides

`scripts/perf/gate` evaluates the run (rules from PLAN section 2.6). A PR fails when any of these holds:

| Check | Rule |
|---|---|
| Time | a gated benchmark is 3% or more slower at p < 0.01 (Mann-Whitney U), or the gated geomean is 1.5% or more slower |
| `allocs/op` | any gated benchmark allocates more |
| `B/op` | any gated benchmark rises by more than 2% |
| Instructions/op | any case executes more than 1.5% more instructions (`cmd/perfdriver`) |

**A/A control.** Each run also compares the base binary against a second copy of itself. If more than 10% of benchmarks move by more than 3% in that A/A comparison, the machine is too noisy: the job re-runs once, and a second noisy result is **inconclusive**, which is neutral, not a failure.

**Verdicts:** `pass`, `regression`, `noisy` (re-run), `inconclusive`. The gate starts in shadow mode (it reports but never fails); enforcement is switched on after the shadow period. A maintainer can accept a known regression with the `perf-regression-accepted` label plus a written justification in the PR body.

## Baseline files

`benchmarks/baselines/<goarch>.json` (`amd64.json`, `arm64.json`) records, for each gated benchmark, `ns_per_op` (trend only, never gated), `bytes_per_op` and `allocs_per_op` (gated). Keys are `<package path>:<benchmark name>`.

```bash
task bench:baseline                    # re-measure, fail if allocs/op rose or B/op rose >2%
task bench:baseline:update             # re-measure and rewrite benchmarks/baselines/<GOARCH>.json
go run ./scripts/perf/baseline -input out.txt     # check recorded `go test -bench -benchmem` output
```

`task bench:baseline` is local-only: no workflow runs `scripts/perf/baseline`, and it cannot run on CI's amd64 until `amd64.json` is recorded and the check is wired into `perf-gate.yml` (W0-13). In CI, allocs/op and B/op are currently gated relatively by the A/B gate. When recording from external output use `-update -input out.txt -go-version <toolchain>`; the local toolchain is never stamped onto external numbers.

Update a baseline only in a PR whose purpose or measured effect justifies it, and say why in the PR body. Record each architecture on that architecture's hardware; an empty file is refused by the check instead of passing silently. `amd64.json` is recorded at the first amd64 checkpoint.

The check fails (it does not pass silently) when a full measurement leaves a baseline entry unmeasured or finds a benchmark the baseline lacks, because a suite-regex change rekeys entries: run `task bench:baseline:update`. It also fails when no baseline benchmark was measured, and with `-input` it rejects output whose `goarch:` header differs from `-arch`. allocs/op and B/op can shift between Go minors, so the check warns when the baseline's `go_version` differs in major.minor from the running toolchain; record baselines with the toolchain CI uses.

Deviation from PLAN 2.7: the baseline files do not store instructions/op (Ir). Ir is gated relatively by `perfdriver` in the A/B gate instead.

`performance_baselines.json` and `TestPerformanceRegression` (`pkg/sql/parser`) remain only as a **smoke test**: loose ns/op ceilings with 60-65% tolerances that catch order-of-magnitude breakage on noisy CI. They are not a gate and their tolerances must not be tightened to act as one.

## Profiling and PGO

```bash
task bench:profile                     # pprof at -cpu 1 / GOGC=off / -cpu 4 for the gap queries
task pgo:refresh                       # regenerate cmd/gosqlx/default.pgo from the parse benchmarks
```

A refreshed PGO profile is committed only after `task bench:ab` shows a gain and no gated regression.

## Claims policy

Public performance statements (README, website, release notes) follow these rules:

- **Form:** "fastest of N measured on `<corpus, dialect, arch>`". N, the corpus, the dialect and the architecture must all be named.
- **Measurement:** same machine, interleaved, in-process, with raw JSON published and a one-command reproduction (`task bench:publish`).
- **Corpus:** the headline corpus is the set of statements every listed parser accepts. Acceptance rate is reported next to speed.
- **Ties:** a gap under 3% is a tie.
- **Per-cell evidence:** a claim needs every relevant peer measured in that cell. No Go peer in a dialect means only "the only Go parser with X", not a speed claim.
- **Rust and C:** no claim against Rust or C parsers until the cross-language harness has run on the same machine and corpus; then report the result whatever it is.
- **No peer:** for lint, security scan, transform, LSP, bindings and WASM we publish latency budgets only, never "fastest".
- **Timing:** website claims ship with the release docs PR, not on code merge.

## Reference

- `scripts/perf/ab.sh`, `scripts/perf/gate/`, `scripts/perf/gate-suite.txt`: A/B runner, verdict logic, gated suite
- `scripts/perf/baseline/`: baseline recorder and checker
- `.github/workflows/perf-gate.yml`: CI gate; `.github/workflows/bench-compare.yml`: competitor runs
- `benchmarks/compare/README.md`: competitor harness
