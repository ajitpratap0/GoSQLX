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
task bench:matrix                      # all pkg benchmarks, -cpu 1, GOGC=off GOMEMLIMIT=64MiB -> .bench/matrix.txt
task bench:matrix FILTER='^BenchmarkParseRW$' BENCHTIME=200ms
```

`pkg/cbinding` needs CGO and is run by `task bench:interop`. Competitor parsers are measured separately by `task bench:compare` (single pass) and `task bench:publish` (`-count=10`, writes `benchmarks/compare/results/latest.{json,txt}`).

## Running an A/B comparison

```bash
task bench:ab                          # working tree vs origin/main, gated suite
task bench:ab BASE=v1.17.0 ROUNDS=40   # two rounds per layout
task bench:ab BENCH='./pkg/gosqlx=^BenchmarkParseE2E$'    # one benchmark
task bench:gate                        # exactly what CI runs, locally
```

`scripts/perf/ab.sh` builds test binaries for both revisions with the same toolchain and runs them interleaved, rotating the arm order every round (20 rounds of 100ms by default). Each arm is built as `K` binaries (default 20, `-k`/`LAYOUTS`) linked with `-ldflags=-randlayout=<seed>`, which shuffles the order of every Go function; base and head use the same seeds and round `r` runs layout `r mod K`. Where the linker places a function moves its timing by a few percent through alignment, branch-predictor and cache aliasing, and by different amounts on different CPU models. With one binary per arm, a change that adds no work but shifts the code by a few bytes could look 3-10% slower or faster (PR #931 and its control runs). With randomized layouts, every arm averages over the same layout distribution. `-k 0` builds one default-layout binary per arm, as before. The primary metric uses `GOGC=off GOMEMLIMIT=64MiB GOMAXPROCS=1` (`-cpu 1`, pinned to one CPU where `taskset` exists): almost garbage-collection-free mutator time has low variance and ranks queries the same way the `-cpu 4` headline does. A secondary default-GC `-cpu 1` arm (`-g`, enabled by `bench:gate`) is reported for information only; `-cpu 4` is measured only by `task bench:profile` and the competitor harness. Results go through `benchstat` at alpha 0.01. The benchmarks that are gated are listed in `scripts/perf/gate-suite.txt`.

Adaptive layouts are enabled by `-G` with a 600-second extension budget; plain A/B and matrix runs keep extension off. `-B SECS` overrides that wall-time budget (0 disables), `-E SECS` stops new extension work after that many seconds from the script's start (0 means no deadline), and `-K KMAX` caps layouts per arm (default 200). CI uses `-B 600 -E 2100`: normal measurement is about 13.5 minutes plus up to 10 minutes of extension; the measured forced-retry case is 21.7 + 10 = 31.7 minutes. The step allows 40 minutes and the job 45, including about one minute for setup and upload. Raw output carries `suite-line:` labels to preserve benchmark process context.

**Why GOMEMLIMIT.** With `GOGC=off` and no limit the heap only grows, so every allocated byte lands on a fresh page and pays a first-touch page fault and kernel zeroing. That cost is not mutator work, scales with B/op and lands on whichever benchmark first grows the heap in a process (in the amd64 checkpoint the first benchmark of a binary gained nothing from `GOGC=off` while the others gained 21-25%). With a limit the collector runs only when the heap reaches it and the pages are reused. Every `GOGC=off` measurement (`ab.sh`, `profile.sh`, `task bench:matrix`, the competitor harness) therefore also sets `GOMEMLIMIT`, default `64MiB` from `scripts/perf/lib.sh`; override it with `PERF_GOMEMLIMIT` (or the `gomemlimit` dispatch input), and `off` unsets it. Consequences:

- Timings include a small GC share (each collection of the tiny live heap costs about 0.5 ms, about 1% of a run), and so do instructions/op: `perfdriver` and cachegrind run with the same limit, so Ir/op is no longer pure mutator work but carries a GC share proportional to B/op (about 0.25% for `join`).
- Each collection drains the `sync.Pool`s. allocs/op stays exact for the gated suite (identical in every A/A and PR run so far) but varies for large-input and low-iteration benchmarks (`ParseRW/*/large`, `Handler_LargeDocument`, `*SustainedLoad*`), which are not gated.
- `GOGC=off` timings recorded before this change are not comparable with later ones; base and head of one run always share the setting.

`scripts/perf/baseline` (below) is the deliberate exception: it gates absolute allocs/op and B/op only, so it runs `GOGC=off` with no limit, where no collection drains a pool and the counts are exact for every benchmark.

**Toolchain.** `perf-gate.yml` and `bench-compare.yml` build with one pinned Go release, `PERF_GO_VERSION` (1.26.9, the toolchain of the recorded baselines), with `GOTOOLCHAIN=local` so `go.mod` cannot switch it. Numbers from the gate and the competitor harness are only comparable when built by the same release.

**Ratios only.** Hosted runners hand out different CPU models from job to job. Every artifact and report names the runner CPU, and reports compare base and head of the same job by ratio only; absolute ns/op hold for that CPU and job alone. The competitor harness summary likewise leads with GoSQLX/peer time ratios (`cmd/publish -ratios`).

Tips: run on an idle machine, close other benchmarks, and re-run once if the A/A control (below) reports noise. Never weaken a test or a threshold to make a result pass.

## How the gate decides

`scripts/perf/gate` evaluates the run (rules from PLAN section 2.6). A PR fails when any of these holds:

| Check | Rule |
|---|---|
| Time | a gated benchmark is 3% or more slower and significant at a false discovery rate of 0.01 over the suite (Benjamini-Hochberg on exact Mann-Whitney U p-values of the per-layout medians), or the gated geomean is 1.5% or more slower at p < 0.01 (the same test on per-layout suite geomeans) |
| `allocs/op` | any gated benchmark allocates more |
| `B/op` | any gated benchmark rises by more than 2% |
| Instructions/op | any case executes more than 1.5% more instructions (`cmd/perfdriver`) |

**Why per-layout medians and false-discovery control.** The layout is the experimental unit: every sample of one binary shares its layout offset, so pooling a binary's samples treats one draw of that offset as many independent ones. Each layout is summarised by the median of its samples and the two arms' `K` values are compared with an exact Mann-Whitney U test. Under "no change" the per-layout values of both arms are exchangeable, so the test is calibrated whatever shape the layout distribution has. The reported change is the matching Hodges-Lehmann shift: the median ratio over all pairs of head and base layouts. With one 100ms run per layout, a single run disturbed by another tenant can be tens of percent off; ranks and the Hodges-Lehmann shift ignore it, while a mean would not. Equal seeds do not give corresponding layouts once the symbol lists differ, so the test is unpaired. Testing 30-odd benchmarks at 0.01 each would still flag about one no-op change in ten; the Benjamini-Hochberg step-up keeps the chance of any false time regression on a no-op change at 1%. A lone single-benchmark regression then needs p <= 0.01/m. Stage 1 remains 20 layouts, the A/A' control, the secondary metric, instruction counts and the existing noisy retry. The gate then sizes each benchmark independently for 80% estimated power against a lone +5% slowdown at alpha/m. Base and head receive extra randomized layouts, in batches of at most eight and at most three extension stages, with replanning over all samples. Each benchmark runs in its original suite-line binary after that line's first benchmark as a warm-up. Linking finishes before measurement starts; each batch's binaries are deleted afterwards.

Only per-benchmark primary time uses stage-1 plus extension layouts. The A/A' noise rule and flagged count, suite geomean, allocs/op, B/op, secondary metric and instructions/op all use stage-1 data only. Sizing uses within-arm dispersion, never the head-base difference: per-layout medians are divided by their own arm's median and logged, then pooled across base, head and the stage-1 A/A' control. Under the null, both arms run the same balanced procedure within each stage, so the unpaired U remains calibrated; heterogeneity between stages can only make it conservative. A no-op simulation guards against type-I inflation from data-dependent sizing. Above 50 layouts per arm the U test uses a normal approximation, which can be slightly anti-conservative in the extreme tail near p = 0.0002.

**Low power.** Noether's normal approximation now uses an empirical effect size: AUC = P(r_j + ln(1.05) > r_i), over distinct ordered residual pairs with half credit for ties. Estimated power is Phi((AUC - 1/2) * sqrt(12*n1*n2/(n1+n2+1)) - z(1 - alpha/(2m))). The reported required K is the smallest per-arm count reaching 80%. Extension plans size to 90% estimated power, capped by `-K`, to leave a safety margin for dispersion estimates that rise after new layouts; the stopping and reporting threshold remains 80%, within the same three-stage and time limits. The report shows each benchmark's actual K and power; the `spread` column still describes the base arm's robust relative standard deviation (1.4826 x MAD).

The previous MAD-based normal effect model missed tight floors with long right tails and discrete layout clusters. Evidence E1 from PR #934 compares Monte Carlo of the actual U test at alpha/m = 0.01/50 for a lone +5% slowdown:

| distribution | K | Monte Carlo | MAD-Noether (previous) | empirical-AUC Noether |
|---|---:|---:|---:|---:|
| 75% N(0,0.7%) + 25% U(+4%,+25%) | 20 | 0.39 | 1.00 | 0.33 |
| same | 40 | 0.87 | 1.00 | 0.83 |
| two clusters 0 / +8%, 50/50 | 20 | 0.16 | 1.00 | 0.16 |
| same | 60 | 0.88 | 1.00 | 0.84 |
| uniform +-4% | 20 | 0.99 | 0.90 | 0.80 |
| uniform +-6% | 20 | 0.48 | 0.40 | 0.42 |

On these distributions the empirical estimate is conservative by up to 0.19 and optimistic by at most 0.06. The Low power section lists only benchmarks still below 80%, their K, estimated power, slowdown caught 80% of the time, and a reason: the layout cap, adaptive layouts off, exhausted time budget, still short after the last extension stage, or an estimate that rose after the final extension. It always reports how many benchmarks were extended. Instructions/op, allocs/op and the stage-1 suite geomean still guard these benchmarks; a slowdown affecting several benchmarks lowers the Benjamini-Hochberg bar. When even complete separation cannot reach alpha/m, the report also keeps the reach warning.

**A/A' control.** Each run also measures the base revision under a second, disjoint set of layout seeds, interleaved with the A/B arms, so the control sees the same layout variance as the A/B comparison. The previous identical-binary A/A could not see it. If more than 10% of benchmarks move by more than 3% in that A/A' comparison, the run is too noisy: the job re-links every arm with a fresh, disjoint block of seeds (links only; compiles are cached) and re-measures once, and a second noisy result is **inconclusive**, which is neutral, not a failure. The report also counts how many benchmarks the time rule would have flagged in the A/A' comparison; that should almost always be 0.

**Other dispatch modes** of `perf-gate.yml`: `matrix` runs the same interleaved A/B over the whole benchmark matrix (`scripts/perf/matrix-suite.sh`, about 900 benchmarks, 5 rounds of 100ms by default, roughly an hour; base = head gives an A/A of the whole matrix) without the A/A arm and instruction counts. It is a report, not a gate: its job is named "Matrix A/B (report only)" and its heading says so. `profile` records pprof profiles, `perf stat` counters where the PMU allows, and cachegrind cache simulation (32 KiB 8-way L1i, the Zen 3/4/5 geometry) of the gap queries: instructions, L1i and L1d misses per operation and the functions with the most L1i misses.

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
task bench:profile                     # pprof at -cpu 1 / GOGC=off (with GOMEMLIMIT) / -cpu 4 for the gap queries
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
- `scripts/perf/lib.sh`: shared settings (the `GOMEMLIMIT` default, the runner CPU model)
- `scripts/perf/baseline/`: baseline recorder and checker
- `.github/workflows/perf-gate.yml`: CI gate; `.github/workflows/bench-compare.yml`: competitor runs
- `benchmarks/compare/README.md`: competitor harness
