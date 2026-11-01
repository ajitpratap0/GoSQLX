// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"strings"
)

// Units the gate reads from benchmark output.
const (
	unitTime   = "ns/op"
	unitBytes  = "B/op"
	unitAllocs = "allocs/op"
	unitIr     = "instructions/op"
)

// Verdict is the gate outcome.
type Verdict string

const (
	// Pass: nothing regressed.
	Pass Verdict = "pass"
	// Regression: a gated metric regressed past its threshold.
	Regression Verdict = "regression"
	// Noisy: the A/A control was too noisy to trust the timings; the caller
	// should measure again once.
	Noisy Verdict = "noisy"
	// Inconclusive: still noisy after the re-run. Neutral, never a failure.
	Inconclusive Verdict = "inconclusive"
)

// Config holds the thresholds of PLAN section 2.6. Percentages are in percent.
type Config struct {
	Alpha            float64 // significance level for time, B/op and allocs/op
	TimePct          float64 // per-benchmark time regression threshold
	GeomeanPct       float64 // time geomean regression threshold
	BytesPct         float64 // B/op regression threshold
	IrPct            float64 // instructions/op regression threshold
	AADeltaPct       float64 // an A/A benchmark is noisy when |delta| exceeds this
	AANoisyFraction  float64 // the A/A run is noisy when more than this % of benchmarks are
	FinalAttempt     bool    // a noisy A/A is now inconclusive instead of noisy
	MinSamplesForSig int     // below this many samples per arm the p-value is not used
}

// DefaultConfig is the configuration CI uses.
func DefaultConfig() Config {
	return Config{
		Alpha:            0.01,
		TimePct:          3,
		GeomeanPct:       1.5,
		BytesPct:         2,
		IrPct:            1.5,
		AADeltaPct:       3,
		AANoisyFraction:  10,
		MinSamplesForSig: 3,
	}
}

// Inputs are the parsed arms. Base, Head and (optionally) AA are the primary
// GOGC=off -cpu 1 runs; AA is a second, interleaved run of the base binary.
// SecBase/SecHead are the default-GC -cpu 1 runs (informational). IrBase and
// IrHead hold instructions/op from cmd/perfdriver.
type Inputs struct {
	Base, Head, AA   *Run
	SecBase, SecHead *Run
	IrBase, IrHead   *Run
}

// Cmp compares one metric of one benchmark between two arms.
type Cmp struct {
	OK         bool    // both arms have samples
	Base, Head float64 // medians
	DeltaPct   float64 // (Head/Base - 1) * 100
	P          float64 // Mann-Whitney two-sided p-value
	Separated  bool    // every head sample is above every base sample, or every one below
	NBase      int
	NHead      int
}

func compare(base, head []float64) Cmp {
	if len(base) == 0 || len(head) == 0 {
		return Cmp{}
	}
	c := Cmp{OK: true, Base: median(base), Head: median(head), NBase: len(base), NHead: len(head)}
	switch {
	case c.Base != 0:
		c.DeltaPct = (c.Head/c.Base - 1) * 100
	case c.Head != 0:
		c.DeltaPct = math.Inf(1)
	}
	c.P = mannWhitney(base, head)
	bLo, bHi := minMax(base)
	hLo, hHi := minMax(head)
	c.Separated = hLo > bHi || hHi < bLo
	return c
}

// significant reports whether the change is unlikely to be noise: p below
// alpha. For a deterministic metric (allocs/op, B/op) complete separation of
// the two arms also counts, so that a run with too few rounds for the test to
// reach alpha still catches an extra allocation; timings never get that
// shortcut.
func (c Cmp) significant(cfg Config, deterministic bool) bool {
	if !c.OK {
		return false
	}
	if c.NBase >= cfg.MinSamplesForSig && c.NHead >= cfg.MinSamplesForSig && c.P < cfg.Alpha {
		return true
	}
	return deterministic && c.Separated
}

// Row is the per-benchmark result.
type Row struct {
	Name    string
	Time    Cmp
	AA      Cmp // base vs base2, time
	Bytes   Cmp
	Allocs  Cmp
	Sec     Cmp // secondary (default GC) time
	Status  []string
	Regress bool
}

// IrRow is the instruction-count result of one perfdriver case.
type IrRow struct {
	Name    string
	Cmp     Cmp
	Regress bool
}

// Result is the full gate outcome.
type Result struct {
	Verdict        Verdict
	Reasons        []string
	Rows           []Row
	IrRows         []IrRow
	Geomean        float64 // head/base time geomean ratio, NaN if unknown
	GeomeanP       float64 // p-value of the per-round suite geomeans, NaN if unknown
	AAGeomean      float64
	SecGeomean     float64
	AANoisy        int // A/A benchmarks with |delta| > AADeltaPct
	AACompared     int
	TimeRegressed  int
	HardRegressed  int
	MissingInHead  []string
	NewInHead      []string
	HasAA, HasSec  bool
	HasIr          bool
	TimingDisabled bool // A/A noisy: timing results are not trusted
}

// Evaluate applies the gate rules.
//
// Hard metrics (allocs/op, B/op, instructions/op) count even when the A/A
// control is noisy, because GC-free allocation counts and instruction counts
// do not depend on machine noise. Timing regressions count only when the A/A
// control is quiet.
func Evaluate(in Inputs, cfg Config) Result {
	res := Result{
		Geomean:    math.NaN(),
		GeomeanP:   math.NaN(),
		AAGeomean:  math.NaN(),
		SecGeomean: math.NaN(),
		HasAA:      in.AA != nil,
		HasSec:     in.SecBase != nil && in.SecHead != nil,
		HasIr:      in.IrBase != nil && in.IrHead != nil,
	}
	var ratios, aaRatios, secRatios []float64
	headSeen := make(map[string]bool)
	if in.Head != nil {
		for _, n := range in.Head.Names {
			headSeen[n] = true
		}
	}
	if in.Base != nil {
		for _, name := range in.Base.Names {
			if !headSeen[name] {
				res.MissingInHead = append(res.MissingInHead, name)
				continue
			}
			row := Row{Name: name}
			row.Time = compare(in.Base.Get(name, unitTime), in.Head.Get(name, unitTime))
			row.Bytes = compare(in.Base.Get(name, unitBytes), in.Head.Get(name, unitBytes))
			row.Allocs = compare(in.Base.Get(name, unitAllocs), in.Head.Get(name, unitAllocs))
			if in.AA != nil {
				row.AA = compare(in.Base.Get(name, unitTime), in.AA.Get(name, unitTime))
			}
			if res.HasSec {
				row.Sec = compare(in.SecBase.Get(name, unitTime), in.SecHead.Get(name, unitTime))
			}
			if row.Time.OK && row.Time.Base > 0 && row.Time.Head > 0 {
				ratios = append(ratios, row.Time.Head/row.Time.Base)
			}
			if row.AA.OK && row.AA.Base > 0 && row.AA.Head > 0 {
				aaRatios = append(aaRatios, row.AA.Head/row.AA.Base)
				res.AACompared++
				if math.Abs(row.AA.DeltaPct) > cfg.AADeltaPct {
					res.AANoisy++
				}
			}
			if row.Sec.OK && row.Sec.Base > 0 && row.Sec.Head > 0 {
				secRatios = append(secRatios, row.Sec.Head/row.Sec.Base)
			}
			res.Rows = append(res.Rows, row)
		}
	}
	if in.Head != nil {
		for _, name := range in.Head.Names {
			if in.Base == nil || in.Base.Values[name] == nil {
				res.NewInHead = append(res.NewInHead, name)
			}
		}
	}
	res.Geomean = geomean(ratios)
	if in.Base != nil && in.Head != nil {
		res.GeomeanP = roundGeomeanP(in.Base, in.Head, res.Rows)
	}
	res.AAGeomean = geomean(aaRatios)
	res.SecGeomean = geomean(secRatios)

	aaNoisy := res.AACompared > 0 &&
		float64(res.AANoisy)*100/float64(res.AACompared) > cfg.AANoisyFraction
	res.TimingDisabled = aaNoisy

	var slower, faster, moreAllocs, moreBytes int
	for i := range res.Rows {
		r := &res.Rows[i]
		if r.Time.significant(cfg, false) {
			switch {
			case r.Time.DeltaPct >= cfg.TimePct:
				r.Status = append(r.Status, "slower")
				slower++
				if !aaNoisy {
					r.Regress = true
					res.TimeRegressed++
				}
			case r.Time.DeltaPct <= -cfg.TimePct:
				r.Status = append(r.Status, "faster")
				faster++
			}
		}
		if r.Allocs.Head > r.Allocs.Base && r.Allocs.significant(cfg, true) {
			r.Status = append(r.Status, "+allocs")
			r.Regress = true
			moreAllocs++
		} else if r.Allocs.Head < r.Allocs.Base && r.Allocs.significant(cfg, true) {
			r.Status = append(r.Status, "-allocs")
		}
		if exceeds(r.Bytes.DeltaPct, cfg.BytesPct) && r.Bytes.significant(cfg, true) {
			r.Status = append(r.Status, "+B/op")
			r.Regress = true
			moreBytes++
		}
		if len(r.Status) == 0 {
			r.Status = append(r.Status, "ok")
		}
	}

	var moreIr int
	if res.HasIr {
		for _, name := range in.IrBase.Names {
			c := compare(in.IrBase.Get(name, unitIr), in.IrHead.Get(name, unitIr))
			if !c.OK {
				continue
			}
			row := IrRow{Name: name, Cmp: c, Regress: exceeds(c.DeltaPct, cfg.IrPct)}
			if row.Regress {
				moreIr++
			}
			res.IrRows = append(res.IrRows, row)
		}
	}
	res.HardRegressed = moreAllocs + moreBytes + moreIr

	// The geomean is a regression only when the per-round suite geomeans
	// of the two arms also differ significantly; one noisy benchmark in a
	// short run must not trip it.
	geoRegressed := !aaNoisy && !math.IsNaN(res.Geomean) && (res.Geomean-1)*100 >= cfg.GeomeanPct &&
		!math.IsNaN(res.GeomeanP) && res.GeomeanP < cfg.Alpha

	if moreAllocs > 0 {
		res.Reasons = append(res.Reasons, fmt.Sprintf("allocs/op increased in %d benchmark(s)", moreAllocs))
	}
	if moreBytes > 0 {
		res.Reasons = append(res.Reasons, fmt.Sprintf("B/op rose more than %.3g%% in %d benchmark(s)", cfg.BytesPct, moreBytes))
	}
	if moreIr > 0 {
		res.Reasons = append(res.Reasons, fmt.Sprintf("instructions/op rose more than %.3g%% in %d case(s)", cfg.IrPct, moreIr))
	}
	if aaNoisy {
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"A/A control noisy: %d of %d benchmarks moved more than %.3g%% between two runs of the same binary; timings are not judged",
			res.AANoisy, res.AACompared, cfg.AADeltaPct))
		if slower > 0 {
			res.Reasons = append(res.Reasons, fmt.Sprintf("%d benchmark(s) look slower, but the run is too noisy to tell", slower))
		}
	} else {
		if res.TimeRegressed > 0 {
			res.Reasons = append(res.Reasons, fmt.Sprintf("%d benchmark(s) slower by %.3g%% or more at p < %.3g", res.TimeRegressed, cfg.TimePct, cfg.Alpha))
		}
		if geoRegressed {
			res.Reasons = append(res.Reasons, fmt.Sprintf("time geomean %s at p = %.2g (threshold +%.3g%%)", pct((res.Geomean-1)*100), res.GeomeanP, cfg.GeomeanPct))
		}
	}
	if faster > 0 && !aaNoisy {
		res.Reasons = append(res.Reasons, fmt.Sprintf("%d benchmark(s) faster by %.3g%% or more", faster, cfg.TimePct))
	}

	switch {
	case res.HardRegressed > 0:
		res.Verdict = Regression
	case aaNoisy && cfg.FinalAttempt:
		res.Verdict = Inconclusive
	case aaNoisy:
		res.Verdict = Noisy
	case res.TimeRegressed > 0 || geoRegressed:
		res.Verdict = Regression
	default:
		res.Verdict = Pass
	}
	return res
}

// roundGeomeanP compares the suite geomean of each round between the arms.
// Sample i of every benchmark comes from round i (ab.sh runs each benchmark
// once per arm per round), so when every compared benchmark has the same
// sample count the i-th suite geomean of an arm is a valid per-round sample.
// It returns NaN when the counts differ.
func roundGeomeanP(base, head *Run, rows []Row) float64 {
	n := -1
	var names []string
	for _, r := range rows {
		if !r.Time.OK {
			continue
		}
		if n == -1 {
			n = r.Time.NBase
		}
		if r.Time.NBase != n || r.Time.NHead != n {
			return math.NaN()
		}
		names = append(names, r.Name)
	}
	if n < 1 || len(names) == 0 {
		return math.NaN()
	}
	perRound := func(run *Run) []float64 {
		out := make([]float64, n)
		for i := 0; i < n; i++ {
			var s float64
			for _, name := range names {
				s += math.Log(run.Get(name, unitTime)[i])
			}
			out[i] = math.Exp(s / float64(len(names)))
		}
		return out
	}
	return mannWhitney(perRound(base), perRound(head))
}

// exceeds reports d > limit, treating values within rounding error of the
// limit as equal: 400 -> 408 B/op is exactly +2%, not "more than 2%".
func exceeds(d, limit float64) bool { return d > limit+1e-9 }

func pct(d float64) string {
	if math.IsNaN(d) {
		return "n/a"
	}
	if math.IsInf(d, 0) {
		return "+inf%"
	}
	return fmt.Sprintf("%+.2f%%", d)
}

func pval(c Cmp) string {
	if !c.OK {
		return ""
	}
	if c.P < 0.001 {
		return "<0.001"
	}
	return fmt.Sprintf("%.3f", c.P)
}

// Meta is free-form context printed above the tables.
type Meta struct {
	BaseRef, HeadRef string
	Mode             string // "shadow" or "enforce"
	Accepted         bool   // perf-regression-accepted label present
	Settings         string // one line: rounds, benchtime, pinning
	Env              string // lscpu / go version block
	Benchstat        string // raw benchstat output
	IrNote           string // why instruction counts were skipped, if they were
}

// ReportMarker identifies the sticky PR comment.
const ReportMarker = "<!-- perf-gate-report -->"

// Markdown renders the result for the job summary and the PR comment. Only
// relative deltas are shown; absolute timings live in the raw artifacts.
func Markdown(res Result, cfg Config, meta Meta) string {
	var b strings.Builder
	b.WriteString(ReportMarker + "\n")
	verdict := strings.ToUpper(string(res.Verdict))
	mode := "shadow mode: report only, this check never fails"
	if meta.Mode == "enforce" {
		mode = "enforced"
		if meta.Accepted && res.Verdict == Regression {
			mode = "enforced, regression accepted by the perf-regression-accepted label"
		}
	}
	fmt.Fprintf(&b, "## Perf gate: %s (%s)\n\n", verdict, mode)
	if meta.BaseRef != "" || meta.HeadRef != "" {
		fmt.Fprintf(&b, "Base `%s`, head `%s`.", meta.BaseRef, meta.HeadRef)
		if meta.Settings != "" {
			fmt.Fprintf(&b, " %s", meta.Settings)
		}
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b, "Runner CPU: `%s`. Base and head ran interleaved in this job, so the tables show their ratios only; "+
		"absolute timings (raw files in the artifact) hold for this CPU and this job alone and are never compared across jobs.\n\n", runnerCPU(meta.Env))
	if len(res.Reasons) > 0 {
		for _, r := range res.Reasons {
			fmt.Fprintf(&b, "- %s\n", r)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("- no gated metric moved past its threshold\n\n")
	}
	fmt.Fprintf(&b, "Rules: time regresses at >= +%.3g%% with p < %.3g (Mann-Whitney U), or a suite geomean >= +%.3g%% (per-round geomeans, same test); "+
		"allocs/op must not increase; B/op must not rise more than %.3g%%; instructions/op must not rise more than %.3g%%. "+
		"An A/A control with more than %.3g%% of benchmarks moving over %.3g%% is noisy: re-run once, then inconclusive (neutral).\n\n",
		cfg.TimePct, cfg.Alpha, cfg.GeomeanPct, cfg.BytesPct, cfg.IrPct, cfg.AANoisyFraction, cfg.AADeltaPct)

	b.WriteString("### Gated suite (GOGC=off, GOMAXPROCS=1)\n\n")
	b.WriteString("| benchmark | time | p | A/A | B/op | allocs/op | status |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---|\n")
	for _, r := range res.Rows {
		aa := ""
		if r.AA.OK {
			aa = pct(r.AA.DeltaPct)
		}
		bytes := ""
		if r.Bytes.OK {
			bytes = pct(r.Bytes.DeltaPct)
		}
		allocs := ""
		if r.Allocs.OK {
			allocs = fmt.Sprintf("%g → %g", r.Allocs.Base, r.Allocs.Head)
		}
		status := strings.Join(r.Status, ", ")
		if r.Regress {
			status = "**" + status + "**"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			strings.TrimPrefix(r.Name, "Benchmark"), pct(r.Time.DeltaPct), pval(r.Time), aa, bytes, allocs, status)
	}
	geoP := ""
	if !math.IsNaN(res.GeomeanP) {
		geoP = pval(Cmp{OK: true, P: res.GeomeanP})
	}
	fmt.Fprintf(&b, "| **geomean** | %s | %s | %s | | | |\n\n", pct((res.Geomean-1)*100), geoP, pct((res.AAGeomean-1)*100))
	if res.HasAA {
		fmt.Fprintf(&b, "A/A control: %d of %d benchmarks moved more than %.3g%%.\n\n", res.AANoisy, res.AACompared, cfg.AADeltaPct)
	} else {
		b.WriteString("A/A control not run: timings were not checked against machine noise.\n\n")
	}
	if len(res.MissingInHead) > 0 {
		fmt.Fprintf(&b, "Missing in head (not judged): %s\n\n", codeList(res.MissingInHead))
	}
	if len(res.NewInHead) > 0 {
		fmt.Fprintf(&b, "New in head, no base to compare (not judged): %s\n\n", codeList(res.NewInHead))
	}

	b.WriteString("### Instructions per operation (cmd/perfdriver)\n\n")
	if res.HasIr && len(res.IrRows) > 0 {
		b.WriteString("| case | instructions/op | status |\n|---|---:|---|\n")
		for _, r := range res.IrRows {
			st := "ok"
			if r.Regress {
				st = "**+instructions**"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", strings.TrimPrefix(r.Name, "BenchmarkPerfdriver/"), pct(r.Cmp.DeltaPct), st)
		}
		b.WriteString("\n")
	} else {
		note := meta.IrNote
		if note == "" {
			note = "not measured"
		}
		fmt.Fprintf(&b, "Skipped: %s.\n\n", note)
	}

	if res.HasSec {
		b.WriteString("<details><summary>Secondary metric: default GC, GOMAXPROCS=1 (informational)</summary>\n\n")
		b.WriteString("| benchmark | time | p |\n|---|---:|---:|\n")
		for _, r := range res.Rows {
			if r.Sec.OK {
				fmt.Fprintf(&b, "| `%s` | %s | %s |\n", strings.TrimPrefix(r.Name, "Benchmark"), pct(r.Sec.DeltaPct), pval(r.Sec))
			}
		}
		fmt.Fprintf(&b, "| **geomean** | %s | |\n\n</details>\n\n", pct((res.SecGeomean-1)*100))
	}
	if meta.Env != "" {
		fmt.Fprintf(&b, "<details><summary>Environment</summary>\n\n```\n%s\n```\n\n</details>\n\n", strings.TrimSpace(meta.Env))
	}
	if meta.Benchstat != "" {
		fmt.Fprintf(&b, "<details><summary>benchstat (primary metric)</summary>\n\n```\n%s\n```\n\n</details>\n", strings.TrimSpace(meta.Benchstat))
	}
	return b.String()
}

// runnerCPU extracts the CPU model from the environment block: the
// "cpu model:" line scripts/perf/lib.sh writes, else lscpu's "Model name:",
// else "unknown".
func runnerCPU(env string) string {
	for _, prefix := range []string{"cpu model:", "Model name:"} {
		for _, line := range strings.Split(env, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
				if v = strings.TrimSpace(v); v != "" {
					return v
				}
			}
		}
	}
	return "unknown"
}

func codeList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = "`" + strings.TrimPrefix(n, "Benchmark") + "`"
	}
	return strings.Join(q, ", ")
}
