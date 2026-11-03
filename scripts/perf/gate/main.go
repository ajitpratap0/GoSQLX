// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Command gate judges an interleaved A/B benchmark run (scripts/perf/ab.sh)
// against the perf-gate rules of the performance plan (section 2.6):
//
//   - time (GOGC=off, GOMAXPROCS=1): a benchmark regresses at >= +3% when
//     its Mann-Whitney U p-value survives Benjamini-Hochberg at a false
//     discovery rate of 0.01 over the suite, or the geomean regresses by
//     >= 1.5% at p < 0.01. When the inputs carry "layout: <seed>" lines
//     (ab.sh links K binaries per arm with -ldflags=-randlayout), the tests
//     run over the per-layout medians, so a regression must hold across code
//     layouts;
//   - allocs/op must not increase; B/op must not rise more than 2%;
//   - instructions/op (cmd/perfdriver) must not rise more than 1.5%;
//   - an A/A' control (the base revision under a disjoint set of layout
//     seeds, interleaved) where more than 10% of benchmarks move over 3% is
//     noisy: the caller re-runs once (exit status "noisy"), and a second noisy
//     run is inconclusive, which is neutral, not a failure.
//
// Adaptive planning estimates power from pooled within-arm layout residuals
// and sizes each benchmark for a lone +5% slowdown at alpha/m. Extension
// arms enter only the time comparison; all other rules use stage-1 data.
// With -plan PATH it writes an adaptive-layout TSV and exits without a report.
//
// It writes a Markdown report and a one-word status file (pass, regression,
// noisy or inconclusive). It exits 1 only with -enforce, on a regression,
// without -accepted; in shadow mode (the default) it exits 0 for any verdict.
//
// Usage:
//
//	go run ./scripts/perf/gate -base base.txt -head head.txt [-aa base2.txt] \
//	    [-sec-base gc-base.txt -sec-head gc-head.txt] [-ir-base ir-base.txt -ir-head ir-head.txt] \
//	    [-md report.md] [-status status.txt] [-final] [-enforce] [-accepted]
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	code, err := realMain(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func readOptional(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func realMain(args []string, stdout io.Writer) (int, error) {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	var (
		basePath    = fs.String("base", "", "primary base arm (Go benchmark output)")
		headPath    = fs.String("head", "", "primary head arm")
		baseExtPath = fs.String("base-ext", "", "additional primary base layouts")
		headExtPath = fs.String("head-ext", "", "additional primary head layouts")
		planPath    = fs.String("plan", "", "write the adaptive-layout plan here and exit")
		aaPath      = fs.String("aa", "", "A/A' control: the base revision under disjoint layout seeds")
		secBasePath = fs.String("sec-base", "", "secondary (default GC) base arm")
		secHeadPath = fs.String("sec-head", "", "secondary (default GC) head arm")
		irBasePath  = fs.String("ir-base", "", "instructions/op of the base arm")
		irHeadPath  = fs.String("ir-head", "", "instructions/op of the head arm")
		mdPath      = fs.String("md", "", "write the Markdown report here (default: stdout)")
		statusPath  = fs.String("status", "", "write the one-word verdict here")
		enforce     = fs.Bool("enforce", false, "exit 1 on a regression (default: shadow mode)")
		accepted    = fs.Bool("accepted", false, "the perf-regression-accepted label is present")
		baseRef     = fs.String("base-ref", "", "base commit, for the report")
		headRef     = fs.String("head-ref", "", "head commit, for the report")
		settings    = fs.String("settings", "", "one-line description of the run settings")
		envPath     = fs.String("env", "", "environment description file to embed")
		bstatPath   = fs.String("benchstat", "", "benchstat output file to embed")
		irNote      = fs.String("ir-note", "", "why instruction counts were not measured")
		title       = fs.String("title", "", "report heading (default \"Perf gate\")")
		reportOnly  = fs.Bool("report-only", false, "the run is a comparison, not a gate (heading says so); exclusive with -enforce")
	)
	fs.Float64Var(&cfg.Alpha, "alpha", cfg.Alpha, "significance level")
	fs.Float64Var(&cfg.TimePct, "time-pct", cfg.TimePct, "per-benchmark time threshold, %")
	fs.Float64Var(&cfg.GeomeanPct, "geomean-pct", cfg.GeomeanPct, "geomean time threshold, %")
	fs.Float64Var(&cfg.BytesPct, "bytes-pct", cfg.BytesPct, "B/op threshold, %")
	fs.Float64Var(&cfg.IrPct, "ir-pct", cfg.IrPct, "instructions/op threshold, %")
	fs.Float64Var(&cfg.AADeltaPct, "aa-delta-pct", cfg.AADeltaPct, "A/A per-benchmark noise threshold, %")
	fs.Float64Var(&cfg.AANoisyFraction, "aa-noisy-pct", cfg.AANoisyFraction, "A/A noisy when more than this % of benchmarks are noisy")
	fs.BoolVar(&cfg.FinalAttempt, "final", false, "this is the re-run: a noisy A/A is inconclusive")
	fs.IntVar(&cfg.ExtMax, "ext-max", cfg.ExtMax, "maximum adaptive layouts per arm (at least 2)")
	fs.StringVar(&cfg.ExtStatus, "ext-status", cfg.ExtStatus, "adaptive layout status: off, done, budget or stages")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() > 0 {
		return 0, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *reportOnly && *enforce {
		return 0, errors.New("-report-only and -enforce are exclusive")
	}
	if *basePath == "" || *headPath == "" {
		return 0, errors.New("-base and -head are required")
	}
	if (*secBasePath == "") != (*secHeadPath == "") {
		return 0, errors.New("-sec-base and -sec-head go together")
	}
	if (*irBasePath == "") != (*irHeadPath == "") {
		return 0, errors.New("-ir-base and -ir-head go together")
	}
	if (*baseExtPath == "") != (*headExtPath == "") {
		return 0, errors.New("-base-ext and -head-ext go together")
	}
	if cfg.ExtMax < 2 {
		return 0, errors.New("-ext-max must be at least 2")
	}
	switch cfg.ExtStatus {
	case "off", "done", "budget", "stages":
	default:
		return 0, errors.New("-ext-status must be off, done, budget or stages")
	}

	var in Inputs
	for _, p := range []struct {
		dst  **Run
		path string
	}{
		{&in.Base, *basePath}, {&in.Head, *headPath}, {&in.AA, *aaPath},
		{&in.BaseExt, *baseExtPath}, {&in.HeadExt, *headExtPath},
		{&in.SecBase, *secBasePath}, {&in.SecHead, *secHeadPath},
		{&in.IrBase, *irBasePath}, {&in.IrHead, *irHeadPath},
	} {
		r, err := parseFile(p.path)
		if err != nil {
			return 0, err
		}
		*p.dst = r
	}
	if len(in.Base.Names) == 0 || len(in.Head.Names) == 0 {
		return 0, errors.New("no benchmark results in -base or -head")
	}
	res := Evaluate(in, cfg)
	if *planPath != "" {
		var plan bytes.Buffer
		level := cfg.Alpha
		if res.TimeTests > 0 {
			level /= float64(res.TimeTests)
		}
		if err := WritePlan(&plan, Plan(res, cfg), mergeRuns(in.Base, in.BaseExt).LineFirst, level, res.TimeTests, cfg.ExtMax); err != nil {
			return 0, err
		}
		if err := os.WriteFile(*planPath, plan.Bytes(), 0o644); err != nil {
			return 0, err
		}
		return 0, nil
	}

	meta := Meta{BaseRef: *baseRef, HeadRef: *headRef, Settings: *settings, Accepted: *accepted, IrNote: *irNote, Mode: "shadow", Title: *title}
	switch {
	case *enforce:
		meta.Mode = "enforce"
	case *reportOnly:
		meta.Mode = "report"
	}
	var err error
	if meta.Env, err = readOptional(*envPath); err != nil {
		return 0, err
	}
	if meta.Benchstat, err = readOptional(*bstatPath); err != nil {
		return 0, err
	}

	md := Markdown(res, cfg, meta)
	if *mdPath == "" {
		if _, err := fmt.Fprint(stdout, md); err != nil {
			return 0, err
		}
	} else if err := os.WriteFile(*mdPath, []byte(md), 0o644); err != nil {
		return 0, err
	}
	if *statusPath != "" {
		if err := os.WriteFile(*statusPath, []byte(string(res.Verdict)+"\n"), 0o644); err != nil {
			return 0, err
		}
	}
	fmt.Fprintf(os.Stderr, "gate: verdict %s\n", res.Verdict)
	if *enforce && res.Verdict == Regression && !*accepted {
		return 1, nil
	}
	return 0, nil
}
