// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Command gate judges an interleaved A/B benchmark run (scripts/perf/ab.sh)
// against the perf-gate rules of the performance plan (section 2.6):
//
//   - time (GOGC=off, GOMAXPROCS=1): a benchmark regresses at >= +3% with
//     p < 0.01 (Mann-Whitney U), or the geomean regresses by >= 1.5%;
//   - allocs/op must not increase; B/op must not rise more than 2%;
//   - instructions/op (cmd/perfdriver) must not rise more than 1.5%;
//   - an A/A control (a second, interleaved run of the base binary) where more
//     than 10% of benchmarks move over 3% is noisy: the caller re-runs once
//     (exit status "noisy"), and a second noisy run is inconclusive, which is
//     neutral, not a failure.
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
		aaPath      = fs.String("aa", "", "A/A control: a second run of the base binary")
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
	)
	fs.Float64Var(&cfg.Alpha, "alpha", cfg.Alpha, "significance level")
	fs.Float64Var(&cfg.TimePct, "time-pct", cfg.TimePct, "per-benchmark time threshold, %")
	fs.Float64Var(&cfg.GeomeanPct, "geomean-pct", cfg.GeomeanPct, "geomean time threshold, %")
	fs.Float64Var(&cfg.BytesPct, "bytes-pct", cfg.BytesPct, "B/op threshold, %")
	fs.Float64Var(&cfg.IrPct, "ir-pct", cfg.IrPct, "instructions/op threshold, %")
	fs.Float64Var(&cfg.AADeltaPct, "aa-delta-pct", cfg.AADeltaPct, "A/A per-benchmark noise threshold, %")
	fs.Float64Var(&cfg.AANoisyFraction, "aa-noisy-pct", cfg.AANoisyFraction, "A/A noisy when more than this % of benchmarks are noisy")
	fs.BoolVar(&cfg.FinalAttempt, "final", false, "this is the re-run: a noisy A/A is inconclusive")
	if err := fs.Parse(args); err != nil {
		return 0, err
	}
	if fs.NArg() > 0 {
		return 0, fmt.Errorf("unexpected arguments: %v", fs.Args())
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

	var in Inputs
	for _, p := range []struct {
		dst  **Run
		path string
	}{
		{&in.Base, *basePath}, {&in.Head, *headPath}, {&in.AA, *aaPath},
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

	meta := Meta{BaseRef: *baseRef, HeadRef: *headRef, Settings: *settings, Accepted: *accepted, IrNote: *irNote, Mode: "shadow"}
	if *enforce {
		meta.Mode = "enforce"
	}
	var err error
	if meta.Env, err = readOptional(*envPath); err != nil {
		return 0, err
	}
	if meta.Benchstat, err = readOptional(*bstatPath); err != nil {
		return 0, err
	}

	res := Evaluate(in, cfg)
	md := Markdown(res, cfg, meta)
	if *mdPath == "" {
		fmt.Fprint(stdout, md)
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
