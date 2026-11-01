// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Command baseline records and checks the per-architecture benchmark baselines
// in benchmarks/baselines/<goarch>.json (PLAN section 2.7).
//
// A baseline stores ns/op (trend only, never gated), B/op and allocs/op for
// every benchmark of the gated suite (scripts/perf/gate-suite.txt). The check
// fails when allocs/op rises or B/op rises by more than 2 percent. Time is
// judged by the interleaved A/B gate (scripts/perf/ab.sh), not here.
//
// Usage:
//
//	go run ./scripts/perf/baseline -update            # re-measure and rewrite the file
//	go run ./scripts/perf/baseline                    # re-measure and check
//	go run ./scripts/perf/baseline -input out.txt     # check recorded `go test -bench -benchmem` output
//	go run ./scripts/perf/baseline -input out.txt -update
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const fileComment = "ns_per_op is trend-only. bytes_per_op and allocs_per_op are gated by scripts/perf/baseline " +
	"(allocs/op must not rise, B/op may rise at most 2 percent). Measured with GOGC=off, -cpu 1, medians. " +
	"Regenerate with: task bench:baseline:update"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "baseline:", err)
		os.Exit(exitCode(err))
	}
}

type usageError struct{ error }

func exitCode(err error) int {
	if _, ok := err.(usageError); ok {
		return 2
	}
	return 1
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	update := fs.Bool("update", false, "rewrite the baseline file from a fresh measurement instead of checking")
	dir := fs.String("dir", "benchmarks/baselines", "directory holding <goarch>.json")
	arch := fs.String("arch", runtime.GOARCH, "architecture whose baseline to use")
	input := fs.String("input", "", "read `go test -bench -benchmem` output from this file instead of running the suite")
	suite := fs.String("suite", "scripts/perf/gate-suite.txt", "gated suite file")
	benchtime := fs.String("benchtime", "200ms", "-benchtime of each benchmark")
	count := fs.Int("count", 5, "samples per benchmark (the median is recorded)")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	if *count < 1 {
		return usageError{fmt.Errorf("-count must be positive")}
	}
	path := filepath.Join(*dir, *arch+".json")

	var raw []byte
	if *input != "" {
		b, err := os.ReadFile(*input)
		if err != nil {
			return err
		}
		raw = b
	} else {
		if *arch != runtime.GOARCH {
			return usageError{fmt.Errorf("cannot measure %s on %s; use -input", *arch, runtime.GOARCH)}
		}
		b, err := measure(*suite, *benchtime, *count, stderr)
		if err != nil {
			return err
		}
		raw = b
	}
	if *input != "" {
		// A recorded run may come from another machine (CI artifacts): its
		// goarch header must match the baseline it is checked against or
		// written into.
		for _, g := range Goarchs(bytes.NewReader(raw)) {
			if g != *arch {
				return fmt.Errorf("%s reports goarch %q but -arch is %q", *input, g, *arch)
			}
		}
	}
	measured, err := Parse(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if len(measured) == 0 {
		return fmt.Errorf("no benchmarks with B/op and allocs/op found (was -benchmem set?)")
	}

	if *update {
		f := File{Schema: SchemaVersion, Arch: *arch, Comment: fileComment, Benchmarks: measured,
			Updated: time.Now().UTC().Format("2006-01-02"), GoVersion: runtime.Version()}
		out, err := f.Marshal()
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "wrote %s (%d benchmarks)\n", path, len(measured))
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read baseline: %w (create it with -update)", err)
	}
	base, err := ParseFile(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(base.Benchmarks) == 0 {
		return fmt.Errorf("%s has no benchmarks yet; record it on %s hardware with -update", path, *arch)
	}
	if base.GoVersion != "" && !SameGoMinor(base.GoVersion, runtime.Version()) {
		fmt.Fprintf(stdout, "warning: baseline recorded with %s, running %s; allocs/op and B/op can shift between Go minors, re-record with the pinned toolchain if this fails\n",
			base.GoVersion, runtime.Version())
	}
	rep := Check(base, measured)
	for _, s := range rep.TimeDrift {
		fmt.Fprintln(stdout, "note (ns/op is trend-only):", s)
	}
	for _, s := range rep.New {
		fmt.Fprintln(stdout, "note: not in the baseline:", s)
	}
	for _, s := range rep.Missing {
		fmt.Fprintln(stdout, "note: not measured:", s)
	}
	for _, v := range rep.Violations {
		fmt.Fprintln(stdout, "REGRESSION:", v)
	}
	if err := rep.Verdict(*input == ""); err != nil {
		return fmt.Errorf("%w (%s)", err, path)
	}
	fmt.Fprintf(stdout, "ok: %d benchmarks within %s\n", rep.Compared, path)
	return nil
}

// measure runs every line of the suite file and returns the concatenated
// `go test` output.
func measure(suite, benchtime string, count int, log io.Writer) ([]byte, error) {
	f, err := os.Open(suite)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var all bytes.Buffer
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad suite line %q", line)
		}
		fmt.Fprintf(log, "baseline: %s %s\n", parts[0], parts[1])
		cmd := exec.Command("go", "test", "-run", "^$", "-bench", parts[1], "-benchmem",
			"-benchtime", benchtime, "-count", fmt.Sprint(count), "-cpu", "1", parts[0])
		cmd.Env = append(os.Environ(), "GOGC=off")
		cmd.Stderr = log
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("go test %s: %w", parts[0], err)
		}
		all.Write(out)
	}
	return all.Bytes(), sc.Err()
}
