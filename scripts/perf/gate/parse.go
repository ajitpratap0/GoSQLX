// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Run holds every sample of one arm: benchmark name -> unit -> values, plus
// the order in which names first appeared. Layouts runs parallel to Values:
// Layouts[name][unit][i] is the code layout (the -randlayout seed the binary
// was linked with) that produced Values[name][unit][i], or "" when the input
// carries no "layout:" lines.
type Run struct {
	Names     []string
	Values    map[string]map[string][]float64
	Layouts   map[string]map[string][]string
	Line      map[string]int
	LineFirst map[int]string
}

func newRun() *Run {
	return &Run{Values: make(map[string]map[string][]float64), Layouts: make(map[string]map[string][]string), Line: make(map[string]int), LineFirst: make(map[int]string)}
}

// Get returns the samples of name in unit (nil if absent).
func (r *Run) Get(name, unit string) []float64 {
	if r == nil {
		return nil
	}
	return r.Values[name][unit]
}

// ByLayout groups the samples of name in unit by code layout: the layouts in
// the order they first appear and, for each, its samples. A run without
// layout labels yields one group labelled "".
func (r *Run) ByLayout(name, unit string) (labels []string, groups [][]float64) {
	if r == nil {
		return nil, nil
	}
	vals := r.Values[name][unit]
	labs := r.Layouts[name][unit]
	index := make(map[string]int)
	for i, v := range vals {
		l := ""
		if i < len(labs) {
			l = labs[i]
		}
		k, ok := index[l]
		if !ok {
			k = len(labels)
			index[l] = k
			labels = append(labels, l)
			groups = append(groups, nil)
		}
		groups[k] = append(groups[k], v)
	}
	return labels, groups
}

func (r *Run) add(name, unit, layout string, v float64) {
	units, ok := r.Values[name]
	if !ok {
		units = make(map[string][]float64)
		r.Values[name] = units
		r.Layouts[name] = make(map[string][]string)
		r.Names = append(r.Names, name)
	}
	units[unit] = append(units[unit], v)
	r.Layouts[name][unit] = append(r.Layouts[name][unit], layout)
}

// procSuffix is the "-<GOMAXPROCS>" suffix the testing package appends to a
// benchmark name when GOMAXPROCS is not 1.
var procSuffix = regexp.MustCompile(`-\d+$`)

// layoutKey is the benchmark-format configuration key ab.sh writes before the
// output of each binary: "layout: <seed>" (benchfmt "key: value" line). It
// holds for every result line that follows until the next layout line.
const layoutKey = "layout:"

// lineKey identifies the suite line whose binary produced subsequent results.
const lineKey = "suite-line:"

// parseBench reads Go benchmark output (the format of `go test -bench`):
// lines of "BenchmarkName[-procs] <iterations> <value> <unit> ...", labelled
// with the most recent "layout: <seed>" line. Every other line (goos:, pkg:,
// PASS, logs) is ignored.
func parseBench(r io.Reader) (*Run, error) {
	run := newRun()
	layout := ""
	suiteLine, hasLine := 0, false
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
		if len(f) >= 1 && f[0] == layoutKey {
			layout = strings.Join(f[1:], " ")
			continue
		}
		if len(f) >= 1 && f[0] == lineKey {
			if len(f) != 2 {
				return nil, fmt.Errorf("line %d: bad suite-line label: %q", line, sc.Text())
			}
			value, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: bad suite-line %q: %w", line, f[1], err)
			}
			suiteLine, hasLine = value, true
			continue
		}
		if len(f) < 4 || !strings.HasPrefix(f[0], "Benchmark") {
			continue
		}
		if _, err := strconv.ParseInt(f[1], 10, 64); err != nil {
			continue // a log line that happens to start with "Benchmark"
		}
		if len(f)%2 != 0 {
			return nil, fmt.Errorf("line %d: odd number of value/unit fields: %q", line, sc.Text())
		}
		name := procSuffix.ReplaceAllString(f[0], "")
		if hasLine {
			if _, ok := run.Line[name]; !ok {
				run.Line[name] = suiteLine
			}
			if _, ok := run.LineFirst[suiteLine]; !ok {
				run.LineFirst[suiteLine] = name
			}
		}
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad value %q: %w", line, f[i], err)
			}
			run.add(name, f[i+1], layout, v)
		}
	}
	return run, sc.Err()
}

// mergeRuns appends b's samples and previously unseen names to a fresh Run,
// preserving layout labels and preferring a's suite-line context.
func mergeRuns(a, b *Run) *Run {
	if b == nil {
		return a
	}
	out := newRun()
	for _, run := range []*Run{a, b} {
		if run == nil {
			continue
		}
		for _, name := range run.Names {
			for unit, values := range run.Values[name] {
				labels := run.Layouts[name][unit]
				for i, value := range values {
					label := ""
					if i < len(labels) {
						label = labels[i]
					}
					out.add(name, unit, label, value)
				}
			}
		}
		for name, line := range run.Line {
			if _, ok := out.Line[name]; !ok {
				out.Line[name] = line
			}
		}
		for line, name := range run.LineFirst {
			if _, ok := out.LineFirst[line]; !ok {
				out.LineFirst[line] = name
			}
		}
	}
	return out
}

func parseFile(path string) (*Run, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	run, err := parseBench(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return run, nil
}
