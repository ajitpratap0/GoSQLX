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
// the order in which names first appeared.
type Run struct {
	Names  []string
	Values map[string]map[string][]float64
}

func newRun() *Run { return &Run{Values: make(map[string]map[string][]float64)} }

// Get returns the samples of name in unit (nil if absent).
func (r *Run) Get(name, unit string) []float64 {
	if r == nil {
		return nil
	}
	return r.Values[name][unit]
}

func (r *Run) add(name, unit string, v float64) {
	units, ok := r.Values[name]
	if !ok {
		units = make(map[string][]float64)
		r.Values[name] = units
		r.Names = append(r.Names, name)
	}
	units[unit] = append(units[unit], v)
}

// procSuffix is the "-<GOMAXPROCS>" suffix the testing package appends to a
// benchmark name when GOMAXPROCS is not 1.
var procSuffix = regexp.MustCompile(`-\d+$`)

// parseBench reads Go benchmark output (the format of `go test -bench`):
// lines of "BenchmarkName[-procs] <iterations> <value> <unit> ...". Every
// other line (goos:, pkg:, PASS, logs) is ignored.
func parseBench(r io.Reader) (*Run, error) {
	run := newRun()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
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
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				return nil, fmt.Errorf("line %d: bad value %q: %w", line, f[i], err)
			}
			run.add(name, f[i+1], v)
		}
	}
	return run, sc.Err()
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
