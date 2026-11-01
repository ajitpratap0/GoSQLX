// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion is the version of the baseline file format.
const SchemaVersion = 1

// BytesTolerance is the allowed relative rise in B/op (PLAN section 2.1).
const BytesTolerance = 0.02

// Entry is the recorded cost of one benchmark. NsPerOp is trend-only data
// (it is never gated); BytesPerOp and AllocsPerOp are the gated, deterministic
// metrics.
type Entry struct {
	NsPerOp     float64 `json:"ns_per_op"`
	BytesPerOp  float64 `json:"bytes_per_op"`
	AllocsPerOp float64 `json:"allocs_per_op"`
}

// File is the content of benchmarks/baselines/<goarch>.json.
type File struct {
	Schema     int              `json:"schema"`
	Arch       string           `json:"arch"`
	Comment    string           `json:"comment"`
	Updated    string           `json:"updated,omitempty"`
	GoVersion  string           `json:"go_version,omitempty"`
	Benchmarks map[string]Entry `json:"benchmarks"`
}

// Marshal renders f as stable, indented JSON (map keys are sorted by
// encoding/json), terminated by a newline.
func (f File) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParseFile decodes and validates a baseline file.
func ParseFile(data []byte) (File, error) {
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("decode baseline: %w", err)
	}
	if f.Schema != SchemaVersion {
		return File{}, fmt.Errorf("baseline schema %d, want %d", f.Schema, SchemaVersion)
	}
	return f, nil
}

var (
	procSuffix = regexp.MustCompile(`-\d+$`)
	modPrefix  = "github.com/ajitpratap0/GoSQLX/"
)

// samples collects every observation of one benchmark.
type samples struct{ ns, bytes, allocs []float64 }

// Parse reads `go test -bench -benchmem` output and returns, per benchmark
// ("<package path>:<benchmark name>"), the median of each metric over all
// samples. Benchmarks without B/op and allocs/op are skipped, because the
// gated metrics need -benchmem.
func Parse(r io.Reader) (map[string]Entry, error) {
	got := map[string]*samples{}
	pkg := ""
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "pkg: ") {
			pkg = strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "pkg: ")), modPrefix)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil {
			continue
		}
		name := procSuffix.ReplaceAllString(fields[0], "")
		key := pkg + ":" + name
		var ns, b, a float64
		var hasNs, hasB, hasA bool
		for i := 2; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				continue
			}
			switch fields[i+1] {
			case "ns/op":
				ns, hasNs = v, true
			case "B/op":
				b, hasB = v, true
			case "allocs/op":
				a, hasA = v, true
			}
		}
		if !hasNs || !hasB || !hasA {
			continue
		}
		s := got[key]
		if s == nil {
			s = &samples{}
			got[key] = s
		}
		s.ns = append(s.ns, ns)
		s.bytes = append(s.bytes, b)
		s.allocs = append(s.allocs, a)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read benchmark output: %w", err)
	}
	out := make(map[string]Entry, len(got))
	for k, s := range got {
		out[k] = Entry{NsPerOp: round(median(s.ns)), BytesPerOp: round(median(s.bytes)), AllocsPerOp: round(median(s.allocs))}
	}
	return out, nil
}

func round(v float64) float64 { return math.Round(v*100) / 100 }

func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// Violation is one gated metric that got worse than the baseline allows.
type Violation struct {
	Name, Metric string
	Base, Got    float64
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s %g -> %g", v.Name, v.Metric, v.Base, v.Got)
}

// Report is the outcome of comparing a measurement with a baseline.
type Report struct {
	Violations []Violation
	// Missing lists baseline benchmarks that were not measured.
	Missing []string
	// New lists measured benchmarks that the baseline does not know.
	New []string
	// TimeDrift lists benchmarks whose ns/op moved more than 25 percent; it is
	// informational only, since time is never gated here.
	TimeDrift []string
}

// OK reports whether the gated metrics hold. A benchmark missing from the
// measurement does not fail the check (the suite may be run in part), but New
// and Missing are reported so stale baselines are visible.
func (r Report) OK() bool { return len(r.Violations) == 0 }

// Check compares measured against base. allocs/op must not increase and B/op
// must not rise by more than BytesTolerance. ns/op is reported, never gated.
func Check(base File, measured map[string]Entry) Report {
	var rep Report
	for _, name := range sortedKeys(base.Benchmarks) {
		b := base.Benchmarks[name]
		m, ok := measured[name]
		if !ok {
			rep.Missing = append(rep.Missing, name)
			continue
		}
		if m.AllocsPerOp > b.AllocsPerOp+1e-9 {
			rep.Violations = append(rep.Violations, Violation{name, "allocs/op", b.AllocsPerOp, m.AllocsPerOp})
		}
		if m.BytesPerOp > b.BytesPerOp*(1+BytesTolerance)+1e-9 {
			rep.Violations = append(rep.Violations, Violation{name, "B/op", b.BytesPerOp, m.BytesPerOp})
		}
		if b.NsPerOp > 0 && math.Abs(m.NsPerOp-b.NsPerOp)/b.NsPerOp > 0.25 {
			rep.TimeDrift = append(rep.TimeDrift, fmt.Sprintf("%s: %g -> %g ns/op", name, b.NsPerOp, m.NsPerOp))
		}
	}
	for _, name := range sortedKeys(measured) {
		if _, ok := base.Benchmarks[name]; !ok {
			rep.New = append(rep.New, name)
		}
	}
	return rep
}

func sortedKeys(m map[string]Entry) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
