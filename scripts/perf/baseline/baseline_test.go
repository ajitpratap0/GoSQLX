// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `goos: linux
goarch: amd64
pkg: github.com/ajitpratap0/GoSQLX/pkg/gosqlx
BenchmarkParseE2E/join-8      	  100	      1000 ns/op	     500 B/op	      10 allocs/op
BenchmarkParseE2E/join-8      	  100	      3000 ns/op	     500 B/op	      10 allocs/op
BenchmarkParseE2E/join-8      	  100	      2000 ns/op	     700 B/op	      12 allocs/op
BenchmarkNoMem-8              	  100	      2000 ns/op
PASS
pkg: github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer
BenchmarkTokenize/scratch/join	  100	       400 ns/op	       0 B/op	       0 allocs/op
`

func TestParseTakesMedianPerPackageQualifiedBenchmark(t *testing.T) {
	got, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 benchmarks (the one without -benchmem is skipped), got %v", got)
	}
	e, ok := got["pkg/gosqlx:BenchmarkParseE2E/join"]
	if !ok {
		t.Fatalf("missing procs-stripped, package-qualified key: %v", got)
	}
	if e.NsPerOp != 2000 || e.BytesPerOp != 500 || e.AllocsPerOp != 10 {
		t.Errorf("medians wrong: %+v", e)
	}
	if _, ok := got["pkg/sql/tokenizer:BenchmarkTokenize/scratch/join"]; !ok {
		t.Errorf("tokenizer benchmark missing: %v", got)
	}
}

func TestCheckGatesAllocsAndBytesNotTime(t *testing.T) {
	base := File{Benchmarks: map[string]Entry{
		"a": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 10},
		"b": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 10},
		"c": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 10},
		"d": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 10},
		"e": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 10},
	}}
	measured := map[string]Entry{
		"a": {NsPerOp: 900, BytesPerOp: 1000, AllocsPerOp: 10}, // 9x slower: trend only
		"b": {NsPerOp: 100, BytesPerOp: 1000, AllocsPerOp: 11}, // +1 alloc
		"c": {NsPerOp: 100, BytesPerOp: 1020, AllocsPerOp: 10}, // exactly +2%: allowed
		"d": {NsPerOp: 100, BytesPerOp: 1021, AllocsPerOp: 10}, // over +2%
		"e": {NsPerOp: 100, BytesPerOp: 500, AllocsPerOp: 5},   // improvement
		"f": {NsPerOp: 1, BytesPerOp: 1, AllocsPerOp: 1},
	}
	rep := Check(base, measured)
	var names []string
	for _, v := range rep.Violations {
		names = append(names, v.Name+"/"+v.Metric)
	}
	if got := strings.Join(names, ","); got != "b/allocs/op,d/B/op" {
		t.Errorf("violations = %q, want b/allocs/op,d/B/op", got)
	}
	if len(rep.TimeDrift) != 1 || !strings.HasPrefix(rep.TimeDrift[0], "a:") {
		t.Errorf("time drift should be reported for a only: %v", rep.TimeDrift)
	}
	if len(rep.New) != 1 || rep.New[0] != "f" {
		t.Errorf("New = %v", rep.New)
	}
	if rep.OK() {
		t.Error("report with violations must not be OK")
	}
}

func TestCheckMissingBenchmarkDoesNotFail(t *testing.T) {
	base := File{Benchmarks: map[string]Entry{"a": {BytesPerOp: 1, AllocsPerOp: 1}}}
	rep := Check(base, map[string]Entry{})
	if !rep.OK() || len(rep.Missing) != 1 {
		t.Errorf("want OK with one Missing, got %+v", rep)
	}
}

func TestUpdateThenCheckRoundTripAndRegression(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bench.txt")
	if err := os.WriteFile(in, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	args := []string{"-dir", dir, "-arch", "amd64", "-input", in}
	if err := run(append(args, "-update"), &out, &errb); err != nil {
		t.Fatalf("update: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "amd64.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f, err := ParseFile(data); err != nil || f.Arch != "amd64" || len(f.Benchmarks) != 2 {
		t.Fatalf("written file wrong: %v %+v", err, f)
	}
	out.Reset()
	if err := run(args, &out, &errb); err != nil {
		t.Fatalf("check of identical data failed: %v\n%s", err, out.String())
	}

	worse := strings.ReplaceAll(sample, "      10 allocs/op", "      30 allocs/op")
	worse = strings.ReplaceAll(worse, "      12 allocs/op", "      30 allocs/op")
	if err := os.WriteFile(in, []byte(worse), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err = run(args, &out, &errb)
	if err == nil || !strings.Contains(out.String(), "REGRESSION: pkg/gosqlx:BenchmarkParseE2E/join: allocs/op") {
		t.Fatalf("alloc regression not caught: err=%v out=%s", err, out.String())
	}
}

func TestCheckRefusesEmptyBaseline(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bench.txt")
	if err := os.WriteFile(in, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := File{Schema: SchemaVersion, Arch: "amd64", Benchmarks: map[string]Entry{}}
	b, _ := empty.Marshal()
	if err := os.WriteFile(filepath.Join(dir, "amd64.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err := run([]string{"-dir", dir, "-arch", "amd64", "-input", in}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "no benchmarks yet") {
		t.Fatalf("empty baseline must be refused loudly, got %v", err)
	}
}

func TestRepositoryBaselineFilesAreValid(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "benchmarks", "baselines", arch+".json"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseFile(data)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		if f.Arch != arch {
			t.Errorf("%s.json declares arch %q", arch, f.Arch)
		}
	}
}
