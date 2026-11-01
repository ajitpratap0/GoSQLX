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

func writeBase(t *testing.T, dir, arch, goVersion string, keys ...string) {
	t.Helper()
	f := File{Schema: SchemaVersion, Arch: arch, GoVersion: goVersion, Benchmarks: map[string]Entry{}}
	for _, k := range keys {
		f.Benchmarks[k] = Entry{NsPerOp: 1000, BytesPerOp: 500, AllocsPerOp: 10}
	}
	b, _ := f.Marshal()
	if err := os.WriteFile(filepath.Join(dir, arch+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckFailsWhenNothingBaselinedWasMeasured(t *testing.T) {
	dir := t.TempDir()
	writeBase(t, dir, "amd64", "", "pkg/gosqlx:BenchmarkParseE2E/join")
	in := filepath.Join(dir, "bench.txt")
	renamed := "goarch: amd64\npkg: github.com/ajitpratap0/GoSQLX/pkg/gosqlx\nBenchmarkParseE2ERenamed/join-8 100 1 ns/op 9999 B/op 9999 allocs/op\n"
	if err := os.WriteFile(in, []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err := run([]string{"-dir", dir, "-arch", "amd64", "-input", in}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "baseline stale") {
		t.Fatalf("disjoint run must fail as stale, got %v out=%s", err, out.String())
	}
}

func TestVerdictStaleness(t *testing.T) {
	base := File{Benchmarks: map[string]Entry{"a": {BytesPerOp: 1, AllocsPerOp: 1}, "b": {BytesPerOp: 1, AllocsPerOp: 1}}}
	partial := Check(base, map[string]Entry{"a": {BytesPerOp: 1, AllocsPerOp: 1}})
	if err := partial.Verdict(false); err != nil {
		t.Fatalf("partial run must pass when not full: %v", err)
	}
	if err := partial.Verdict(true); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("missing entry must be stale in full mode, got %v", err)
	}
	extra := Check(base, map[string]Entry{"a": {BytesPerOp: 1, AllocsPerOp: 1}, "b": {BytesPerOp: 1, AllocsPerOp: 1}, "c": {}})
	if err := extra.Verdict(false); err != nil {
		t.Fatalf("new entry must pass when not full: %v", err)
	}
	if err := extra.Verdict(true); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("new entry must be stale in full mode, got %v", err)
	}
	none := Check(base, map[string]Entry{"z": {}})
	if err := none.Verdict(false); err == nil {
		t.Fatal("nothing measured must fail even when not full")
	}
}

func TestInputGoarchMustMatchArch(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bench.txt")
	if err := os.WriteFile(in, []byte(strings.Replace(sample, "amd64", "arm64", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	err := run([]string{"-dir", dir, "-arch", "amd64", "-input", in, "-update"}, &out, &errb)
	if err == nil || !strings.Contains(err.Error(), "goarch") {
		t.Fatalf("goarch mismatch must be rejected, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "amd64.json")); statErr == nil {
		t.Fatal("amd64.json must not be written from arm64 numbers")
	}
}

func TestSameGoMinor(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"go1.26.1", "go1.26.4", true},
		{"go1.26rc1", "go1.26.0", true},
		{"go1.27.2", "go1.26.1", false},
	} {
		if got := SameGoMinor(c.a, c.b); got != c.want {
			t.Errorf("SameGoMinor(%s,%s)=%v", c.a, c.b, got)
		}
	}
}
