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

func TestParseAdaptivePlannedMetadata(t *testing.T) {
	a := mustParse(t, "layout: 21\nsuite-line: 0\nadaptive-planned: BenchmarkTarget\nBenchmarkWarm 1 100 ns/op\nBenchmarkTarget 1 120 ns/op\n")
	if !a.Planned["BenchmarkTarget"] || a.Planned["BenchmarkWarm"] {
		t.Fatalf("planned metadata = %v", a.Planned)
	}
	b := mustParse(t, "layout: 22\nadaptive-planned: BenchmarkWarm\nBenchmarkWarm 1 100 ns/op\n")
	merged := mergeRuns(a, b)
	if !merged.Planned["BenchmarkTarget"] || !merged.Planned["BenchmarkWarm"] || a.Planned["BenchmarkWarm"] {
		t.Fatalf("merge lost or mutated planned metadata: %v, original %v", merged.Planned, a.Planned)
	}
	if _, err := parseBench(strings.NewReader("adaptive-planned:\n")); err == nil {
		t.Fatal("accepted an empty planned benchmark name")
	}
}

func TestSkippedExtensionStatus(t *testing.T) {
	dir := t.TempDir()
	base, head := filepath.Join(dir, "base.txt"), filepath.Join(dir, "head.txt")
	for _, path := range []string{base, head} {
		if err := os.WriteFile(path, []byte(layoutArm(1, 100, 1, 20, 20, .12, quiet()[:1])), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	code, err := realMain([]string{"-base", base, "-head", head, "-ext-status", "skipped"}, &out)
	if err != nil || code != 0 {
		t.Fatalf("skipped status rejected: code %d, error %v", code, err)
	}
	if !strings.Contains(out.String(), "timings not judged") || !strings.Contains(out.String(), "not planned (timings not judged)") {
		t.Fatalf("missing skipped reason:\n%s", out.String())
	}
	if _, err := realMain([]string{"-base", base, "-head", head, "-ext-status", "invalid"}, &out); err == nil {
		t.Fatal("invalid extension status accepted")
	}
}
