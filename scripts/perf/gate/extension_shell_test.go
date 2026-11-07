// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runExtensionShell(t *testing.T, script string) string {
	t.Helper()
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+script)
	cmd.Env = append(os.Environ(), "OUT="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell failed: %v\n%s", err, output)
	}
	return string(output)
}

func extensionShellSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../ab.sh")
	if err != nil {
		t.Fatal(err)
	}
	return string(src)
}

func TestExtensionSkippedWhenTimingsNotJudged(t *testing.T) {
	src := extensionShellSource(t)
	start := strings.LastIndex(src, "\next_clause=")
	if start < 0 {
		t.Fatal("extension dispatch not found")
	}
	for _, tc := range []struct{ status, budget, layouts, want string }{
		{"noisy", "10", "20", "skipped"},
		{"inconclusive", "10", "20", "skipped"},
		{"pass", "10", "20", "done"},
		{"noisy", "0", "20", "off"},
		{"inconclusive", "10", "0", "off"},
	} {
		t.Run(tc.status+"/"+tc.budget+"/"+tc.layouts, func(t *testing.T) {
			setup := `out=$OUT; mkdir -p "$out/raw"
status=` + tc.status + `; budget=` + tc.budget + `; layouts=` + tc.layouts + `
kmax=200 gate=0 gate_rc=0 ext_status=off ext_count=0 ext_k=0 ext_stages=0 ext_seconds=0 ext_warmups=0
final_flags=() started=$(date +%s)
log() { :; }
die() { echo "$*"; exit 3; }
judge() { printf '%s|%s\n' "$ext_status" "$ext_clause" >> "$out/calls"; echo "$status" > "$out/status"; : > "$out/report.md"; }
extend() { ext_status=done; ext_count=1; ext_k=25; ext_stages=1; }
`
			// Keep the script's exit in a subshell so the test can inspect its output.
			output := runExtensionShell(t, "("+setup+src[start:]+")\ncat \"$OUT/calls\" \"$OUT/env.txt\" 2>/dev/null || true\n")
			if !strings.Contains(output, tc.want+"|") {
				t.Fatalf("want final status %s, got %s", tc.want, output)
			}
			if tc.want == "skipped" {
				if !strings.Contains(output, "timings not judged") {
					t.Fatalf("missing skip reason: %s", output)
				}
				if strings.Contains(output, "0s, off.") {
					t.Fatalf("placeholder off clause: %s", output)
				}
			}
		})
	}
}

func TestExtensionRecordsPlannedBenchmarksBeforeWarmups(t *testing.T) {
	src := extensionShellSource(t)
	start, end := strings.Index(src, "extend() {"), strings.Index(src, "\n# The gate tool comes")
	if start < 0 || end < start {
		t.Fatal("extension function not found")
	}
	lib, err := filepath.Abs("../lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	setup := `out=$OUT; mkdir -p "$out/raw"
. "` + lib + `"
layouts=20 seed0=100 budget=60 ext_deadline=0 ext_j=0 ext_stages=0 ext_seconds=0 ab_t0=$(date +%s)
final_flags=() ext_dirs=() pkgs=(./fake)
log() { :; }
die() { echo "$*"; exit 3; }
judge() {
 local plan=$2
 if [ "$plan" = "$out/plan-1.tsv" ]; then
  printf 'warmup\t0\t^Warm$\nneed\t0\t1\t20\t21\t^Short$\tBenchmarkShort\nneed\t0\t2\t20\t22\t^Long$\tBenchmarkLong\n' > "$plan"
 else : > "$plan"; fi
}
build_ext() { mkdir -p "$out/bin/$1/L$2"; }
run_line() {
 printf 'ran: %s\nBenchmarkWarm 1 1 ns/op\nBenchmarkShort 1 1 ns/op\nBenchmarkLong 1 1 ns/op\n' "$6" >> "$3"
}
`
	output := runExtensionShell(t, setup+src[start:end]+"\nextend\nprintf 'count: %s; warmups: %s\\n' \"$ext_count\" \"$ext_warmups\"\ncat \"$out/raw/gcoff-base-ext.txt\"\ncat \"$out/raw/gcoff-head-ext.txt\"\n")
	if strings.Count(output, "adaptive-planned: BenchmarkShort\n") != 2 || strings.Count(output, "adaptive-planned: BenchmarkLong\n") != 4 {
		t.Fatalf("planned metadata must follow each round's need rows in both arms: %s", output)
	}
	if strings.Contains(output, "adaptive-planned: BenchmarkWarm") || !strings.Contains(output, "count: 2; warmups: 1\n") {
		t.Fatalf("warmups counted as planned: %s", output)
	}
	for _, chunk := range strings.Split(output, "layout: ")[1:] {
		planned, ran := strings.Index(chunk, "adaptive-planned:"), strings.Index(chunk, "ran:")
		if planned < 0 || ran < planned {
			t.Fatalf("metadata must precede benchmark run: %s", chunk)
		}
	}
}
