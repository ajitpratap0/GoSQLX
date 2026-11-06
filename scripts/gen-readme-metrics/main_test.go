package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncBanners(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"bold version", "**Version**: v1.13.0 | **Last Updated**: 2026-03-20", "**Version**: v1.15.0 | **Last Updated**: 2026-03-20"},
		{"title", "# API Reference (v1.14.0)", "# API Reference (v1.15.0)"},
		{"bold version no v", "**Version**: 1.6.0", "**Version**: 1.15.0"},
		{"current version", "**Current Version**: v1.14.0 | x", "**Current Version**: v1.15.0 | x"},
		{"no v prefix", "**GoSQLX Version**: 1.14.0", "**GoSQLX Version**: 1.15.0"},
		{"colon inside bold", "**Version:** v1.6.0", "**Version:** v1.15.0"},
		{"colon inside bold GoSQLX", "**GoSQLX Version:** v1.6.0", "**GoSQLX Version:** v1.15.0"},
		{"history untouched", "| ✅ v1.14.0 |", "| ✅ v1.14.0 |"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := syncBanners(tc.in, "1.15.0"); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReplaceBlock(t *testing.T) {
	src := "a\n<!-- x:start -->\nold\n<!-- x:end -->\nb <!-- y:start -->old<!-- y:end -->"
	got, err := replaceBlock(src, "x", "new")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "<!-- x:start -->\nnew\n<!-- x:end -->") {
		t.Fatalf("block not replaced: %q", got)
	}
	got, err = replaceBlock(got, "y", "new")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "<!-- y:start -->new<!-- y:end -->") {
		t.Fatalf("inline block not replaced: %q", got)
	}
	if _, err := replaceBlock(src, "missing", "n"); err == nil {
		t.Fatal("expected error for missing markers")
	}
}

func TestParsesPerSec(t *testing.T) {
	if got := (metrics{ParseNsPerOp: 318}).parsesPerSec(); got != "~3.1M" {
		t.Fatalf("got %s", got)
	}
}

func TestParseBaselineAndMedian(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"BenchmarkPerformanceBaseline/SimpleSelect-10  100  1 ns/op",
		"BenchmarkPerformanceBaseline/ComplexQuery-10 100 900 ns/op",
		"BenchmarkPerformanceBaseline/SimpleSelect-4  100  2 ns/op",
		"BenchmarkPerformanceBaseline/SimpleSelect-10  100  3 ns/op",
		"BenchmarkPerformanceBaseline/ComplexQuery-4 100 800 ns/op",
		"BenchmarkPerformanceBaseline/SimpleSelect-4  100  4 ns/op",
		"BenchmarkPerformanceBaseline/SimpleSelect-10  100  9 ns/op",
		"BenchmarkPerformanceBaselineX/SimpleSelect-10 100 999 ns/op",
	}, "\n"))
	samples, err := parseBaseline(raw, "SimpleSelect")
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 5 || median(samples) != 3 {
		t.Fatalf("samples=%v, median=%v; want 5 and 3", samples, median(samples))
	}
	if got := median([]float64{9, 1, 5, 3}); got != 4 {
		t.Fatalf("even median=%v, want 4", got)
	}
	if _, err := parseBaseline([]byte("BenchmarkPerformanceBaselineX/SimpleSelect-10 100 12 ns/op\n"), "SimpleSelect"); err == nil {
		t.Fatal("prefix trap was accepted as a SimpleSelect benchmark")
	}
	if _, err := parseBaseline([]byte("BenchmarkPerformanceBaseline/ComplexQuery-10 100 12 ns/op\n"), "SimpleSelect"); err == nil {
		t.Fatal("missing SimpleSelect samples did not return an error")
	}
}

func TestRecordRewritesMetrics(t *testing.T) {
	root := t.TempDir()
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.MkdirAll(filepath.Join(root, "scripts/gen-readme-metrics"), 0o755); err != nil {
		t.Fatal(err)
	}
	metricsBefore := `{
  "stage": "parse",
  "query": "simple SELECT",
  "parse_ns_per_op": 318,
  "hardware": "Old CPU",
  "go_version": "1.26",
  "runs": 10,
  "benchmark": "BenchmarkPerformanceBaseline/SimpleSelect",
  "benchmark_package": "./pkg/sql/parser",
  "sql99_estimate": "~80-85%",
  "dialects": 8,
  "race_conditions": 0,
  "measured_at": "2026-10-22",
  "measured_tag": "v1.16.0"
}
`
	if err := os.WriteFile("scripts/gen-readme-metrics/metrics.json", []byte(metricsBefore), 0o644); err != nil {
		t.Fatal(err)
	}
	readme := "<!-- metrics:start -->\nold table\n<!-- metrics:end -->\n<!-- metrics-inline:start -->\nold inline\n<!-- metrics-inline:end -->\n"
	if err := os.WriteFile("README.md", []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("doc.go", []byte("// v1.2.3: fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("raw.txt", []byte("BenchmarkPerformanceBaseline/SimpleSelect-10 100 2 ns/op\nBenchmarkPerformanceBaseline/SimpleSelect-10 100 3 ns/op\nBenchmarkPerformanceBaseline/ComplexQuery-10 100 20 ns/op\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"--record", "raw.txt", "--tag", "v1.2.3", "--hardware", "Test CPU", "--go-version", "1.27", "--date", "2026-11-03", "--version", "1.2.3"}
	if err := runWithArgs(args); err != nil {
		t.Fatal(err)
	}
	gotMetrics, err := os.ReadFile("scripts/gen-readme-metrics/metrics.json")
	if err != nil {
		t.Fatal(err)
	}
	wantMetrics := strings.ReplaceAll(metricsBefore,
		`"parse_ns_per_op": 318`, `"parse_ns_per_op": 3`)
	wantMetrics = strings.ReplaceAll(wantMetrics, `"hardware": "Old CPU"`, `"hardware": "Test CPU"`)
	wantMetrics = strings.ReplaceAll(wantMetrics, `"go_version": "1.26"`, `"go_version": "1.27"`)
	wantMetrics = strings.ReplaceAll(wantMetrics, `"runs": 10`, `"runs": 2`)
	wantMetrics = strings.ReplaceAll(wantMetrics, `"measured_at": "2026-10-22"`, `"measured_at": "2026-11-03"`)
	wantMetrics = strings.ReplaceAll(wantMetrics, `"measured_tag": "v1.16.0"`, `"measured_tag": "v1.2.3"`)
	if string(gotMetrics) != wantMetrics {
		t.Fatalf("metrics mismatch\n--- got ---\n%s\n--- want ---\n%s", gotMetrics, wantMetrics)
	}
	gotReadme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(gotReadme), "old table") || !strings.Contains(string(gotReadme), "3 ns parse latency") {
		t.Fatalf("README metrics block was not rewritten: %s", gotReadme)
	}
	badArgs := []string{"--record", "raw.txt", "--tag", "1.2.3", "--hardware", "Test CPU", "--go-version", "1.27", "--date", "2026-11-03", "--version", "1.2.3"}
	if err := runWithArgs(badArgs); err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("bad tag error=%v, want a tag validation error", err)
	}
}
