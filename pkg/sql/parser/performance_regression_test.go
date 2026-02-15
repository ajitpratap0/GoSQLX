package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// PerformanceBaseline represents a single performance baseline
type PerformanceBaseline struct {
	NsPerOp          int64   `json:"ns_per_op,omitempty"`
	TokensPerSec     int64   `json:"tokens_per_sec,omitempty"`
	OpsPerSec        int64   `json:"ops_per_sec,omitempty"`
	TolerancePercent float64 `json:"tolerance_percent"`
	Description      string  `json:"description"`
}

// BaselineConfig represents the entire baseline configuration
type BaselineConfig struct {
	Version   string                         `json:"version"`
	Updated   string                         `json:"updated"`
	Baselines map[string]PerformanceBaseline `json:"baselines"`
}

// PerformanceResult represents the result of a performance test
type PerformanceResult struct {
	Name         string
	NsPerOp      int64
	TokensPerSec int64
	OpsPerSec    int64
	AllocsPerOp  int64
	BytesPerOp   int64
	Iterations   int
	Duration     time.Duration
}

// loadBaselines loads performance baselines from JSON file
func loadBaselines(t *testing.T) BaselineConfig {
	// Find the project root by looking for go.mod
	currentDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Walk up directories to find project root
	projectRoot := currentDir
	for {
		goModPath := filepath.Join(projectRoot, "go.mod")
		if _, err := os.Stat(goModPath); err == nil {
			break
		}
		parent := filepath.Dir(projectRoot)
		if parent == projectRoot {
			t.Fatalf("Could not find project root (go.mod)")
		}
		projectRoot = parent
	}

	baselinesPath := filepath.Join(projectRoot, "performance_baselines.json")
	data, err := os.ReadFile(baselinesPath)
	if err != nil {
		t.Fatalf("Failed to read baselines file %s: %v", baselinesPath, err)
	}

	var config BaselineConfig
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to parse baselines JSON: %v", err)
	}

	return config
}

// calculateDegradation calculates the percentage degradation from baseline
func calculateDegradation(actual, baseline int64) float64 {
	if baseline == 0 {
		return 0
	}
	return (float64(actual) - float64(baseline)) / float64(baseline) * 100
}

// TestPerformanceRegression tests for performance regressions against baselines
func TestPerformanceRegression(t *testing.T) {
	// Skip on older Go versions — perf baselines are calibrated for Go 1.24+
	// Older compilers produce slower code, causing false regression failures
	if !goVersionAtLeast(1, 24) {
		t.Skip("Skipping performance regression tests on Go < 1.24 (baselines calibrated for 1.24+)")
	}

	// Skip performance tests when race detector is enabled
	// Race detector adds 3-5x overhead making performance measurements unreliable
	// This is detected via the raceEnabled variable set in performance_regression_race.go
	if raceEnabled {
		t.Skip("Skipping performance regression tests with race detector (adds 3-5x overhead)")
	}

	// Also skip in short mode for faster test runs
	if testing.Short() {
		t.Skip("Skipping performance regression tests in short mode")
	}

	// Load baselines
	config := loadBaselines(t)

	t.Logf("Running performance regression tests against baselines version %s (updated: %s)",
		config.Version, config.Updated)

	// Track overall pass/fail
	failures := []string{}
	warnings := []string{}

	// Test 1: Simple SELECT performance
	t.Run("SimpleSelect", func(t *testing.T) {
		baseline := config.Baselines["SimpleSelect"]

		// Run benchmark
		result := testing.Benchmark(func(b *testing.B) {
			benchmarkParser(b, simpleSelectTokens)
		})

		actualNs := result.NsPerOp()
		degradation := calculateDegradation(actualNs, baseline.NsPerOp)

		t.Logf("Simple SELECT: %d ns/op (baseline: %d ns/op, degradation: %.1f%%)",
			actualNs, baseline.NsPerOp, degradation)

		if degradation > baseline.TolerancePercent {
			msg := fmt.Sprintf("SimpleSelect: %.1f%% slower (actual: %d ns/op, baseline: %d ns/op)",
				degradation, actualNs, baseline.NsPerOp)
			failures = append(failures, msg)
			t.Errorf("REGRESSION: %s", msg)
		} else if degradation > baseline.TolerancePercent/2 {
			msg := fmt.Sprintf("SimpleSelect: %.1f%% slower (approaching threshold)",
				degradation)
			warnings = append(warnings, msg)
			t.Logf("WARNING: %s", msg)
		} else {
			t.Logf("✓ Performance within acceptable range")
		}
	})

	// Test 2: Complex query performance
	t.Run("ComplexQuery", func(t *testing.T) {
		baseline := config.Baselines["ComplexQuery"]

		result := testing.Benchmark(func(b *testing.B) {
			benchmarkParser(b, complexSelectTokens)
		})

		actualNs := result.NsPerOp()
		degradation := calculateDegradation(actualNs, baseline.NsPerOp)

		t.Logf("Complex Query: %d ns/op (baseline: %d ns/op, degradation: %.1f%%)",
			actualNs, baseline.NsPerOp, degradation)

		if degradation > baseline.TolerancePercent {
			msg := fmt.Sprintf("ComplexQuery: %.1f%% slower (actual: %d ns/op, baseline: %d ns/op)",
				degradation, actualNs, baseline.NsPerOp)
			failures = append(failures, msg)
			t.Errorf("REGRESSION: %s", msg)
		} else if degradation > baseline.TolerancePercent/2 {
			msg := fmt.Sprintf("ComplexQuery: %.1f%% slower (approaching threshold)",
				degradation)
			warnings = append(warnings, msg)
			t.Logf("WARNING: %s", msg)
		} else {
			t.Logf("✓ Performance within acceptable range")
		}
	})

	// Test 3: Window function performance
	t.Run("WindowFunction", func(t *testing.T) {
		baseline := config.Baselines["WindowFunction"]

		// Window function query: SELECT name, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary) FROM employees
		windowTokens := []token.Token{
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "name"},
			{Type: models.TokenTypeComma, Literal: ","},
			{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeOver, Literal: "OVER"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypePartition, Literal: "PARTITION"},
			{Type: models.TokenTypeBy, Literal: "BY"},
			{Type: models.TokenTypeIdentifier, Literal: "dept"},
			{Type: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: models.TokenTypeBy, Literal: "BY"},
			{Type: models.TokenTypeIdentifier, Literal: "salary"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "employees"},
		}

		result := testing.Benchmark(func(b *testing.B) {
			benchmarkParser(b, windowTokens)
		})

		actualNs := result.NsPerOp()
		degradation := calculateDegradation(actualNs, baseline.NsPerOp)

		t.Logf("Window Function: %d ns/op (baseline: %d ns/op, degradation: %.1f%%)",
			actualNs, baseline.NsPerOp, degradation)

		if degradation > baseline.TolerancePercent {
			msg := fmt.Sprintf("WindowFunction: %.1f%% slower (actual: %d ns/op, baseline: %d ns/op)",
				degradation, actualNs, baseline.NsPerOp)
			failures = append(failures, msg)
			t.Errorf("REGRESSION: %s", msg)
		} else if degradation > baseline.TolerancePercent/2 {
			msg := fmt.Sprintf("WindowFunction: %.1f%% slower (approaching threshold)",
				degradation)
			warnings = append(warnings, msg)
			t.Logf("WARNING: %s", msg)
		} else {
			t.Logf("✓ Performance within acceptable range")
		}
	})

	// Test 4: CTE performance
	t.Run("CTE", func(t *testing.T) {
		baseline := config.Baselines["CTE"]

		// CTE query: WITH cte AS (SELECT id FROM users) SELECT * FROM cte
		cteTokens := []token.Token{
			{Type: models.TokenTypeWith, Literal: "WITH"},
			{Type: models.TokenTypeIdentifier, Literal: "cte"},
			{Type: models.TokenTypeAs, Literal: "AS"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeAsterisk, Literal: "*"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "cte"},
		}

		result := testing.Benchmark(func(b *testing.B) {
			benchmarkParser(b, cteTokens)
		})

		actualNs := result.NsPerOp()
		degradation := calculateDegradation(actualNs, baseline.NsPerOp)

		t.Logf("CTE: %d ns/op (baseline: %d ns/op, degradation: %.1f%%)",
			actualNs, baseline.NsPerOp, degradation)

		if degradation > baseline.TolerancePercent {
			msg := fmt.Sprintf("CTE: %.1f%% slower (actual: %d ns/op, baseline: %d ns/op)",
				degradation, actualNs, baseline.NsPerOp)
			failures = append(failures, msg)
			t.Errorf("REGRESSION: %s", msg)
		} else if degradation > baseline.TolerancePercent/2 {
			msg := fmt.Sprintf("CTE: %.1f%% slower (approaching threshold)",
				degradation)
			warnings = append(warnings, msg)
			t.Logf("WARNING: %s", msg)
		} else {
			t.Logf("✓ Performance within acceptable range")
		}
	})

	// Test 5: INSERT performance (added to replace RecursiveCTE until UNION is fully supported)
	t.Run("INSERT", func(t *testing.T) {
		baseline, ok := config.Baselines["INSERT"]
		if !ok {
			// Fallback baseline if not found in config
			baseline = PerformanceBaseline{
				NsPerOp:          350,
				TolerancePercent: 20,
				Description:      "Simple INSERT statement",
			}
		}

		result := testing.Benchmark(func(b *testing.B) {
			benchmarkParser(b, insertTokens)
		})

		actualNs := result.NsPerOp()
		degradation := calculateDegradation(actualNs, baseline.NsPerOp)

		t.Logf("INSERT: %d ns/op (baseline: %d ns/op, degradation: %.1f%%)",
			actualNs, baseline.NsPerOp, degradation)

		if degradation > baseline.TolerancePercent {
			msg := fmt.Sprintf("INSERT: %.1f%% slower (actual: %d ns/op, baseline: %d ns/op)",
				degradation, actualNs, baseline.NsPerOp)
			failures = append(failures, msg)
			t.Errorf("REGRESSION: %s", msg)
		} else if degradation > baseline.TolerancePercent/2 {
			msg := fmt.Sprintf("INSERT: %.1f%% slower (approaching threshold)",
				degradation)
			warnings = append(warnings, msg)
			t.Logf("WARNING: %s", msg)
		} else {
			t.Logf("✓ Performance within acceptable range")
		}
	})

	// Summary report
	t.Run("Summary", func(t *testing.T) {
		separator := "================================================================================"
		t.Log("\n" + separator)
		t.Log("PERFORMANCE REGRESSION TEST SUMMARY")
		t.Log(separator)

		if len(failures) == 0 && len(warnings) == 0 {
			t.Log("✓ All performance tests passed with no warnings")
		} else {
			if len(failures) > 0 {
				t.Log("\nREGRESSIONS DETECTED:")
				for _, failure := range failures {
					t.Logf("  ✗ %s", failure)
				}
			}

			if len(warnings) > 0 {
				t.Log("\nWARNINGS (approaching threshold):")
				for _, warning := range warnings {
					t.Logf("  ⚠ %s", warning)
				}
			}
		}

		t.Logf("\nBaseline Version: %s", config.Version)
		t.Logf("Baseline Updated: %s", config.Updated)
		t.Logf("Tests Run: 5")
		t.Logf("Failures: %d", len(failures))
		t.Logf("Warnings: %d", len(warnings))
		t.Log(separator)

		// Fail the summary test if there were any regressions
		if len(failures) > 0 {
			t.Errorf("Performance regression test suite detected %d regression(s)", len(failures))
		}
	})
}

// BenchmarkPerformanceBaseline is a convenience benchmark to establish new baselines
// Run with: go test -bench=BenchmarkPerformanceBaseline -benchmem -count=5 ./pkg/sql/parser/
func BenchmarkPerformanceBaseline(b *testing.B) {
	b.Run("SimpleSelect", func(b *testing.B) {
		b.ReportAllocs()
		benchmarkParser(b, simpleSelectTokens)
	})

	b.Run("ComplexQuery", func(b *testing.B) {
		b.ReportAllocs()
		benchmarkParser(b, complexSelectTokens)
	})

	b.Run("WindowFunction", func(b *testing.B) {
		windowTokens := []token.Token{
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "name"},
			{Type: models.TokenTypeComma, Literal: ","},
			{Type: models.TokenTypeIdentifier, Literal: "ROW_NUMBER"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeOver, Literal: "OVER"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypePartition, Literal: "PARTITION"},
			{Type: models.TokenTypeBy, Literal: "BY"},
			{Type: models.TokenTypeIdentifier, Literal: "dept"},
			{Type: models.TokenTypeOrder, Literal: "ORDER"},
			{Type: models.TokenTypeBy, Literal: "BY"},
			{Type: models.TokenTypeIdentifier, Literal: "salary"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "employees"},
		}
		b.ReportAllocs()
		benchmarkParser(b, windowTokens)
	})

	b.Run("CTE", func(b *testing.B) {
		cteTokens := []token.Token{
			{Type: models.TokenTypeWith, Literal: "WITH"},
			{Type: models.TokenTypeIdentifier, Literal: "cte"},
			{Type: models.TokenTypeAs, Literal: "AS"},
			{Type: models.TokenTypeLParen, Literal: "("},
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeIdentifier, Literal: "id"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "users"},
			{Type: models.TokenTypeRParen, Literal: ")"},
			{Type: models.TokenTypeSelect, Literal: "SELECT"},
			{Type: models.TokenTypeAsterisk, Literal: "*"},
			{Type: models.TokenTypeFrom, Literal: "FROM"},
			{Type: models.TokenTypeIdentifier, Literal: "cte"},
		}
		b.ReportAllocs()
		benchmarkParser(b, cteTokens)
	})

	b.Run("INSERT", func(b *testing.B) {
		b.ReportAllocs()
		benchmarkParser(b, insertTokens)
	})
}

// goVersionAtLeast checks if the current Go version is >= major.minor.
func goVersionAtLeast(major, minor int) bool {
	v := runtime.Version() // e.g. "go1.24.1"
	v = strings.TrimPrefix(v, "go")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && min >= minor)
}
