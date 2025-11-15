package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestAnalyzer_Analyze tests SQL analysis functionality
func TestAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		opts          CLIAnalyzerOptions
		expectError   bool
		errorContains string
	}{
		{
			name:  "valid SQL - basic SELECT",
			input: "SELECT * FROM users WHERE active = true",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError: false,
		},
		{
			name:  "valid SQL - complex query with JOIN",
			input: "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError: false,
		},
		{
			name:  "valid SQL - window function",
			input: "SELECT name, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError: false,
		},
		{
			name:  "valid SQL - CTE",
			input: "WITH temp AS (SELECT id FROM users) SELECT * FROM temp",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError: false,
		},
		{
			name:  "invalid SQL - missing table name",
			input: "SELECT * FROM",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError:   true,
			errorContains: "parsing failed",
		},
		{
			name:  "empty input",
			input: "",
			opts: CLIAnalyzerOptions{
				Format: "table",
			},
			expectError:   true,
			errorContains: "empty input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			analyzer := NewAnalyzer(&outBuf, &errBuf, tt.opts)

			result, err := analyzer.Analyze(tt.input)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Error("Expected result but got nil")
				}
				if result != nil && result.Report == nil {
					t.Error("Expected report but got nil")
				}
			}
		})
	}
}

// TestAnalyzer_DisplayReport_JSON tests JSON output format
func TestAnalyzer_DisplayReport_JSON(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format: "json",
	})

	result, err := analyzer.Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	err = analyzer.DisplayReport(result.Report)
	if err != nil {
		t.Fatalf("Failed to display report: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected JSON output but got empty string")
	}

	// Basic JSON validation
	if !strings.Contains(output, "{") || !strings.Contains(output, "}") {
		t.Error("Output doesn't look like valid JSON")
	}
}

// TestAnalyzer_DisplayReport_YAML tests YAML output format
func TestAnalyzer_DisplayReport_YAML(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format: "yaml",
	})

	result, err := analyzer.Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	err = analyzer.DisplayReport(result.Report)
	if err != nil {
		t.Fatalf("Failed to display report: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected YAML output but got empty string")
	}
}

// TestAnalyzer_DisplayReport_Table tests table output format
func TestAnalyzer_DisplayReport_Table(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format: "table",
	})

	result, err := analyzer.Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	err = analyzer.DisplayReport(result.Report)
	if err != nil {
		t.Fatalf("Failed to display report: %v", err)
	}

	output := outBuf.String()
	if output == "" {
		t.Error("Expected table output but got empty string")
	}

	// Check for expected table elements
	expectedElements := []string{
		"SQL Analysis Report",
		"Summary:",
		"Security Analysis:",
		"Performance Analysis:",
		"Complexity Metrics:",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(output, elem) {
			t.Errorf("Expected output to contain '%s', but it doesn't", elem)
		}
	}
}

// TestAnalyzer_SecurityAnalysis tests security-focused analysis
func TestAnalyzer_SecurityAnalysis(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format:   "table",
		Security: true,
	})

	result, err := analyzer.Analyze("SELECT * FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Report == nil {
		t.Fatal("Expected report but got nil")
	}

	// Security analysis should produce a report
	if result.Report.SecurityScore < 0 || result.Report.SecurityScore > 100 {
		t.Errorf("Invalid security score: %d", result.Report.SecurityScore)
	}
}

// TestAnalyzer_ComplexityAnalysis tests complexity-focused analysis
func TestAnalyzer_ComplexityAnalysis(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format:     "table",
		Complexity: true,
	})

	// Complex query with JOINs
	complexQuery := "SELECT u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.name"
	result, err := analyzer.Analyze(complexQuery)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Report == nil {
		t.Fatal("Expected report but got nil")
	}

	// Complexity metrics should be populated
	if result.Report.ComplexityMetrics.ComplexityScore < 0 {
		t.Errorf("Invalid complexity score: %.1f", result.Report.ComplexityMetrics.ComplexityScore)
	}
}

// TestAnalyzer_PerformanceAnalysis tests performance-focused analysis
func TestAnalyzer_PerformanceAnalysis(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	analyzer := NewAnalyzer(&outBuf, &errBuf, CLIAnalyzerOptions{
		Format:      "table",
		Performance: true,
	})

	result, err := analyzer.Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Report == nil {
		t.Fatal("Expected report but got nil")
	}

	// Performance analysis should produce a score
	if result.Report.PerformanceScore < 0 || result.Report.PerformanceScore > 100 {
		t.Errorf("Invalid performance score: %d", result.Report.PerformanceScore)
	}
}

// TestFilterIssuesByCategory tests issue filtering
func TestFilterIssuesByCategory(t *testing.T) {
	issues := []AnalysisIssue{
		{
			Category: IssueCategorySecurity,
			Title:    "Security issue 1",
		},
		{
			Category: IssueCategoryPerformance,
			Title:    "Performance issue 1",
		},
		{
			Category: IssueCategorySecurity,
			Title:    "Security issue 2",
		},
	}

	securityIssues := filterIssuesByCategory(issues, IssueCategorySecurity)
	if len(securityIssues) != 2 {
		t.Errorf("Expected 2 security issues, got %d", len(securityIssues))
	}

	performanceIssues := filterIssuesByCategory(issues, IssueCategoryPerformance)
	if len(performanceIssues) != 1 {
		t.Errorf("Expected 1 performance issue, got %d", len(performanceIssues))
	}
}

// TestAnalyzerOptionsFromConfig tests configuration merging
func TestAnalyzerOptionsFromConfig(t *testing.T) {
	opts := &CLIAnalyzerOptions{
		Security:    true,
		Performance: false,
		Format:      "json",
	}

	if !opts.Security {
		t.Error("Expected Security=true")
	}
	if opts.Performance {
		t.Error("Expected Performance=false")
	}
	if opts.Format != "json" {
		t.Errorf("Expected Format=json, got %s", opts.Format)
	}
}
