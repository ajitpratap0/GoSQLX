package output

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFormatPRComment(t *testing.T) {
	tests := []struct {
		name            string
		result          *ValidationResult
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "all files valid",
			result: &ValidationResult{
				TotalFiles:   5,
				ValidFiles:   5,
				InvalidFiles: 0,
				Duration:     100 * time.Millisecond,
				Files: []FileValidationResult{
					{Path: "query1.sql", Valid: true},
					{Path: "query2.sql", Valid: true},
					{Path: "query3.sql", Valid: true},
					{Path: "query4.sql", Valid: true},
					{Path: "query5.sql", Valid: true},
				},
			},
			wantContains: []string{
				"All SQL files are valid",
				"**5** file(s) validated successfully",
				"Total Files | 5",
				"✅ Valid | 5",
				"❌ Invalid | 0",
			},
			wantNotContains: []string{
				"Validation Errors",
				"❌ `",
			},
		},
		{
			name: "files with errors",
			result: &ValidationResult{
				TotalFiles:   3,
				ValidFiles:   1,
				InvalidFiles: 2,
				Duration:     50 * time.Millisecond,
				Files: []FileValidationResult{
					{Path: "valid.sql", Valid: true},
					{
						Path:  "error1.sql",
						Valid: false,
						Error: errors.New("parsing failed: unexpected token"),
					},
					{
						Path:  "error2.sql",
						Valid: false,
						Error: errors.New("tokenization failed: invalid character"),
					},
				},
			},
			wantContains: []string{
				"Found issues in **2** file(s)",
				"Total Files | 3",
				"✅ Valid | 1",
				"❌ Invalid | 2",
				"Validation Errors",
				"❌ `error1.sql`",
				"parsing failed: unexpected token",
				"❌ `error2.sql`",
				"tokenization failed: invalid character",
			},
		},
		{
			name: "single error",
			result: &ValidationResult{
				TotalFiles:   1,
				ValidFiles:   0,
				InvalidFiles: 1,
				Duration:     10 * time.Millisecond,
				Files: []FileValidationResult{
					{
						Path:  "bad.sql",
						Valid: false,
						Error: errors.New("syntax error on line 5"),
					},
				},
			},
			wantContains: []string{
				"Found issues in **1** file(s)",
				"❌ `bad.sql`",
				"syntax error on line 5",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPRComment(tt.result)

			// Check for required content
			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("FormatPRComment() missing expected content: %q\nGot:\n%s", want, result)
				}
			}

			// Check for prohibited content
			for _, notWant := range tt.wantNotContains {
				if strings.Contains(result, notWant) {
					t.Errorf("FormatPRComment() contains unexpected content: %q\nGot:\n%s", notWant, result)
				}
			}

			// Verify it's valid markdown-ish
			if !strings.Contains(result, "##") {
				t.Error("FormatPRComment() missing markdown headers")
			}

			if !strings.Contains(result, "GoSQLX") {
				t.Error("FormatPRComment() missing branding")
			}
		})
	}
}

func TestFormatPRCommentCompact(t *testing.T) {
	tests := []struct {
		name            string
		result          *ValidationResult
		maxErrors       int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "all files valid compact",
			result: &ValidationResult{
				TotalFiles:   10,
				ValidFiles:   10,
				InvalidFiles: 0,
				Duration:     200 * time.Millisecond,
				Files:        make([]FileValidationResult, 10),
			},
			maxErrors: 5,
			wantContains: []string{
				"All SQL files valid",
				"Validated **10** file(s)",
			},
			wantNotContains: []string{
				"Found issues",
			},
		},
		{
			name: "multiple errors with truncation",
			result: &ValidationResult{
				TotalFiles:   10,
				ValidFiles:   5,
				InvalidFiles: 5,
				Duration:     100 * time.Millisecond,
				Files: []FileValidationResult{
					{Path: "valid1.sql", Valid: true},
					{Path: "valid2.sql", Valid: true},
					{Path: "valid3.sql", Valid: true},
					{Path: "valid4.sql", Valid: true},
					{Path: "valid5.sql", Valid: true},
					{Path: "error1.sql", Valid: false, Error: errors.New("error 1")},
					{Path: "error2.sql", Valid: false, Error: errors.New("error 2")},
					{Path: "error3.sql", Valid: false, Error: errors.New("error 3")},
					{Path: "error4.sql", Valid: false, Error: errors.New("error 4")},
					{Path: "error5.sql", Valid: false, Error: errors.New("error 5")},
				},
			},
			maxErrors: 3,
			wantContains: []string{
				"Found issues in 5/10 files",
				"❌ `error1.sql`: error 1",
				"❌ `error2.sql`: error 2",
				"❌ `error3.sql`: error 3",
				"and 2 more error(s)",
			},
			wantNotContains: []string{
				"error4.sql",
				"error5.sql",
			},
		},
		{
			name: "errors within limit",
			result: &ValidationResult{
				TotalFiles:   3,
				ValidFiles:   1,
				InvalidFiles: 2,
				Duration:     50 * time.Millisecond,
				Files: []FileValidationResult{
					{Path: "valid.sql", Valid: true},
					{Path: "error1.sql", Valid: false, Error: errors.New("error 1")},
					{Path: "error2.sql", Valid: false, Error: errors.New("error 2")},
				},
			},
			maxErrors: 5,
			wantContains: []string{
				"Found issues in 2/3 files",
				"❌ `error1.sql`: error 1",
				"❌ `error2.sql`: error 2",
			},
			wantNotContains: []string{
				"more error(s)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPRCommentCompact(tt.result, tt.maxErrors)

			// Check for required content
			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("FormatPRCommentCompact() missing expected content: %q\nGot:\n%s", want, result)
				}
			}

			// Check for prohibited content
			for _, notWant := range tt.wantNotContains {
				if strings.Contains(result, notWant) {
					t.Errorf("FormatPRCommentCompact() contains unexpected content: %q\nGot:\n%s", notWant, result)
				}
			}

			// Verify it's more compact than full format
			if strings.Count(result, "\n") > 20 {
				t.Error("FormatPRCommentCompact() should be more compact")
			}
		})
	}
}

func TestPRCommentMarkdownStructure(t *testing.T) {
	result := &ValidationResult{
		TotalFiles:   2,
		ValidFiles:   1,
		InvalidFiles: 1,
		Duration:     25 * time.Millisecond,
		Files: []FileValidationResult{
			{Path: "valid.sql", Valid: true},
			{Path: "error.sql", Valid: false, Error: errors.New("test error")},
		},
	}

	comment := FormatPRComment(result)

	// Verify markdown structure
	tests := []struct {
		name    string
		pattern string
	}{
		{"has level 2 header", "## "},
		{"has level 3 header", "### "},
		{"has level 4 header", "#### "},
		{"has table", "| Metric | Value |"},
		{"has table separator", "|--------|-------|"},
		{"has code block", "```"},
		{"has horizontal rule", "---"},
		{"has bold text", "**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(comment, tt.pattern) {
				t.Errorf("FormatPRComment() missing markdown element: %s", tt.name)
			}
		})
	}
}
