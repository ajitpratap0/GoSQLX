package security

import (
	"testing"
)

func TestStripDollarQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no dollar strings", "SELECT 1", "SELECT 1"},
		{"empty content", "$$$$", "$$$$"},
		{"simple content", "$$hello$$", "$$$$"},
		{"tagged", "$tag$content$tag$", "$tag$$tag$"},
		{"preserves surrounding", "SELECT $$DROP TABLE$$ FROM t", "SELECT $$$$ FROM t"},
		{"unterminated passthrough", "$$unterminated", "$$unterminated"},
		{"standalone dollar", "SELECT $1", "SELECT $1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripDollarQuotedStrings(tt.input)
			if got != tt.expected {
				t.Errorf("stripDollarQuotedStrings(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestScanSQL_DollarQuotedNoFalsePositives(t *testing.T) {
	scanner := NewScanner()

	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "DROP TABLE inside dollar-quoted string",
			sql:  "SELECT $$DROP TABLE users; DELETE FROM accounts$$ AS body",
		},
		{
			name: "UNION SELECT inside dollar-quoted string",
			sql:  "SELECT $fn$SELECT 1 UNION SELECT 2$fn$ AS query_text",
		},
		{
			name: "Comment patterns inside dollar-quoted string",
			sql:  "SELECT $$this has -- comments and /* blocks */$$ AS val",
		},
		{
			name: "Sleep function inside dollar-quoted string",
			sql:  "SELECT $$pg_sleep(10)$$ AS example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.ScanSQL(tt.sql)
			if len(result.Findings) > 0 {
				for _, f := range result.Findings {
					t.Errorf("unexpected finding: [%s] %s: %s", f.Severity, f.Pattern, f.Description)
				}
			}
		})
	}
}
