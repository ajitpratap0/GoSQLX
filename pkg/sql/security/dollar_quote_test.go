package security

import "testing"

func TestStripDollarQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no dollar quotes", "SELECT 1", "SELECT 1"},
		{"basic empty tag", "SELECT $$hello$$ FROM t", "SELECT $$$$ FROM t"},
		{"named tag", "SELECT $fn$body$fn$ FROM t", "SELECT $fn$$fn$ FROM t"},
		{"nested", "$$outer $inner$x$inner$ outer$$", "$$$$"},
		{"unterminated", "$$hello", "$$hello"},
		{"multiple", "$$a$$ AND $$b$$", "$$$$ AND $$$$"},
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

func TestScanSQL_DollarQuotedInjectionBypass(t *testing.T) {
	scanner := NewScanner()

	// Injection hidden inside dollar-quoted string should NOT trigger
	result := scanner.ScanSQL(`SELECT $$SLEEP(5)$$ FROM t`)
	if result.HasHighOrAbove() {
		t.Error("should not detect injection inside dollar-quoted string content")
	}

	// Injection outside dollar-quoted string SHOULD trigger
	result = scanner.ScanSQL(`SELECT $$safe$$ FROM t; DROP TABLE users --`)
	if !result.HasHighOrAbove() {
		t.Error("should detect injection outside dollar-quoted string")
	}
}

func TestScanSQL_DollarQuotedUnionBypass(t *testing.T) {
	scanner := NewScanner()

	// UNION SELECT hidden inside dollar-quoted string
	result := scanner.ScanSQL(`SELECT $body$UNION SELECT password FROM users$body$ FROM t`)
	for _, f := range result.Findings {
		if f.Pattern == PatternUnionBased {
			t.Error("should not detect UNION injection inside dollar-quoted string")
		}
	}
}
