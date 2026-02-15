package formatter

import (
	"strings"
	"testing"
)

func TestFormat_BasicStatements(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple select", "SELECT id, name FROM users", false},
		{"select with where", "SELECT * FROM users WHERE id = 1", false},
		{"insert", "INSERT INTO users (id, name) VALUES (1, 'test')", false},
		{"update", "UPDATE users SET name = 'new' WHERE id = 1", false},
		{"delete", "DELETE FROM users WHERE id = 1", false},
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"invalid SQL", "SELEC BOGUS FROM", true},
	}

	f := New(Options{IndentSize: 2})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := f.Format(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Format() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.input != "" && tt.input != "   " && result == "" {
				t.Error("Format() returned empty string for valid non-empty SQL")
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	result, err := FormatString("SELECT 1")
	if err != nil {
		t.Fatalf("FormatString() error = %v", err)
	}
	if result == "" {
		t.Error("FormatString() returned empty")
	}
}

func TestNew_DefaultIndent(t *testing.T) {
	f := New(Options{})
	if f.opts.IndentSize != 2 {
		t.Errorf("default IndentSize = %d, want 2", f.opts.IndentSize)
	}
}

func TestFormat_UppercaseOutput(t *testing.T) {
	f := New(Options{Uppercase: true})
	result, err := f.Format("select id from users")
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.Contains(result, "SELECT") {
		t.Errorf("Expected uppercase SELECT in output, got: %s", result)
	}
	if !strings.Contains(result, "FROM") {
		t.Errorf("Expected uppercase FROM in output, got: %s", result)
	}
}

func TestFormat_CompactOutput(t *testing.T) {
	f := New(Options{Compact: true})
	result, err := f.Format("SELECT id, name FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if strings.Contains(result, "\n") {
		t.Errorf("Compact mode should not contain newlines, got: %s", result)
	}
}
