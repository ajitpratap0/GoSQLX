package errors

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains []string // Substrings that should be in the error message
	}{
		{
			name: "basic error without context",
			err: &Error{
				Code:     ErrCodeUnexpectedToken,
				Message:  "unexpected token: IDENT",
				Location: models.Location{Line: 1, Column: 10},
			},
			contains: []string{
				"Error E2001",
				"line 1, column 10",
				"unexpected token: IDENT",
			},
		},
		{
			name: "error with hint",
			err: &Error{
				Code:     ErrCodeExpectedToken,
				Message:  "expected FROM, got FORM",
				Location: models.Location{Line: 1, Column: 10},
				Hint:     "Did you mean 'FROM'?",
			},
			contains: []string{
				"Error E2002",
				"Hint: Did you mean 'FROM'?",
			},
		},
		{
			name: "error with help URL",
			err: &Error{
				Code:     ErrCodeUnexpectedToken,
				Message:  "unexpected token",
				Location: models.Location{Line: 1, Column: 5},
				HelpURL:  "https://docs.gosqlx.dev/errors/E2001",
			},
			contains: []string{
				"Help: https://docs.gosqlx.dev/errors/E2001",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("Error() output missing expected substring:\nwant substring: %s\ngot: %s", substr, got)
				}
			}
		})
	}
}

func TestError_WithContext(t *testing.T) {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	err := NewError(ErrCodeExpectedToken, "expected FROM, got FORM", location)
	err.WithContext(sql, 4) // Highlight "FORM" (4 characters)

	output := err.Error()

	// Should contain the SQL line
	if !strings.Contains(output, sql) {
		t.Errorf("Error output should contain SQL line, got: %s", output)
	}

	// Should contain position indicator
	if !strings.Contains(output, "^") {
		t.Errorf("Error output should contain position indicator (^), got: %s", output)
	}

	// Should highlight the correct length
	if !strings.Contains(output, "^^^^") {
		t.Errorf("Error output should highlight 4 characters (^^^^), got: %s", output)
	}
}

func TestError_WithHint(t *testing.T) {
	err := NewError(ErrCodeUnexpectedToken, "unexpected token", models.Location{Line: 1, Column: 5})
	err.WithHint("This is a helpful hint")

	if err.Hint != "This is a helpful hint" {
		t.Errorf("WithHint() failed to set hint, got: %s", err.Hint)
	}

	output := err.Error()
	if !strings.Contains(output, "Hint: This is a helpful hint") {
		t.Errorf("Error output should contain hint, got: %s", output)
	}
}

func TestNewError(t *testing.T) {
	location := models.Location{Line: 5, Column: 10}
	err := NewError(ErrCodeInvalidSyntax, "test error", location)

	if err.Code != ErrCodeInvalidSyntax {
		t.Errorf("NewError() code = %v, want %v", err.Code, ErrCodeInvalidSyntax)
	}
	if err.Message != "test error" {
		t.Errorf("NewError() message = %v, want %v", err.Message, "test error")
	}
	if err.Location != location {
		t.Errorf("NewError() location = %v, want %v", err.Location, location)
	}
	if !strings.Contains(err.HelpURL, string(ErrCodeInvalidSyntax)) {
		t.Errorf("NewError() HelpURL should contain error code, got: %s", err.HelpURL)
	}
}

func TestIsCode(t *testing.T) {
	err := NewError(ErrCodeExpectedToken, "test", models.Location{})

	if !IsCode(err, ErrCodeExpectedToken) {
		t.Error("IsCode() should return true for matching code")
	}

	if IsCode(err, ErrCodeUnexpectedToken) {
		t.Error("IsCode() should return false for non-matching code")
	}

	// Test with non-structured error
	if IsCode(nil, ErrCodeExpectedToken) {
		t.Error("IsCode() should return false for nil error")
	}
}

func TestGetCode(t *testing.T) {
	err := NewError(ErrCodeUnexpectedToken, "test", models.Location{})

	code := GetCode(err)
	if code != ErrCodeUnexpectedToken {
		t.Errorf("GetCode() = %v, want %v", code, ErrCodeUnexpectedToken)
	}

	// Test with nil
	code = GetCode(nil)
	if code != "" {
		t.Errorf("GetCode(nil) = %v, want empty string", code)
	}
}

func TestError_FormatContext(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		location models.Location
		wantLine string
		wantPos  bool // Should have position indicator
	}{
		{
			name:     "single line SQL",
			sql:      "SELECT * FROM users",
			location: models.Location{Line: 1, Column: 10},
			wantLine: "SELECT * FROM users",
			wantPos:  true,
		},
		{
			name: "multi-line SQL",
			sql: `SELECT *
FROM users
WHERE age > 18`,
			location: models.Location{Line: 2, Column: 6},
			wantLine: "FROM users",
			wantPos:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(ErrCodeUnexpectedToken, "test", tt.location)
			err.WithContext(tt.sql, 1)

			output := err.formatContext()

			if !strings.Contains(output, tt.wantLine) {
				t.Errorf("formatContext() should contain line %q, got: %s", tt.wantLine, output)
			}

			if tt.wantPos && !strings.Contains(output, "^") {
				t.Errorf("formatContext() should contain position indicator, got: %s", output)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	causeErr := NewError(ErrCodeInvalidSyntax, "cause error", models.Location{})
	err := NewError(ErrCodeUnexpectedToken, "wrapper error", models.Location{})
	err.WithCause(causeErr)

	unwrapped := err.Unwrap()
	if unwrapped != causeErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, causeErr)
	}
}
