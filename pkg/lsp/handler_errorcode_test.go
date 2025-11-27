package lsp

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestCreateDiagnosticFromError_WithStructuredError tests that error codes
// are extracted from structured errors
func TestCreateDiagnosticFromError_WithStructuredError(t *testing.T) {
	h := &Handler{}

	// Create a structured error with error code and location
	structuredErr := &errors.Error{
		Code:    errors.ErrCodeUnexpectedToken,
		Message: "unexpected token SELECT",
		Location: models.Location{
			Line:   5,
			Column: 10,
		},
	}

	content := "SELECT * FROM users\nWHERE id = 1\nAND name = 'test'\nORDER BY created_at\nSELECT invalid syntax"

	diag := h.createDiagnosticFromError(content, structuredErr, 0)

	// Verify error code is included
	if diag.Code == nil {
		t.Error("Expected error code to be set, got nil")
	}

	codeStr, ok := diag.Code.(string)
	if !ok {
		t.Errorf("Expected error code to be string, got %T", diag.Code)
	}

	if codeStr != string(errors.ErrCodeUnexpectedToken) {
		t.Errorf("Expected error code %s, got %s", errors.ErrCodeUnexpectedToken, codeStr)
	}

	// Verify position is correct (converted to 0-based)
	expectedLine := 4 // Line 5 in 1-based becomes 4 in 0-based
	if diag.Range.Start.Line != expectedLine {
		t.Errorf("Expected line %d, got %d", expectedLine, diag.Range.Start.Line)
	}

	expectedChar := 9 // Column 10 in 1-based becomes 9 in 0-based
	if diag.Range.Start.Character != expectedChar {
		t.Errorf("Expected character %d, got %d", expectedChar, diag.Range.Start.Character)
	}

	// Verify message is the clean message without context
	if diag.Message != structuredErr.Message {
		t.Errorf("Expected message '%s', got '%s'", structuredErr.Message, diag.Message)
	}

	// Verify severity is error
	if diag.Severity != SeverityError {
		t.Errorf("Expected severity %d, got %d", SeverityError, diag.Severity)
	}

	// Verify source
	if diag.Source != "gosqlx" {
		t.Errorf("Expected source 'gosqlx', got '%s'", diag.Source)
	}
}

// TestCreateDiagnosticFromError_WithPlainError tests that plain errors
// without structured error codes still work
func TestCreateDiagnosticFromError_WithPlainError(t *testing.T) {
	h := &Handler{}

	// Create a plain error (simulating wrapped error or non-GoSQLX error)
	plainErr := errors.NewError(errors.ErrCodeInvalidSyntax, "syntax error near FROM", models.Location{Line: 1, Column: 8})

	content := "SELECT FROM users"

	diag := h.createDiagnosticFromError(content, plainErr, 0)

	// Verify error code is included for plain structured errors
	if diag.Code == nil {
		t.Error("Expected error code to be set, got nil")
	}

	codeStr, ok := diag.Code.(string)
	if !ok {
		t.Errorf("Expected error code to be string, got %T", diag.Code)
	}

	if codeStr != string(errors.ErrCodeInvalidSyntax) {
		t.Errorf("Expected error code %s, got %s", errors.ErrCodeInvalidSyntax, codeStr)
	}
}

// TestCreateDiagnosticFromError_EdgeCases tests edge cases
func TestCreateDiagnosticFromError_EdgeCases(t *testing.T) {
	h := &Handler{}

	tests := []struct {
		name        string
		err         error
		content     string
		defaultLine int
		expectCode  bool
	}{
		{
			name: "Structured error with line 0",
			err: &errors.Error{
				Code:     errors.ErrCodeUnexpectedChar,
				Message:  "unexpected character",
				Location: models.Location{Line: 0, Column: 0},
			},
			content:     "SELECT",
			defaultLine: 0,
			expectCode:  true,
		},
		{
			name: "Structured error with negative position (clamped to 0)",
			err: &errors.Error{
				Code:     errors.ErrCodeUnexpectedChar,
				Message:  "unexpected character",
				Location: models.Location{Line: -1, Column: -5},
			},
			content:     "SELECT",
			defaultLine: 0,
			expectCode:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diag := h.createDiagnosticFromError(tt.content, tt.err, tt.defaultLine)

			if tt.expectCode {
				if diag.Code == nil {
					t.Error("Expected error code to be set, got nil")
				}
			}

			// Verify position is never negative
			if diag.Range.Start.Line < 0 {
				t.Errorf("Line should be >= 0, got %d", diag.Range.Start.Line)
			}
			if diag.Range.Start.Character < 0 {
				t.Errorf("Character should be >= 0, got %d", diag.Range.Start.Character)
			}
		})
	}
}
