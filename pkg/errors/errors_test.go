// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
				HelpURL:  "https://github.com/ajitpratap0/GoSQLX/blob/main/docs/ERROR_CODES.md#E2001",
			},
			contains: []string{
				"Help: https://github.com/ajitpratap0/GoSQLX/blob/main/docs/ERROR_CODES.md#E2001",
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
	err = err.WithContext(sql, 4) // Highlight "FORM" (4 characters)

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
	err = err.WithHint("This is a helpful hint")

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
			err = err.WithContext(tt.sql, 1)

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
	err = err.WithCause(causeErr)

	unwrapped := err.Unwrap()
	if unwrapped != causeErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, causeErr)
	}
}

// TestError_WithContext_Immutable verifies WithContext does not mutate the
// receiver: the original *Error is unchanged, and the returned *Error carries
// the new Context. Guards against H6 regressions (observer effects across
// call sites that share a *Error pointer).
func TestError_WithContext_Immutable(t *testing.T) {
	orig := NewError(ErrCodeUnexpectedToken, "msg", models.Location{Line: 1, Column: 5})
	if orig.Context != nil {
		t.Fatalf("precondition: fresh error should have nil Context, got %+v", orig.Context)
	}

	withCtx := orig.WithContext("SELECT * FORM users", 4)

	if orig.Context != nil {
		t.Fatalf("WithContext mutated the receiver: orig.Context = %+v", orig.Context)
	}
	if withCtx.Context == nil {
		t.Fatalf("WithContext returned error without Context set")
	}
	if withCtx.Context.SQL != "SELECT * FORM users" {
		t.Errorf("returned Context.SQL = %q, want %q", withCtx.Context.SQL, "SELECT * FORM users")
	}
	if withCtx.Context.HighlightLen != 4 {
		t.Errorf("returned Context.HighlightLen = %d, want 4", withCtx.Context.HighlightLen)
	}
	if orig == withCtx {
		t.Errorf("WithContext returned the same pointer; expected a copy")
	}
}

// TestError_WithHint_Immutable verifies WithHint does not mutate the receiver.
func TestError_WithHint_Immutable(t *testing.T) {
	orig := NewError(ErrCodeUnexpectedToken, "msg", models.Location{Line: 1, Column: 5})
	if orig.Hint != "" {
		t.Fatalf("precondition: fresh error should have empty Hint, got %q", orig.Hint)
	}

	withHint := orig.WithHint("new hint")

	if orig.Hint == "new hint" {
		t.Fatal("WithHint mutated the receiver")
	}
	if orig.Hint != "" {
		t.Fatalf("receiver Hint unexpectedly changed: %q", orig.Hint)
	}
	if withHint.Hint != "new hint" {
		t.Fatalf("returned Error missing hint, got %q", withHint.Hint)
	}
	if orig == withHint {
		t.Errorf("WithHint returned the same pointer; expected a copy")
	}
}

// TestError_WithCause_Immutable verifies WithCause does not mutate the receiver.
func TestError_WithCause_Immutable(t *testing.T) {
	cause := NewError(ErrCodeInvalidSyntax, "root", models.Location{})
	orig := NewError(ErrCodeUnexpectedToken, "wrapper", models.Location{})
	if orig.Cause != nil {
		t.Fatalf("precondition: fresh error should have nil Cause, got %v", orig.Cause)
	}

	withCause := orig.WithCause(cause)

	if orig.Cause != nil {
		t.Fatalf("WithCause mutated the receiver: orig.Cause = %v", orig.Cause)
	}
	if withCause.Cause != cause {
		t.Fatalf("returned Error missing cause; got %v, want %v", withCause.Cause, cause)
	}
	if orig == withCause {
		t.Errorf("WithCause returned the same pointer; expected a copy")
	}
}

// TestError_WithX_SharedReceiver_NoObserverEffects simulates the production
// bug: two call sites holding the same *Error pointer. Before the fix, one
// call site's WithHint would be visible to the other. After the fix, each
// caller gets an independent copy.
func TestError_WithX_SharedReceiver_NoObserverEffects(t *testing.T) {
	shared := NewError(ErrCodeUnexpectedToken, "msg", models.Location{Line: 1, Column: 1})

	a := shared.WithHint("hint from A")
	b := shared.WithHint("hint from B")

	if shared.Hint != "" {
		t.Fatalf("shared receiver was mutated: shared.Hint = %q", shared.Hint)
	}
	if a.Hint != "hint from A" {
		t.Errorf("a.Hint = %q, want %q", a.Hint, "hint from A")
	}
	if b.Hint != "hint from B" {
		t.Errorf("b.Hint = %q, want %q", b.Hint, "hint from B")
	}
	if a == b {
		t.Errorf("both call sites got the same pointer; expected independent copies")
	}
}

// TestError_WithX_Chaining verifies the `err = err.WithA(...).WithB(...)`
// fluent pattern still accumulates all fields on the final returned error.
func TestError_WithX_Chaining(t *testing.T) {
	cause := NewError(ErrCodeInvalidSyntax, "root", models.Location{})
	err := NewError(ErrCodeUnexpectedToken, "msg", models.Location{Line: 2, Column: 3}).
		WithContext("SELECT 1", 1).
		WithHint("a hint").
		WithCause(cause)

	if err.Context == nil || err.Context.SQL != "SELECT 1" {
		t.Errorf("chained WithContext not applied: %+v", err.Context)
	}
	if err.Hint != "a hint" {
		t.Errorf("chained WithHint not applied: %q", err.Hint)
	}
	if err.Cause != cause {
		t.Errorf("chained WithCause not applied: %v", err.Cause)
	}
}
