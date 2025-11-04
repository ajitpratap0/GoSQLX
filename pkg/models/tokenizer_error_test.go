package models

import (
	"strings"
	"testing"
)

func TestTokenizerError(t *testing.T) {
	tests := []struct {
		name         string
		err          TokenizerError
		wantMessage  string
		wantLocation Location
	}{
		{
			name: "unexpected character error",
			err: TokenizerError{
				Message:  "unexpected character '!' at line 1, column 10",
				Location: Location{Line: 1, Column: 10},
			},
			wantMessage:  "unexpected character '!' at line 1, column 10",
			wantLocation: Location{Line: 1, Column: 10},
		},
		{
			name: "unterminated string error",
			err: TokenizerError{
				Message:  "unterminated string literal",
				Location: Location{Line: 3, Column: 15},
			},
			wantMessage:  "unterminated string literal",
			wantLocation: Location{Line: 3, Column: 15},
		},
		{
			name: "invalid number error",
			err: TokenizerError{
				Message:  "invalid numeric literal",
				Location: Location{Line: 5, Column: 20},
			},
			wantMessage:  "invalid numeric literal",
			wantLocation: Location{Line: 5, Column: 20},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Message != tt.wantMessage {
				t.Errorf("TokenizerError.Message = %v, want %v", tt.err.Message, tt.wantMessage)
			}
			if tt.err.Location != tt.wantLocation {
				t.Errorf("TokenizerError.Location = %v, want %v", tt.err.Location, tt.wantLocation)
			}
		})
	}
}

func TestTokenizerError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     TokenizerError
		wantMsg string
	}{
		{
			name: "simple error",
			err: TokenizerError{
				Message:  "test error",
				Location: Location{Line: 1, Column: 10},
			},
			wantMsg: "test error",
		},
		{
			name: "error with location info",
			err: TokenizerError{
				Message:  "unexpected character '!' at line 5, column 20",
				Location: Location{Line: 5, Column: 20},
			},
			wantMsg: "unexpected character '!' at line 5, column 20",
		},
		{
			name: "error with empty message",
			err: TokenizerError{
				Message:  "",
				Location: Location{Line: 1, Column: 1},
			},
			wantMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.wantMsg {
				t.Errorf("TokenizerError.Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestTokenizerErrorImplementsError(t *testing.T) {
	// Verify that TokenizerError implements the error interface
	var _ error = TokenizerError{}
	var _ error = &TokenizerError{}
}

func TestTokenizerErrorAsError(t *testing.T) {
	err := TokenizerError{
		Message:  "test error",
		Location: Location{Line: 1, Column: 10},
	}

	// Test that it can be used as an error
	var e error = err
	if e.Error() != "test error" {
		t.Errorf("Error interface method returned %v, want 'test error'", e.Error())
	}
}

func TestTokenizerErrorEquality(t *testing.T) {
	err1 := TokenizerError{
		Message:  "test error",
		Location: Location{Line: 1, Column: 10},
	}

	err2 := TokenizerError{
		Message:  "test error",
		Location: Location{Line: 1, Column: 10},
	}

	err3 := TokenizerError{
		Message:  "different error",
		Location: Location{Line: 1, Column: 10},
	}

	// Test equality
	if err1 != err2 {
		t.Error("Expected err1 == err2")
	}

	if err1 == err3 {
		t.Error("Expected err1 != err3")
	}
}

func TestTokenizerErrorFields(t *testing.T) {
	err := TokenizerError{
		Message:  "unexpected character",
		Location: Location{Line: 10, Column: 25},
	}

	// Test that fields are accessible
	if err.Message != "unexpected character" {
		t.Errorf("Message field = %v, want 'unexpected character'", err.Message)
	}

	if err.Location.Line != 10 {
		t.Errorf("Location.Line = %d, want 10", err.Location.Line)
	}

	if err.Location.Column != 25 {
		t.Errorf("Location.Column = %d, want 25", err.Location.Column)
	}
}

func TestTokenizerErrorWithComplexMessage(t *testing.T) {
	longMessage := strings.Repeat("error ", 100)
	err := TokenizerError{
		Message:  longMessage,
		Location: Location{Line: 1, Column: 1},
	}

	if err.Error() != longMessage {
		t.Error("Error() should return the full message even if it's long")
	}
}

func TestTokenizerErrorZeroValue(t *testing.T) {
	var err TokenizerError

	if err.Message != "" {
		t.Errorf("Zero value Message = %v, want empty string", err.Message)
	}

	if err.Location.Line != 0 || err.Location.Column != 0 {
		t.Errorf("Zero value Location = %v, want zero location", err.Location)
	}

	if err.Error() != "" {
		t.Errorf("Zero value Error() = %v, want empty string", err.Error())
	}
}

func BenchmarkTokenizerError(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TokenizerError{
			Message:  "test error",
			Location: Location{Line: 1, Column: 10},
		}
	}
}

func BenchmarkTokenizerError_Error(b *testing.B) {
	err := TokenizerError{
		Message:  "test error",
		Location: Location{Line: 1, Column: 10},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = err.Error()
	}
}
