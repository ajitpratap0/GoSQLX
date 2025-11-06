package errors

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestFormatErrorWithContext(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sql      string
		contains []string
	}{
		{
			name: "structured error",
			err: NewError(ErrCodeUnexpectedToken, "unexpected token: IDENT", models.Location{Line: 1, Column: 10}).
				WithContext("SELECT * FORM users", 4),
			sql: "SELECT * FORM users",
			contains: []string{
				"Error E2001",
				"line 1, column 10",
				"unexpected token",
				"SELECT * FORM users",
				"^",
			},
		},
		{
			name: "non-structured error",
			err:  fmt.Errorf("simple error"),
			sql:  "SELECT * FROM users",
			contains: []string{
				"Error:",
				"simple error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatErrorWithContext(tt.err, tt.sql)
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatErrorWithContext() missing substring %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func TestFormatErrorWithContextAt(t *testing.T) {
	tests := []struct {
		name         string
		code         ErrorCode
		message      string
		location     models.Location
		sql          string
		highlightLen int
		wantContains []string
	}{
		{
			name:         "simple error",
			code:         ErrCodeExpectedToken,
			message:      "expected FROM, got FORM",
			location:     models.Location{Line: 1, Column: 10},
			sql:          "SELECT * FORM users",
			highlightLen: 4,
			wantContains: []string{
				"E2002",
				"expected FROM, got FORM",
				"line 1, column 10",
				"^^^^",
			},
		},
		{
			name:         "multi-line SQL",
			code:         ErrCodeUnexpectedToken,
			message:      "unexpected token",
			location:     models.Location{Line: 2, Column: 1},
			sql:          "SELECT *\nFORM users\nWHERE age > 18",
			highlightLen: 4,
			wantContains: []string{
				"E2001",
				"FORM users",
				"line 2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatErrorWithContextAt(tt.code, tt.message, tt.location, tt.sql, tt.highlightLen)
			for _, substr := range tt.wantContains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatErrorWithContextAt() missing substring %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func TestFormatMultiLineContext(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		location     models.Location
		highlightLen int
		wantContains []string
		wantLines    int // Expected number of SQL lines in output
	}{
		{
			name: "error on middle line",
			sql: `SELECT *
FROM users
WHERE age > 18`,
			location:     models.Location{Line: 2, Column: 6},
			highlightLen: 5,
			wantContains: []string{
				"SELECT *",
				"FROM users",
				"WHERE age > 18",
				"^^^^^",
			},
			wantLines: 3,
		},
		{
			name: "error on first line",
			sql: `SELECT * FORM users
WHERE age > 18`,
			location:     models.Location{Line: 1, Column: 10},
			highlightLen: 4,
			wantContains: []string{
				"SELECT * FORM users",
				"WHERE age > 18",
				"^^^^",
			},
			wantLines: 2,
		},
		{
			name:         "single line",
			sql:          "SELECT * FORM users",
			location:     models.Location{Line: 1, Column: 10},
			highlightLen: 4,
			wantContains: []string{
				"SELECT * FORM users",
				"^^^^",
			},
			wantLines: 1,
		},
		{
			name:         "invalid line number",
			sql:          "SELECT * FROM users",
			location:     models.Location{Line: 99, Column: 1},
			highlightLen: 1,
			wantContains: []string{},
			wantLines:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatMultiLineContext(tt.sql, tt.location, tt.highlightLen)

			for _, substr := range tt.wantContains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatMultiLineContext() missing substring %q\nGot:\n%s", substr, got)
				}
			}

			// Verify we have the right structure if wantLines > 0
			if tt.wantLines > 0 && !strings.Contains(got, "|") {
				t.Errorf("FormatMultiLineContext() should contain line number separator '|'\nGot:\n%s", got)
			}
		})
	}
}

func TestFormatErrorSummary(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode bool
		contains []string
	}{
		{
			name:     "structured error",
			err:      NewError(ErrCodeUnexpectedToken, "unexpected token", models.Location{Line: 5, Column: 10}),
			wantCode: true,
			contains: []string{
				"[E2001]",
				"unexpected token",
				"line 5, column 10",
			},
		},
		{
			name:     "simple error",
			err:      fmt.Errorf("simple error"),
			wantCode: false,
			contains: []string{
				"Error:",
				"simple error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatErrorSummary(tt.err)

			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatErrorSummary() missing substring %q\nGot: %s", substr, got)
				}
			}

			if tt.wantCode && !strings.Contains(got, "[E") {
				t.Errorf("FormatErrorSummary() should contain error code [E*]\nGot: %s", got)
			}
		})
	}
}

func TestFormatErrorWithSuggestion(t *testing.T) {
	tests := []struct {
		name       string
		code       ErrorCode
		message    string
		location   models.Location
		sql        string
		suggestion string
		wantHint   bool
	}{
		{
			name:       "custom suggestion",
			code:       ErrCodeExpectedToken,
			message:    "expected FROM",
			location:   models.Location{Line: 1, Column: 10},
			sql:        "SELECT * FORM users",
			suggestion: "Use FROM instead of FORM",
			wantHint:   true,
		},
		{
			name:       "auto-generated suggestion",
			code:       ErrCodeUnterminatedString,
			message:    "unterminated string",
			location:   models.Location{Line: 1, Column: 30},
			sql:        "SELECT * FROM users WHERE name = 'John",
			suggestion: "",
			wantHint:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatErrorWithSuggestion(tt.code, tt.message, tt.location, tt.sql, 1, tt.suggestion)

			if tt.wantHint && !strings.Contains(got, "Hint:") {
				t.Errorf("FormatErrorWithSuggestion() should contain hint\nGot:\n%s", got)
			}

			if tt.suggestion != "" && !strings.Contains(got, tt.suggestion) {
				t.Errorf("FormatErrorWithSuggestion() should contain custom suggestion\nGot:\n%s", got)
			}
		})
	}
}

func TestFormatErrorList(t *testing.T) {
	tests := []struct {
		name     string
		errors   []*Error
		contains []string
	}{
		{
			name:     "empty list",
			errors:   []*Error{},
			contains: []string{"No errors"},
		},
		{
			name: "single error",
			errors: []*Error{
				NewError(ErrCodeUnexpectedToken, "error 1", models.Location{Line: 1, Column: 1}),
			},
			contains: []string{
				"Found 1 error(s)",
				"Error 1:",
				"error 1",
			},
		},
		{
			name: "multiple errors",
			errors: []*Error{
				NewError(ErrCodeUnexpectedToken, "error 1", models.Location{Line: 1, Column: 1}),
				NewError(ErrCodeExpectedToken, "error 2", models.Location{Line: 2, Column: 5}),
			},
			contains: []string{
				"Found 2 error(s)",
				"Error 1:",
				"Error 2:",
				"error 1",
				"error 2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatErrorList(tt.errors)
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatErrorList() missing substring %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func TestFormatErrorWithExample(t *testing.T) {
	got := FormatErrorWithExample(
		ErrCodeExpectedToken,
		"expected FROM, got FORM",
		models.Location{Line: 1, Column: 10},
		"SELECT * FORM users",
		4,
		"SELECT * FORM users",
		"SELECT * FROM users",
	)

	requiredParts := []string{
		"expected FROM, got FORM",
		"Wrong:",
		"SELECT * FORM users",
		"Correct:",
		"SELECT * FROM users",
		"Hint:",
	}

	for _, part := range requiredParts {
		if !strings.Contains(got, part) {
			t.Errorf("FormatErrorWithExample() missing %q\nGot:\n%s", part, got)
		}
	}
}

func TestFormatContextWindow(t *testing.T) {
	sql := `SELECT id, name, email
FROM users
WHERE age > 18
  AND status = 'active'
  AND created_at > '2023-01-01'
ORDER BY name`

	tests := []struct {
		name         string
		location     models.Location
		linesBefore  int
		linesAfter   int
		wantContains []string
		wantMissing  []string
	}{
		{
			name:        "1 line before and after",
			location:    models.Location{Line: 3, Column: 7},
			linesBefore: 1,
			linesAfter:  1,
			wantContains: []string{
				"FROM users",
				"WHERE age > 18",
				"AND status = 'active'",
			},
			wantMissing: []string{
				"SELECT id",
				"ORDER BY",
			},
		},
		{
			name:        "2 lines before and after",
			location:    models.Location{Line: 3, Column: 7},
			linesBefore: 2,
			linesAfter:  2,
			wantContains: []string{
				"SELECT id, name, email",
				"FROM users",
				"WHERE age > 18",
				"AND status = 'active'",
				"AND created_at",
			},
			wantMissing: []string{
				"ORDER BY",
			},
		},
		{
			name:        "error on first line",
			location:    models.Location{Line: 1, Column: 1},
			linesBefore: 2,
			linesAfter:  1,
			wantContains: []string{
				"SELECT id, name, email",
				"FROM users",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatContextWindow(sql, tt.location, 3, tt.linesBefore, tt.linesAfter)

			for _, substr := range tt.wantContains {
				if !strings.Contains(got, substr) {
					t.Errorf("FormatContextWindow() missing substring %q\nGot:\n%s", substr, got)
				}
			}

			for _, substr := range tt.wantMissing {
				if strings.Contains(got, substr) {
					t.Errorf("FormatContextWindow() should not contain %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func TestIsStructuredError(t *testing.T) {
	structErr := NewError(ErrCodeUnexpectedToken, "test", models.Location{})
	simpleErr := fmt.Errorf("simple error")

	if !IsStructuredError(structErr) {
		t.Error("IsStructuredError() should return true for structured error")
	}

	if IsStructuredError(simpleErr) {
		t.Error("IsStructuredError() should return false for simple error")
	}

	if IsStructuredError(nil) {
		t.Error("IsStructuredError() should return false for nil")
	}
}

func TestExtractLocation(t *testing.T) {
	location := models.Location{Line: 5, Column: 10}
	structErr := NewError(ErrCodeUnexpectedToken, "test", location)
	simpleErr := fmt.Errorf("simple error")

	// Test with structured error
	gotLoc, ok := ExtractLocation(structErr)
	if !ok {
		t.Error("ExtractLocation() should return true for structured error")
	}
	if gotLoc != location {
		t.Errorf("ExtractLocation() location = %v, want %v", gotLoc, location)
	}

	// Test with simple error
	_, ok = ExtractLocation(simpleErr)
	if ok {
		t.Error("ExtractLocation() should return false for simple error")
	}
}

func TestExtractErrorCode(t *testing.T) {
	structErr := NewError(ErrCodeUnexpectedToken, "test", models.Location{})
	simpleErr := fmt.Errorf("simple error")

	// Test with structured error
	code, ok := ExtractErrorCode(structErr)
	if !ok {
		t.Error("ExtractErrorCode() should return true for structured error")
	}
	if code != ErrCodeUnexpectedToken {
		t.Errorf("ExtractErrorCode() code = %v, want %v", code, ErrCodeUnexpectedToken)
	}

	// Test with simple error
	_, ok = ExtractErrorCode(simpleErr)
	if ok {
		t.Error("ExtractErrorCode() should return false for simple error")
	}
}

func TestFormatErrorWithUnicode(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		location models.Location
		contains []string
	}{
		{
			name:     "Chinese SQL",
			sql:      "SELECT * FROM 用户表 WHERE 姓名 = '张三'",
			location: models.Location{Line: 1, Column: 15},
			contains: []string{
				"用户表",
				"^",
			},
		},
		{
			name:     "Japanese SQL",
			sql:      "SELECT * FROM テーブル WHERE 名前 = '太郎'",
			location: models.Location{Line: 1, Column: 15},
			contains: []string{
				"テーブル",
				"^",
			},
		},
		{
			name:     "Arabic SQL",
			sql:      "SELECT * FROM جدول WHERE اسم = 'أحمد'",
			location: models.Location{Line: 1, Column: 15},
			contains: []string{
				"جدول",
				"^",
			},
		},
		{
			name:     "Emoji in SQL",
			sql:      "SELECT * FROM users WHERE status = '✅'",
			location: models.Location{Line: 1, Column: 37},
			contains: []string{
				"✅",
				"^",
			},
		},
		{
			name: "Multi-line Unicode",
			sql: `SELECT *
FROM 用户表
WHERE 年龄 > 18`,
			location: models.Location{Line: 2, Column: 6},
			contains: []string{
				"用户表",
				"^",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(ErrCodeUnexpectedToken, "test error", tt.location)
			err.WithContext(tt.sql, 1)

			got := err.Error()

			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("Unicode error formatting missing substring %q\nGot:\n%s", substr, got)
				}
			}
		})
	}
}

func BenchmarkFormatErrorWithContext(b *testing.B) {
	err := NewError(ErrCodeUnexpectedToken, "unexpected token", models.Location{Line: 1, Column: 10}).
		WithContext("SELECT * FORM users WHERE age > 18", 4)
	sql := "SELECT * FORM users WHERE age > 18"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatErrorWithContext(err, sql)
	}
}

func BenchmarkFormatMultiLineContext(b *testing.B) {
	sql := `SELECT id, name, email
FROM users
WHERE age > 18
  AND status = 'active'
ORDER BY name`
	location := models.Location{Line: 3, Column: 7}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatMultiLineContext(sql, location, 5)
	}
}

func BenchmarkFormatContextWindow(b *testing.B) {
	sql := `SELECT id, name, email
FROM users
WHERE age > 18
  AND status = 'active'
  AND created_at > '2023-01-01'
ORDER BY name`
	location := models.Location{Line: 3, Column: 7}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatContextWindow(sql, location, 3, 2, 2)
	}
}
