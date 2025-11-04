package errors

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestUnexpectedCharError(t *testing.T) {
	sql := "SELECT * FROM users WHERE name = 'John' & age > 18"
	location := models.Location{Line: 1, Column: 39}

	err := UnexpectedCharError('&', location, sql)

	if err.Code != ErrCodeUnexpectedChar {
		t.Errorf("UnexpectedCharError() code = %v, want %v", err.Code, ErrCodeUnexpectedChar)
	}

	output := err.Error()
	if !strings.Contains(output, "unexpected character '&'") {
		t.Errorf("Error should mention the unexpected character, got: %s", output)
	}
	if !strings.Contains(output, "Hint:") {
		t.Errorf("Error should include hint, got: %s", output)
	}
}

func TestUnterminatedStringError(t *testing.T) {
	sql := "SELECT * FROM users WHERE name = 'John"
	location := models.Location{Line: 1, Column: 34}

	err := UnterminatedStringError(location, sql)

	if err.Code != ErrCodeUnterminatedString {
		t.Errorf("UnterminatedStringError() code = %v, want %v", err.Code, ErrCodeUnterminatedString)
	}

	output := err.Error()
	if !strings.Contains(output, "unterminated string") {
		t.Errorf("Error should mention unterminated string, got: %s", output)
	}
	if !strings.Contains(output, "Hint:") {
		t.Errorf("Error should include hint about closing quotes, got: %s", output)
	}
}

func TestInvalidNumberError(t *testing.T) {
	sql := "SELECT * FROM users WHERE age > 18.45.6"
	location := models.Location{Line: 1, Column: 33}

	err := InvalidNumberError("18.45.6", location, sql)

	if err.Code != ErrCodeInvalidNumber {
		t.Errorf("InvalidNumberError() code = %v, want %v", err.Code, ErrCodeInvalidNumber)
	}

	output := err.Error()
	if !strings.Contains(output, "invalid numeric literal") {
		t.Errorf("Error should mention invalid numeric literal, got: %s", output)
	}
	if !strings.Contains(output, "18.45.6") {
		t.Errorf("Error should include the invalid number, got: %s", output)
	}
}

func TestUnexpectedTokenError(t *testing.T) {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	err := UnexpectedTokenError("IDENT", "FORM", location, sql)

	if err.Code != ErrCodeUnexpectedToken {
		t.Errorf("UnexpectedTokenError() code = %v, want %v", err.Code, ErrCodeUnexpectedToken)
	}

	output := err.Error()
	if !strings.Contains(output, "unexpected token") {
		t.Errorf("Error should mention unexpected token, got: %s", output)
	}
	if !strings.Contains(output, "FORM") {
		t.Errorf("Error should include the token value, got: %s", output)
	}
	// Should suggest FROM (typo detection)
	if !strings.Contains(output, "Hint:") {
		t.Errorf("Error should include hint with suggestion, got: %s", output)
	}
}

func TestExpectedTokenError(t *testing.T) {
	sql := "SELECT * FORM users"
	location := models.Location{Line: 1, Column: 10}

	err := ExpectedTokenError("FROM", "FORM", location, sql)

	if err.Code != ErrCodeExpectedToken {
		t.Errorf("ExpectedTokenError() code = %v, want %v", err.Code, ErrCodeExpectedToken)
	}

	output := err.Error()
	if !strings.Contains(output, "expected FROM") {
		t.Errorf("Error should mention expected token, got: %s", output)
	}
	if !strings.Contains(output, "got FORM") {
		t.Errorf("Error should mention found token, got: %s", output)
	}
	// Should detect typo and suggest FROM
	if !strings.Contains(output, "Did you mean 'FROM'") {
		t.Errorf("Error should suggest correct spelling, got: %s", output)
	}
}

func TestMissingClauseError(t *testing.T) {
	sql := "SELECT * users"
	location := models.Location{Line: 1, Column: 10}

	err := MissingClauseError("FROM", location, sql)

	if err.Code != ErrCodeMissingClause {
		t.Errorf("MissingClauseError() code = %v, want %v", err.Code, ErrCodeMissingClause)
	}

	output := err.Error()
	if !strings.Contains(output, "missing required FROM clause") {
		t.Errorf("Error should mention missing clause, got: %s", output)
	}
}

func TestInvalidSyntaxError(t *testing.T) {
	sql := "SELECT * FROM WHERE"
	location := models.Location{Line: 1, Column: 15}

	err := InvalidSyntaxError("missing table name", location, sql)

	if err.Code != ErrCodeInvalidSyntax {
		t.Errorf("InvalidSyntaxError() code = %v, want %v", err.Code, ErrCodeInvalidSyntax)
	}

	output := err.Error()
	if !strings.Contains(output, "invalid syntax") {
		t.Errorf("Error should mention invalid syntax, got: %s", output)
	}
	if !strings.Contains(output, "missing table name") {
		t.Errorf("Error should include description, got: %s", output)
	}
}

func TestUnsupportedFeatureError(t *testing.T) {
	sql := "SELECT * FROM users WINDOW w AS (PARTITION BY dept)"
	location := models.Location{Line: 1, Column: 21}

	err := UnsupportedFeatureError("WINDOW clause", location, sql)

	if err.Code != ErrCodeUnsupportedFeature {
		t.Errorf("UnsupportedFeatureError() code = %v, want %v", err.Code, ErrCodeUnsupportedFeature)
	}

	output := err.Error()
	if !strings.Contains(output, "unsupported feature") {
		t.Errorf("Error should mention unsupported feature, got: %s", output)
	}
	if !strings.Contains(output, "WINDOW clause") {
		t.Errorf("Error should include feature name, got: %s", output)
	}
}

func TestIncompleteStatementError(t *testing.T) {
	sql := "SELECT * FROM"
	location := models.Location{Line: 1, Column: 14}

	err := IncompleteStatementError(location, sql)

	if err.Code != ErrCodeIncompleteStatement {
		t.Errorf("IncompleteStatementError() code = %v, want %v", err.Code, ErrCodeIncompleteStatement)
	}

	output := err.Error()
	if !strings.Contains(output, "incomplete SQL statement") {
		t.Errorf("Error should mention incomplete statement, got: %s", output)
	}
}

func TestWrapError(t *testing.T) {
	sql := "SELECT * FROM users"
	location := models.Location{Line: 1, Column: 1}
	causeErr := NewError(ErrCodeInvalidSyntax, "underlying error", location)

	err := WrapError(ErrCodeUnexpectedToken, "wrapper message", location, sql, causeErr)

	if err.Code != ErrCodeUnexpectedToken {
		t.Errorf("WrapError() code = %v, want %v", err.Code, ErrCodeUnexpectedToken)
	}

	if err.Unwrap() != causeErr {
		t.Errorf("WrapError() should preserve cause error")
	}

	output := err.Error()
	if !strings.Contains(output, "wrapper message") {
		t.Errorf("Error should contain wrapper message, got: %s", output)
	}
}

func TestAllErrorsHaveContext(t *testing.T) {
	sql := "SELECT * FROM users"
	location := models.Location{Line: 1, Column: 10}

	errorFuncs := []func() *Error{
		func() *Error { return UnexpectedCharError('!', location, sql) },
		func() *Error { return UnterminatedStringError(location, sql) },
		func() *Error { return InvalidNumberError("123.45.6", location, sql) },
		func() *Error { return UnexpectedTokenError("IDENT", "FORM", location, sql) },
		func() *Error { return ExpectedTokenError("FROM", "FORM", location, sql) },
		func() *Error { return MissingClauseError("FROM", location, sql) },
		func() *Error { return InvalidSyntaxError("test", location, sql) },
		func() *Error { return UnsupportedFeatureError("feature", location, sql) },
		func() *Error { return IncompleteStatementError(location, sql) },
	}

	for i, fn := range errorFuncs {
		err := fn()
		if err.Context == nil {
			t.Errorf("Error function %d should set context", i)
		}
		output := err.Error()
		if !strings.Contains(output, sql) {
			t.Errorf("Error function %d should include SQL in output, got: %s", i, output)
		}
	}
}

func TestAllErrorsHaveHelpURL(t *testing.T) {
	location := models.Location{Line: 1, Column: 1}

	errorCodes := []ErrorCode{
		ErrCodeUnexpectedChar,
		ErrCodeUnterminatedString,
		ErrCodeInvalidNumber,
		ErrCodeUnexpectedToken,
		ErrCodeExpectedToken,
		ErrCodeMissingClause,
		ErrCodeInvalidSyntax,
		ErrCodeUnsupportedFeature,
		ErrCodeIncompleteStatement,
	}

	for _, code := range errorCodes {
		err := NewError(code, "test", location)
		if err.HelpURL == "" {
			t.Errorf("Error with code %s should have help URL", code)
		}
		if !strings.Contains(err.HelpURL, string(code)) {
			t.Errorf("Help URL should contain error code %s, got: %s", code, err.HelpURL)
		}
	}
}
