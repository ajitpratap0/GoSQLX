package parser

import (
	"errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func eof() token.Token {
	return token.Token{Type: models.TokenTypeEOF, Literal: ""}
}

func semi() token.Token {
	return token.Token{Type: models.TokenTypeSemicolon, Literal: ";"}
}

// stringToTokenType is a helper for tests that creates tokens from string type names.
var testStringToType = map[string]models.TokenType{
	"SELECT": models.TokenTypeSelect, "FROM": models.TokenTypeFrom,
	"WHERE": models.TokenTypeWhere, "IDENT": models.TokenTypeIdentifier,
	"INT": models.TokenTypeNumber, "STRING": models.TokenTypeString,
	"=": models.TokenTypeEq, ",": models.TokenTypeComma,
	"(": models.TokenTypeLParen, ")": models.TokenTypeRParen,
	";": models.TokenTypeSemicolon, "EOF": models.TokenTypeEOF,
	"*": models.TokenTypeAsterisk, ".": models.TokenTypePeriod,
	"INSERT": models.TokenTypeInsert, "INTO": models.TokenTypeInto,
	"VALUES": models.TokenTypeValues, "UPDATE": models.TokenTypeUpdate,
	"SET": models.TokenTypeSet, "DELETE": models.TokenTypeDelete,
}

func tok(typ, lit string) token.Token {
	if mt, ok := testStringToType[typ]; ok {
		return token.Token{Type: mt, Literal: lit}
	}
	return token.Token{Type: models.TokenTypeKeyword, Literal: lit}
}

// TestParseWithRecovery_MultipleErrors tests that multiple syntax errors are all reported.
func TestParseWithRecovery_MultipleErrors(t *testing.T) {
	tokens := []token.Token{
		tok("IDENT", "INVALID1"), tok("IDENT", "foo"), semi(),
		tok("IDENT", "INVALID2"), tok("IDENT", "bar"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Statements) != 0 {
		t.Errorf("expected 0 statements, got %d", len(result.Statements))
	}
	if len(result.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(result.Errors))
	}
	for i, err := range result.Errors {
		pe, ok := err.(*ParseError)
		if !ok {
			t.Errorf("error %d is not a *ParseError: %T", i, err)
			continue
		}
		if pe.Cause == nil {
			t.Errorf("error %d: Cause should not be nil", i)
		}
	}
}

// TestParseWithRecovery_FirstValidSecondInvalid tests partial AST with valid+invalid mix.
func TestParseWithRecovery_FirstValidSecondInvalid(t *testing.T) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		tok("IDENT", "INVALID"), tok("IDENT", "foo"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Statements) != 1 {
		t.Errorf("expected 1 statement, got %d", len(result.Statements))
	}
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
}

// TestParseWithRecovery_AllInvalid tests that all-invalid input returns empty AST + multiple errors.
func TestParseWithRecovery_AllInvalid(t *testing.T) {
	tokens := []token.Token{
		tok("IDENT", "BAD1"), semi(),
		tok("IDENT", "BAD2"), semi(),
		tok("IDENT", "BAD3"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Statements) != 0 {
		t.Errorf("expected 0 statements, got %d", len(result.Statements))
	}
	if len(result.Errors) != 3 {
		t.Errorf("expected 3 errors, got %d", len(result.Errors))
	}
}

// TestParseWithRecovery_UnclosedParen tests recovery after unclosed parenthesis.
func TestParseWithRecovery_UnclosedParen(t *testing.T) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("(", "("), tok("INT", "1"), tok("+", "+"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Errors) < 1 {
		t.Errorf("expected at least 1 error, got %d", len(result.Errors))
	}
	if len(result.Statements) < 1 {
		t.Errorf("expected at least 1 successfully parsed statement, got %d", len(result.Statements))
	}
}

// TestParseWithRecovery_RecoveryToKeyword tests recovery skipping to next statement keyword.
func TestParseWithRecovery_RecoveryToKeyword(t *testing.T) {
	tokens := []token.Token{
		tok("IDENT", "INVALID"), tok("IDENT", "foo"), tok("IDENT", "bar"),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(result.Errors))
	}
	if len(result.Statements) != 1 {
		t.Errorf("expected 1 statement, got %d", len(result.Statements))
	}
}

// TestParseWithRecovery_EmptyInput tests empty token stream.
func TestParseWithRecovery_EmptyInput(t *testing.T) {
	tokens := []token.Token{eof()}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Statements) != 0 {
		t.Errorf("expected 0 statements, got %d", len(result.Statements))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
	}
}

// TestParseWithRecovery_AllValid tests that all-valid input returns all statements.
func TestParseWithRecovery_AllValid(t *testing.T) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("SELECT", "SELECT"), tok("INT", "2"), semi(),
		eof(),
	}
	result := ParseMultiWithRecovery(tokens)
	defer result.Release()
	if len(result.Statements) != 2 {
		t.Errorf("expected 2 statements, got %d", len(result.Statements))
	}
	if len(result.Errors) != 0 {
		t.Errorf("expected 0 errors, got %d", len(result.Errors))
	}
}

// TestParseError_ErrorMessage tests ParseError formatting.
func TestParseError_ErrorMessage(t *testing.T) {
	e := &ParseError{Msg: "unexpected token", TokenIdx: 5}
	if e.Error() != "parse error at token 5: unexpected token" {
		t.Errorf("unexpected error message: %s", e.Error())
	}

	e2 := &ParseError{Msg: "bad syntax", TokenIdx: 3, Line: 2, Column: 10}
	if e2.Error() != "parse error at line 2, column 10 (token 3): bad syntax" {
		t.Errorf("unexpected error message: %s", e2.Error())
	}
}

// TestParseError_Unwrap tests that ParseError.Unwrap works with errors.Is/As.
func TestParseError_Unwrap(t *testing.T) {
	cause := errors.New("original error")
	pe := &ParseError{Msg: "wrapped", Cause: cause}

	if !errors.Is(pe, cause) {
		t.Error("errors.Is should find the cause")
	}

	var target *ParseError
	if !errors.As(pe, &target) {
		t.Error("errors.As should work for *ParseError")
	}
}

// TestRecoveryResult_DoubleRelease ensures Release is safe to call twice.
func TestRecoveryResult_DoubleRelease(t *testing.T) {
	tokens := []token.Token{eof()}
	result := ParseMultiWithRecovery(tokens)
	result.Release()
	result.Release() // should not panic
}

// TestParseWithRecovery_ExpandedKeywords tests that expanded keywords trigger recovery.
func TestParseWithRecovery_ExpandedKeywords(t *testing.T) {
	for _, kw := range []string{"EXPLAIN", "ANALYZE", "SHOW", "DESCRIBE", "GRANT", "REVOKE",
		"SET", "USE", "BEGIN", "COMMIT", "ROLLBACK", "VACUUM"} {
		t.Run(kw, func(t *testing.T) {
			tokens := []token.Token{
				tok("IDENT", "BAD"),
				tok(kw, kw), tok("IDENT", "something"), semi(),
				eof(),
			}
			result := ParseMultiWithRecovery(tokens)
			defer result.Release()
			if len(result.Errors) < 1 {
				t.Errorf("expected at least 1 error for keyword %s recovery", kw)
			}
		})
	}
}

// TestParseWithRecovery_MethodAPI tests the method-based API for backward compatibility.
func TestParseWithRecovery_MethodAPI(t *testing.T) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("IDENT", "BAD"), semi(),
		eof(),
	}
	p := GetParser()
	defer PutParser(p)
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 1 {
		t.Errorf("expected 1 statement, got %d", len(stmts))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}
