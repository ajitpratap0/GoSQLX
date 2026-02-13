package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func eof() token.Token {
	return token.Token{Type: "EOF", Literal: ""}
}

func semi() token.Token {
	return token.Token{Type: ";", Literal: ";"}
}

func tok(typ, lit string) token.Token {
	return token.Token{Type: token.Type(typ), Literal: lit}
}

// TestParseWithRecovery_MultipleErrors tests that multiple syntax errors are all reported.
func TestParseWithRecovery_MultipleErrors(t *testing.T) {
	// "INVALID1 foo; INVALID2 bar;"
	tokens := []token.Token{
		tok("IDENT", "INVALID1"), tok("IDENT", "foo"), semi(),
		tok("IDENT", "INVALID2"), tok("IDENT", "bar"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 0 {
		t.Errorf("expected 0 statements, got %d", len(stmts))
	}
	if len(errs) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(errs))
	}
	// Each error should be a *ParseError with position info
	for i, err := range errs {
		if _, ok := err.(*ParseError); !ok {
			t.Errorf("error %d is not a *ParseError: %T", i, err)
		}
	}
}

// TestParseWithRecovery_FirstValidSecondInvalid tests partial AST with valid+invalid mix.
func TestParseWithRecovery_FirstValidSecondInvalid(t *testing.T) {
	// "SELECT * FROM users; INVALID foo;"
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		tok("IDENT", "INVALID"), tok("IDENT", "foo"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 1 {
		t.Errorf("expected 1 statement, got %d", len(stmts))
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
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
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 0 {
		t.Errorf("expected 0 statements, got %d", len(stmts))
	}
	if len(errs) != 3 {
		t.Errorf("expected 3 errors, got %d", len(errs))
	}
}

// TestParseWithRecovery_UnclosedParen tests recovery after unclosed parenthesis.
func TestParseWithRecovery_UnclosedParen(t *testing.T) {
	// "SELECT (1 + ; SELECT * FROM users;"
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("(", "("), tok("INT", "1"), tok("+", "+"), semi(),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(errs) < 1 {
		t.Errorf("expected at least 1 error, got %d", len(errs))
	}
	if len(stmts) < 1 {
		t.Errorf("expected at least 1 successfully parsed statement, got %d", len(stmts))
	}
}

// TestParseWithRecovery_InvalidExpression tests recovery after invalid expression.
func TestParseWithRecovery_InvalidExpression(t *testing.T) {
	// "SELECT FROM; SELECT 1;"
	// First SELECT has no columns (invalid), second is valid
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("FROM", "FROM"), semi(),
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	// The first SELECT FROM might parse differently depending on parser internals,
	// but we should get at least one statement or error
	if len(stmts)+len(errs) < 2 {
		t.Errorf("expected at least 2 total statements+errors, got stmts=%d errs=%d", len(stmts), len(errs))
	}
}

// TestParseWithRecovery_RecoveryToKeyword tests recovery skipping to next statement keyword.
func TestParseWithRecovery_RecoveryToKeyword(t *testing.T) {
	// "INVALID foo bar SELECT * FROM users;"
	// No semicolon after invalid part, should recover at SELECT keyword
	tokens := []token.Token{
		tok("IDENT", "INVALID"), tok("IDENT", "foo"), tok("IDENT", "bar"),
		tok("SELECT", "SELECT"), tok("*", "*"), tok("FROM", "FROM"), tok("IDENT", "users"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if len(stmts) != 1 {
		t.Errorf("expected 1 statement, got %d", len(stmts))
	}
}

// TestParseWithRecovery_EmptyInput tests empty token stream.
func TestParseWithRecovery_EmptyInput(t *testing.T) {
	tokens := []token.Token{eof()}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 0 {
		t.Errorf("expected 0 statements, got %d", len(stmts))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
}

// TestParseWithRecovery_AllValid tests that all-valid input returns all statements.
func TestParseWithRecovery_AllValid(t *testing.T) {
	tokens := []token.Token{
		tok("SELECT", "SELECT"), tok("INT", "1"), semi(),
		tok("SELECT", "SELECT"), tok("INT", "2"), semi(),
		eof(),
	}
	p := NewParser()
	stmts, errs := p.ParseWithRecovery(tokens)
	if len(stmts) != 2 {
		t.Errorf("expected 2 statements, got %d", len(stmts))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
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
