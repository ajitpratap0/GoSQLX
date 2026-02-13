package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestParseFromModelTokens_SimpleSelect(t *testing.T) {
	tokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "id"}},
		{Token: models.Token{Type: models.TokenTypeFrom, Value: "FROM"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "users"}},
		{Token: models.Token{Type: models.TokenTypeEOF, Value: ""}},
	}

	p := GetParser()
	defer PutParser(p)

	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("ParseFromModelTokens failed: %v", err)
	}
	defer ast.ReleaseAST(result)

	if result == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
}

func TestParseFromModelTokens_EmptyTokens(t *testing.T) {
	tokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeEOF, Value: ""}},
	}

	p := GetParser()
	defer PutParser(p)

	_, err := p.ParseFromModelTokens(tokens)
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestParseFromModelTokens_InsertStatement(t *testing.T) {
	tokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeInsert, Value: "INSERT"}},
		{Token: models.Token{Type: models.TokenTypeInto, Value: "INTO"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "users"}},
		{Token: models.Token{Type: models.TokenTypeLParen, Value: "("}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "name"}},
		{Token: models.Token{Type: models.TokenTypeRParen, Value: ")"}},
		{Token: models.Token{Type: models.TokenTypeValues, Value: "VALUES"}},
		{Token: models.Token{Type: models.TokenTypeLParen, Value: "("}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "'Alice'"}},
		{Token: models.Token{Type: models.TokenTypeRParen, Value: ")"}},
		{Token: models.Token{Type: models.TokenTypeEOF, Value: ""}},
	}

	p := GetParser()
	defer PutParser(p)

	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("ParseFromModelTokens failed: %v", err)
	}
	defer ast.ReleaseAST(result)

	if len(result.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result.Statements))
	}
}

func TestParseFromModelTokens_ProducesSameResultAsParse(t *testing.T) {
	// Verify that ParseFromModelTokens produces equivalent results to
	// the manual ConvertTokensForParser + Parse path
	tokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeNumber, Value: "1"}},
		{Token: models.Token{Type: models.TokenTypeEOF, Value: ""}},
	}

	// Path 1: ParseFromModelTokens
	p1 := GetParser()
	defer PutParser(p1)
	result1, err := p1.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("ParseFromModelTokens failed: %v", err)
	}
	defer ast.ReleaseAST(result1)

	// Path 2: ConvertTokensForParser + Parse
	converted, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("ConvertTokensForParser failed: %v", err)
	}
	p2 := GetParser()
	defer PutParser(p2)
	result2, err := p2.Parse(converted)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer ast.ReleaseAST(result2)

	// Both should produce same number of statements
	if len(result1.Statements) != len(result2.Statements) {
		t.Errorf("statement count mismatch: ParseFromModelTokens=%d, Parse=%d",
			len(result1.Statements), len(result2.Statements))
	}
}
