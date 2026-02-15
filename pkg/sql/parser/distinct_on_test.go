// Package parser - distinct_on_test.go
// Tests for PostgreSQL DISTINCT ON clause support

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func TestParser_DistinctOn_Basic(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "salary"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "salary"},
		{Type: models.TokenTypeDesc, Literal: "DESC"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT flag is set
	if !stmt.Distinct {
		t.Error("Expected Distinct to be true")
	}

	// Check DISTINCT ON columns
	if len(stmt.DistinctOnColumns) != 1 {
		t.Fatalf("Expected 1 DISTINCT ON column, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify the DISTINCT ON column is dept_id
	ident, ok := stmt.DistinctOnColumns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("Expected Identifier for DISTINCT ON column, got %T", stmt.DistinctOnColumns[0])
	}
	if ident.Name != "dept_id" {
		t.Errorf("Expected DISTINCT ON column 'dept_id', got '%s'", ident.Name)
	}

	// Verify SELECT columns
	if len(stmt.Columns) != 3 {
		t.Errorf("Expected 3 SELECT columns, got %d", len(stmt.Columns))
	}

	// Verify ORDER BY clause
	if len(stmt.OrderBy) != 2 {
		t.Errorf("Expected 2 ORDER BY expressions, got %d", len(stmt.OrderBy))
	}
}

func TestParser_DistinctOn_MultipleColumns(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "product_name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "purchases"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT flag is set
	if !stmt.Distinct {
		t.Error("Expected Distinct to be true")
	}

	// Check DISTINCT ON columns
	if len(stmt.DistinctOnColumns) != 2 {
		t.Fatalf("Expected 2 DISTINCT ON columns, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify first DISTINCT ON column is user_id
	ident1, ok := stmt.DistinctOnColumns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("Expected Identifier for first DISTINCT ON column, got %T", stmt.DistinctOnColumns[0])
	}
	if ident1.Name != "user_id" {
		t.Errorf("Expected first DISTINCT ON column 'user_id', got '%s'", ident1.Name)
	}

	// Verify second DISTINCT ON column is category
	ident2, ok := stmt.DistinctOnColumns[1].(*ast.Identifier)
	if !ok {
		t.Fatalf("Expected Identifier for second DISTINCT ON column, got %T", stmt.DistinctOnColumns[1])
	}
	if ident2.Name != "category" {
		t.Errorf("Expected second DISTINCT ON column 'category', got '%s'", ident2.Name)
	}

	// Verify SELECT columns
	if len(stmt.Columns) != 3 {
		t.Errorf("Expected 3 SELECT columns, got %d", len(stmt.Columns))
	}

	// Verify ORDER BY clause
	if len(stmt.OrderBy) != 2 {
		t.Errorf("Expected 2 ORDER BY expressions, got %d", len(stmt.OrderBy))
	}
}

func TestParser_DistinctOn_WithExpression(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "LOWER"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "email"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "email"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT flag is set
	if !stmt.Distinct {
		t.Error("Expected Distinct to be true")
	}

	// Check DISTINCT ON columns
	if len(stmt.DistinctOnColumns) != 1 {
		t.Fatalf("Expected 1 DISTINCT ON expression, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify the DISTINCT ON expression is a function call
	funcCall, ok := stmt.DistinctOnColumns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("Expected FunctionCall for DISTINCT ON expression, got %T", stmt.DistinctOnColumns[0])
	}
	if funcCall.Name != "LOWER" {
		t.Errorf("Expected DISTINCT ON function 'LOWER', got '%s'", funcCall.Name)
	}
}

func TestParser_DistinctOn_WithWhere(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "active"},
		{Type: models.TokenTypeEq, Literal: "="},
		{Type: models.TokenTypeTrue, Literal: "TRUE"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT flag and DISTINCT ON columns
	if !stmt.Distinct {
		t.Error("Expected Distinct to be true")
	}
	if len(stmt.DistinctOnColumns) != 1 {
		t.Fatalf("Expected 1 DISTINCT ON column, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify WHERE clause exists
	if stmt.Where == nil {
		t.Error("Expected WHERE clause to exist")
	}

	// Verify ORDER BY clause exists
	if len(stmt.OrderBy) != 1 {
		t.Errorf("Expected 1 ORDER BY expression, got %d", len(stmt.OrderBy))
	}
}

func TestParser_DistinctOn_QualifiedColumn(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "e"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "e"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "e"},
		{Type: models.TokenTypePeriod, Literal: "."},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
		{Type: models.TokenTypeIdentifier, Literal: "e"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT ON columns
	if len(stmt.DistinctOnColumns) != 1 {
		t.Fatalf("Expected 1 DISTINCT ON column, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify the DISTINCT ON column is qualified (e.dept_id)
	ident, ok := stmt.DistinctOnColumns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("Expected Identifier for DISTINCT ON column, got %T", stmt.DistinctOnColumns[0])
	}
	if ident.Table != "e" || ident.Name != "dept_id" {
		t.Errorf("Expected DISTINCT ON column 'e.dept_id', got '%s.%s'", ident.Table, ident.Name)
	}
}

func TestParser_DistinctWithoutOn_StillWorks(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT flag is set
	if !stmt.Distinct {
		t.Error("Expected Distinct to be true")
	}

	// Check DISTINCT ON columns is empty (regular DISTINCT)
	if len(stmt.DistinctOnColumns) != 0 {
		t.Errorf("Expected 0 DISTINCT ON columns for regular DISTINCT, got %d", len(stmt.DistinctOnColumns))
	}

	// Verify SELECT columns
	if len(stmt.Columns) != 2 {
		t.Errorf("Expected 2 SELECT columns, got %d", len(stmt.Columns))
	}
}

// Error case tests

func TestParser_DistinctOn_ErrorMissingParenthesis(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
	}

	parser := NewParser()
	defer parser.Release()

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Error("Expected error for missing opening parenthesis, got nil")
	}
}

func TestParser_DistinctOn_ErrorMissingClosingParenthesis(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
	}

	parser := NewParser()
	defer parser.Release()

	_, err := parser.Parse(tokens)
	if err == nil {
		t.Error("Expected error for missing closing parenthesis, got nil")
	}
}

func TestParser_DistinctOn_WithLimit(t *testing.T) {
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "product_name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeLimit, Literal: "LIMIT"},
		{Type: models.TokenTypeNumber, Literal: "10"},
	}

	parser := NewParser()
	defer parser.Release()

	astObj, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("Parsing failed: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(astObj.Statements))
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	// Check DISTINCT ON columns
	if len(stmt.DistinctOnColumns) != 1 {
		t.Fatalf("Expected 1 DISTINCT ON column, got %d", len(stmt.DistinctOnColumns))
	}

	// Check LIMIT exists
	if stmt.Limit == nil {
		t.Error("Expected LIMIT clause to exist")
	} else if *stmt.Limit != 10 {
		t.Errorf("Expected LIMIT 10, got %d", *stmt.Limit)
	}
}
