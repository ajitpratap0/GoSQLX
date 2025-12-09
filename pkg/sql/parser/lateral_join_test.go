package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_LateralBasic tests basic LATERAL subquery syntax
func TestParser_LateralBasic(t *testing.T) {
	sql := "SELECT u.name, o.order_date FROM users u LEFT JOIN LATERAL (SELECT order_date FROM orders WHERE user_id = u.id LIMIT 1) AS o ON true"

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	result, err := ConvertTokensWithPositions(tokens)
	if err != nil {
		t.Fatalf("Failed to convert tokens: %v", err)
	}

	// Parse tokens
	parser := GetParser()
	defer PutParser(parser)

	astObj, err := parser.ParseWithPositions(result)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a SELECT statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify JOIN contains LATERAL flag
	if len(selectStmt.Joins) == 0 {
		t.Fatal("Expected at least one JOIN")
	}

	join := selectStmt.Joins[0]
	if !join.Right.Lateral {
		t.Error("Expected LATERAL flag to be true on joined table")
	}

	if join.Right.Subquery == nil {
		t.Error("Expected subquery in LATERAL join")
	}
}

// TestParser_LateralFlagFalseWithoutKeyword tests that LATERAL flag is false when keyword is absent
func TestParser_LateralFlagFalseWithoutKeyword(t *testing.T) {
	sql := "SELECT * FROM users u LEFT JOIN (SELECT * FROM orders WHERE user_id = u.id) AS o ON true"

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	result, err := ConvertTokensWithPositions(tokens)
	if err != nil {
		t.Fatalf("Failed to convert tokens: %v", err)
	}

	// Parse tokens
	parser := GetParser()
	defer PutParser(parser)

	astObj, err := parser.ParseWithPositions(result)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify JOIN does NOT have LATERAL flag
	if len(selectStmt.Joins) == 0 {
		t.Fatal("Expected at least one JOIN")
	}

	join := selectStmt.Joins[0]
	if join.Right.Lateral {
		t.Error("Expected LATERAL flag to be false when LATERAL keyword is not present")
	}
}

// TestParser_MultipleLateralJoins tests multiple LATERAL subqueries in one query
func TestParser_MultipleLateralJoins(t *testing.T) {
	sql := `SELECT u.name, recent.order_date, top_product.product_name
FROM users u
LEFT JOIN LATERAL (SELECT order_date FROM orders WHERE user_id = u.id ORDER BY order_date DESC LIMIT 1) AS recent ON true
LEFT JOIN LATERAL (SELECT p.product_name FROM orders o JOIN products p ON o.product_id = p.id WHERE o.user_id = u.id GROUP BY p.product_name LIMIT 1) AS top_product ON true`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser
	result, err := ConvertTokensWithPositions(tokens)
	if err != nil {
		t.Fatalf("Failed to convert tokens: %v", err)
	}

	// Parse tokens
	parser := GetParser()
	defer PutParser(parser)

	astObj, err := parser.ParseWithPositions(result)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify SELECT statement
	selectStmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("Expected SELECT statement")
	}

	// Verify we have 2 JOINs
	if len(selectStmt.Joins) != 2 {
		t.Fatalf("Expected 2 JOINs, got %d", len(selectStmt.Joins))
	}

	// Verify both are LATERAL
	for i, join := range selectStmt.Joins {
		if !join.Right.Lateral {
			t.Errorf("JOIN %d: Expected LATERAL flag to be true", i)
		}
		if join.Right.Subquery == nil {
			t.Errorf("JOIN %d: Expected subquery in LATERAL join", i)
		}
	}
}
