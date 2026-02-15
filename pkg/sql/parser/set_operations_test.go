package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_SimpleUnion(t *testing.T) {
	sql := `SELECT name FROM users UNION SELECT name FROM customers`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse UNION: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SetOperation
	setOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify operation type
	if setOp.Operator != "UNION" {
		t.Errorf("Expected UNION operator, got %s", setOp.Operator)
	}

	// Verify not ALL
	if setOp.All {
		t.Error("Expected UNION (not UNION ALL)")
	}

	// Verify left and right are SELECT statements
	_, leftOk := setOp.Left.(*ast.SelectStatement)
	_, rightOk := setOp.Right.(*ast.SelectStatement)
	if !leftOk || !rightOk {
		t.Errorf("Expected both sides to be SELECT statements, got left=%T, right=%T", setOp.Left, setOp.Right)
	}
}

func TestParser_UnionAll(t *testing.T) {
	sql := `SELECT id FROM orders UNION ALL SELECT id FROM invoices`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse UNION ALL: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SetOperation
	setOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify operation type and ALL flag
	if setOp.Operator != "UNION" {
		t.Errorf("Expected UNION operator, got %s", setOp.Operator)
	}
	if !setOp.All {
		t.Error("Expected UNION ALL")
	}
}

func TestParser_Except(t *testing.T) {
	sql := `SELECT region FROM sales EXCEPT SELECT region FROM returns`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse EXCEPT: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SetOperation
	setOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify operation type
	if setOp.Operator != "EXCEPT" {
		t.Errorf("Expected EXCEPT operator, got %s", setOp.Operator)
	}
}

func TestParser_Intersect(t *testing.T) {
	sql := `SELECT product FROM inventory INTERSECT SELECT product FROM sales`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse INTERSECT: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SetOperation
	setOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify operation type
	if setOp.Operator != "INTERSECT" {
		t.Errorf("Expected INTERSECT operator, got %s", setOp.Operator)
	}
}

func TestParser_MultipleSetOperations(t *testing.T) {
	sql := `SELECT name FROM users UNION SELECT name FROM customers INTERSECT SELECT name FROM employees`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse multiple set operations: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// Verify it's a SetOperation (the outer one)
	outerSetOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify the outer operation is INTERSECT (the last one parsed)
	if outerSetOp.Operator != "INTERSECT" {
		t.Errorf("Expected outer operation to be INTERSECT, got %s", outerSetOp.Operator)
	}

	// Verify the left side is also a SetOperation (UNION)
	leftSetOp, ok := outerSetOp.Left.(*ast.SetOperation)
	if !ok {
		t.Errorf("Expected left side to be SetOperation, got %T", outerSetOp.Left)
	} else {
		if leftSetOp.Operator != "UNION" {
			t.Errorf("Expected left operation to be UNION, got %s", leftSetOp.Operator)
		}
	}

	// Verify the right side is a SELECT statement
	_, rightOk := outerSetOp.Right.(*ast.SelectStatement)
	if !rightOk {
		t.Errorf("Expected right side to be SELECT statement, got %T", outerSetOp.Right)
	}
}

func TestParser_SetOperationWithCTE(t *testing.T) {
	sql := `WITH regional AS (SELECT region FROM sales) SELECT region FROM regional UNION SELECT region FROM returns`

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	// Convert tokens for parser

	// Parse tokens
	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse CTE with set operation: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	// Verify we have a statement
	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	// The result should be a SetOperation with a With clause
	setOp, ok := astObj.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("Expected SetOperation, got %T", astObj.Statements[0])
	}

	// Verify operation type
	if setOp.Operator != "UNION" {
		t.Errorf("Expected UNION operator, got %s", setOp.Operator)
	}

	// The left side should be a SELECT with a WITH clause
	leftSelect, ok := setOp.Left.(*ast.SelectStatement)
	if !ok {
		t.Errorf("Expected left side to be SELECT statement, got %T", setOp.Left)
	} else {
		// Verify WITH clause exists
		if leftSelect.With == nil {
			t.Error("Expected WITH clause in left SELECT")
		} else {
			if len(leftSelect.With.CTEs) != 1 {
				t.Errorf("Expected 1 CTE, got %d", len(leftSelect.With.CTEs))
			}
			if len(leftSelect.With.CTEs) > 0 && leftSelect.With.CTEs[0].Name != "regional" {
				t.Errorf("Expected CTE name 'regional', got '%s'", leftSelect.With.CTEs[0].Name)
			}
		}
	}
}
