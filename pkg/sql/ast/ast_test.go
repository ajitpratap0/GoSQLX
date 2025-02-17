package ast

import (
	"testing"
)

func TestASTNodeInterfaces(t *testing.T) {
	// Test SelectStatement implements Statement interface
	var stmt Statement = &SelectStatement{}
	if stmt.TokenLiteral() != "SELECT" {
		t.Errorf("expected SELECT, got %s", stmt.TokenLiteral())
	}

	// Test Identifier implements Expression interface
	var expr Expression = &Identifier{Name: "test"}
	if expr.TokenLiteral() != "test" {
		t.Errorf("expected test, got %s", expr.TokenLiteral())
	}

	// Test BinaryExpression implements Expression interface
	var binExpr Expression = &BinaryExpression{
		Left:     &Identifier{Name: "id"},
		Operator: "=",
		Right:    &Identifier{Name: "1"},
	}
	if binExpr.TokenLiteral() != "=" {
		t.Errorf("expected =, got %s", binExpr.TokenLiteral())
	}
}

func TestASTPool(t *testing.T) {
	// Test AST pool
	ast1 := NewAST()
	if ast1 == nil {
		t.Fatal("expected non-nil AST")
	}
	if len(ast1.Statements) != 0 {
		t.Errorf("expected empty statements, got %d", len(ast1.Statements))
	}
	ReleaseAST(ast1)

	// Test getting another AST reuses the pool
	ast2 := NewAST()
	if ast2 == nil {
		t.Fatal("expected non-nil AST")
	}
	ReleaseAST(ast2)
}

func TestSelectStatementPool(t *testing.T) {
	// Test getting a SelectStatement
	stmt1 := GetSelectStatement()
	if stmt1 == nil {
		t.Fatal("expected non-nil SelectStatement")
	}
	if len(stmt1.Columns) != 0 {
		t.Errorf("expected empty columns, got %d", len(stmt1.Columns))
	}
	if len(stmt1.OrderBy) != 0 {
		t.Errorf("expected empty order by, got %d", len(stmt1.OrderBy))
	}

	// Add some expressions
	stmt1.Columns = append(stmt1.Columns, &Identifier{Name: "id"})
	stmt1.Where = &BinaryExpression{
		Left:     &Identifier{Name: "id"},
		Operator: "=",
		Right:    &Identifier{Name: "1"},
	}

	// Release back to pool
	PutSelectStatement(stmt1)

	// Test getting another SelectStatement reuses the pool
	stmt2 := GetSelectStatement()
	if stmt2 == nil {
		t.Fatal("expected non-nil SelectStatement")
	}
	if len(stmt2.Columns) != 0 {
		t.Errorf("expected empty columns after reset, got %d", len(stmt2.Columns))
	}
	if stmt2.Where != nil {
		t.Error("expected nil Where after reset")
	}
	PutSelectStatement(stmt2)
}

func TestIdentifierPool(t *testing.T) {
	// Test getting an Identifier
	ident1 := GetIdentifier()
	if ident1 == nil {
		t.Fatal("expected non-nil Identifier")
	}
	ident1.Name = "test"

	// Release back to pool
	PutIdentifier(ident1)

	// Test getting another Identifier reuses the pool
	ident2 := GetIdentifier()
	if ident2 == nil {
		t.Fatal("expected non-nil Identifier")
	}
	if ident2.Name != "" {
		t.Errorf("expected empty name after reset, got %q", ident2.Name)
	}
	PutIdentifier(ident2)
}

func TestBinaryExpressionPool(t *testing.T) {
	// Test getting a BinaryExpression
	expr1 := GetBinaryExpression()
	if expr1 == nil {
		t.Fatal("expected non-nil BinaryExpression")
	}

	expr1.Left = &Identifier{Name: "id"}
	expr1.Operator = "="
	expr1.Right = &Identifier{Name: "1"}

	// Release back to pool
	PutBinaryExpression(expr1)

	// Test getting another BinaryExpression reuses the pool
	expr2 := GetBinaryExpression()
	if expr2 == nil {
		t.Fatal("expected non-nil BinaryExpression")
	}
	if expr2.Left != nil {
		t.Error("expected nil Left after reset")
	}
	if expr2.Right != nil {
		t.Error("expected nil Right after reset")
	}
	if expr2.Operator != "" {
		t.Errorf("expected empty operator after reset, got %q", expr2.Operator)
	}
	PutBinaryExpression(expr2)
}

func TestExpressionSlicePool(t *testing.T) {
	// Test getting an expression slice
	slice1 := GetExpressionSlice()
	if slice1 == nil {
		t.Fatal("expected non-nil slice")
	}
	*slice1 = append(*slice1, &Identifier{Name: "test"})

	// Release back to pool
	PutExpressionSlice(slice1)

	// Test getting another slice reuses the pool
	slice2 := GetExpressionSlice()
	if slice2 == nil {
		t.Fatal("expected non-nil slice")
	}
	if len(*slice2) != 0 {
		t.Errorf("expected empty slice after reset, got len %d", len(*slice2))
	}
	PutExpressionSlice(slice2)
}

func TestPutExpression(t *testing.T) {
	// Test putting nil expression
	PutExpression(nil)

	// Test putting Identifier
	ident := &Identifier{Name: "test"}
	PutExpression(ident)

	// Test putting BinaryExpression
	binExpr := &BinaryExpression{
		Left:     &Identifier{Name: "id"},
		Operator: "=",
		Right:    &Identifier{Name: "1"},
	}
	PutExpression(binExpr)
}
