package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// TestParser_BetweenExpression tests BETWEEN operator parsing
func TestParser_BetweenExpression(t *testing.T) {
	// SELECT * FROM products WHERE price BETWEEN 10 AND 100
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeNumber, Literal: "100"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	betweenExpr, ok := stmt.Where.(*ast.BetweenExpression)
	if !ok {
		t.Fatalf("expected BetweenExpression, got %T", stmt.Where)
	}

	if betweenExpr.Not {
		t.Error("expected Not to be false")
	}

	// Verify expr is identifier "price"
	ident, ok := betweenExpr.Expr.(*ast.Identifier)
	if !ok || ident.Name != "price" {
		t.Error("expected Expr to be identifier 'price'")
	}
}

// TestParser_NotBetweenExpression tests NOT BETWEEN operator
func TestParser_NotBetweenExpression(t *testing.T) {
	// SELECT * FROM products WHERE price NOT BETWEEN 10 AND 100
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeNumber, Literal: "100"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	if !betweenExpr.Not {
		t.Error("expected Not to be true for NOT BETWEEN")
	}
}

// TestParser_InExpression tests IN operator
func TestParser_InExpression(t *testing.T) {
	// SELECT * FROM orders WHERE status IN ('pending', 'processing', 'shipped')
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "status"},
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "pending"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "processing"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "shipped"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	if inExpr.Not {
		t.Error("expected Not to be false")
	}

	if len(inExpr.List) != 3 {
		t.Errorf("expected 3 values in IN list, got %d", len(inExpr.List))
	}
}

// TestParser_NotInExpression tests NOT IN operator
func TestParser_NotInExpression(t *testing.T) {
	// SELECT * FROM orders WHERE status NOT IN ('cancelled')
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "status"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "cancelled"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	inExpr := stmt.Where.(*ast.InExpression)

	if !inExpr.Not {
		t.Error("expected Not to be true for NOT IN")
	}
}

// TestParser_LikeExpression tests LIKE operator
func TestParser_LikeExpression(t *testing.T) {
	// SELECT * FROM users WHERE email LIKE '%@example.com'
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "email"},
		{Type: models.TokenTypeLike, Literal: "LIKE"},
		{Type: models.TokenTypeString, Literal: "%@example.com"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "LIKE" {
		t.Errorf("expected operator 'LIKE', got %q", binExpr.Operator)
	}

	if binExpr.Not {
		t.Error("expected Not to be false")
	}
}

// TestParser_NotLikeExpression tests NOT LIKE operator
func TestParser_NotLikeExpression(t *testing.T) {
	// SELECT * FROM users WHERE name NOT LIKE 'Admin%'
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeLike, Literal: "LIKE"},
		{Type: models.TokenTypeString, Literal: "Admin%"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr := stmt.Where.(*ast.BinaryExpression)

	if !binExpr.Not {
		t.Error("expected Not to be true for NOT LIKE")
	}
}

// TestParser_IsNullExpression tests IS NULL operator
func TestParser_IsNullExpression(t *testing.T) {
	// SELECT * FROM customers WHERE deleted_at IS NULL
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "customers"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "deleted_at"},
		{Type: models.TokenTypeIs, Literal: "IS"},
		{Type: models.TokenTypeNull, Literal: "NULL"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "IS NULL" {
		t.Errorf("expected operator 'IS NULL', got %q", binExpr.Operator)
	}

	if binExpr.Not {
		t.Error("expected Not to be false for IS NULL")
	}
}

// TestParser_IsNotNullExpression tests IS NOT NULL operator
func TestParser_IsNotNullExpression(t *testing.T) {
	// SELECT * FROM posts WHERE published_at IS NOT NULL
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "posts"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "published_at"},
		{Type: models.TokenTypeIs, Literal: "IS"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeNull, Literal: "NULL"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	binExpr := stmt.Where.(*ast.BinaryExpression)

	if binExpr.Operator != "IS NULL" {
		t.Errorf("expected operator 'IS NULL', got %q", binExpr.Operator)
	}

	if !binExpr.Not {
		t.Error("expected Not to be true for IS NOT NULL")
	}
}

// TestParser_BetweenWithIdentifiers tests BETWEEN with column references
func TestParser_BetweenWithIdentifiers(t *testing.T) {
	// SELECT * FROM events WHERE event_date BETWEEN start_date AND end_date
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "events"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "event_date"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "start_date"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "end_date"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	// Verify lower bound is identifier
	lowerIdent, ok := betweenExpr.Lower.(*ast.Identifier)
	if !ok || lowerIdent.Name != "start_date" {
		t.Error("expected lower bound to be identifier 'start_date'")
	}

	// Verify upper bound is identifier
	upperIdent, ok := betweenExpr.Upper.(*ast.Identifier)
	if !ok || upperIdent.Name != "end_date" {
		t.Error("expected upper bound to be identifier 'end_date'")
	}
}

// TestParser_BetweenWithArithmeticExpressions tests BETWEEN with complex expressions (Issue #180)
func TestParser_BetweenWithArithmeticExpressions(t *testing.T) {
	// SELECT * FROM products WHERE price BETWEEN price * 0.9 AND price * 1.1
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "0.9"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "1.1"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	// Verify lower bound is a binary expression (multiplication)
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "*" {
		t.Errorf("expected lower bound operator '*', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is a binary expression (multiplication)
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "*" {
		t.Errorf("expected upper bound operator '*', got '%s'", upperBinary.Operator)
	}
}

// TestParser_BetweenWithAdditionSubtraction tests BETWEEN with +/- expressions
func TestParser_BetweenWithAdditionSubtraction(t *testing.T) {
	// SELECT * FROM orders WHERE total BETWEEN subtotal - 10 AND subtotal + 10
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "total"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "subtotal"},
		{Type: models.TokenTypeMinus, Literal: "-"},
		{Type: models.TokenTypeNumber, Literal: "10"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "subtotal"},
		{Type: models.TokenTypePlus, Literal: "+"},
		{Type: models.TokenTypeNumber, Literal: "10"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	// Verify lower bound is subtraction
	lowerBinary, ok := betweenExpr.Lower.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected lower bound to be BinaryExpression, got %T", betweenExpr.Lower)
	}
	if lowerBinary.Operator != "-" {
		t.Errorf("expected lower bound operator '-', got '%s'", lowerBinary.Operator)
	}

	// Verify upper bound is addition
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "+" {
		t.Errorf("expected upper bound operator '+', got '%s'", upperBinary.Operator)
	}
}

// TestParser_BetweenWithFunctionCallsAndArithmetic tests BETWEEN with function calls
func TestParser_BetweenWithFunctionCallsAndArithmetic(t *testing.T) {
	// SELECT * FROM orders WHERE amount BETWEEN MIN(price) AND MAX(price) * 2
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "amount"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeIdentifier, Literal: "MIN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "MAX"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "price"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeNumber, Literal: "2"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	betweenExpr := stmt.Where.(*ast.BetweenExpression)

	// Verify lower bound is a function call
	_, ok := betweenExpr.Lower.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected lower bound to be FunctionCall, got %T", betweenExpr.Lower)
	}

	// Verify upper bound is a binary expression (function * number)
	upperBinary, ok := betweenExpr.Upper.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected upper bound to be BinaryExpression, got %T", betweenExpr.Upper)
	}
	if upperBinary.Operator != "*" {
		t.Errorf("expected upper bound operator '*', got '%s'", upperBinary.Operator)
	}
}

// TestParser_InWithNumbers tests IN with numeric values
func TestParser_InWithNumbers(t *testing.T) {
	// SELECT * FROM products WHERE category_id IN (1, 2, 3)
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "products"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "category_id"},
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeNumber, Literal: "1"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "2"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "3"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	inExpr := stmt.Where.(*ast.InExpression)

	if len(inExpr.List) != 3 {
		t.Errorf("expected 3 values, got %d", len(inExpr.List))
	}

	// Verify all are literal values
	for i, val := range inExpr.List {
		lit, ok := val.(*ast.LiteralValue)
		if !ok {
			t.Errorf("expected LiteralValue at index %d, got %T", i, val)
		}
		if lit.Type != "int" {
			t.Errorf("expected int type at index %d, got %s", i, lit.Type)
		}
	}
}

// TestParser_TupleInExpression tests tuple expressions in IN clause
// WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))
func TestParser_TupleInExpression(t *testing.T) {
	// SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeLParen, Literal: "("}, // tuple start
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "status"},
		{Type: models.TokenTypeRParen, Literal: ")"}, // tuple end
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("}, // IN list start
		{Type: models.TokenTypeLParen, Literal: "("}, // first tuple value
		{Type: models.TokenTypeNumber, Literal: "1"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "active"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeComma, Literal: ","},  // between tuples
		{Type: models.TokenTypeLParen, Literal: "("}, // second tuple value
		{Type: models.TokenTypeNumber, Literal: "2"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "pending"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"}, // IN list end
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Left side should be a TupleExpression with 2 columns
	tupleLeft, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression on left side of IN, got %T", inExpr.Expr)
	}

	if len(tupleLeft.Expressions) != 2 {
		t.Errorf("expected 2 expressions in left tuple, got %d", len(tupleLeft.Expressions))
	}

	// IN list should contain 2 tuple values
	if len(inExpr.List) != 2 {
		t.Fatalf("expected 2 values in IN list, got %d", len(inExpr.List))
	}

	// First value should be TupleExpression (1, 'active')
	tuple1, ok := inExpr.List[0].(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression at index 0, got %T", inExpr.List[0])
	}
	if len(tuple1.Expressions) != 2 {
		t.Errorf("expected 2 expressions in first value tuple, got %d", len(tuple1.Expressions))
	}

	// Second value should be TupleExpression (2, 'pending')
	tuple2, ok := inExpr.List[1].(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression at index 1, got %T", inExpr.List[1])
	}
	if len(tuple2.Expressions) != 2 {
		t.Errorf("expected 2 expressions in second value tuple, got %d", len(tuple2.Expressions))
	}
}

// TestParser_TupleNotInExpression tests tuple with NOT IN
func TestParser_TupleNotInExpression(t *testing.T) {
	// SELECT * FROM orders WHERE (user_id, status) NOT IN ((1, 'cancelled'))
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "orders"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "status"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeNot, Literal: "NOT"},
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeNumber, Literal: "1"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeString, Literal: "cancelled"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	if !inExpr.Not {
		t.Error("expected Not to be true for NOT IN")
	}

	// Left side should be TupleExpression
	_, ok = inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression on left side, got %T", inExpr.Expr)
	}

	if len(inExpr.List) != 1 {
		t.Errorf("expected 1 value in IN list, got %d", len(inExpr.List))
	}
}

// TestParser_SimpleTupleExpression tests parsing a standalone tuple
func TestParser_SimpleTupleExpression(t *testing.T) {
	// SELECT (1, 2, 3)
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeNumber, Literal: "1"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "2"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeNumber, Literal: "3"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	tuple, ok := stmt.Columns[0].(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", stmt.Columns[0])
	}

	if len(tuple.Expressions) != 3 {
		t.Errorf("expected 3 expressions in tuple, got %d", len(tuple.Expressions))
	}
}

// TestParser_CombinedOperators tests multiple operators in one query
func TestParser_CombinedOperators(t *testing.T) {
	// SELECT * FROM users WHERE age BETWEEN 18 AND 65 AND status IN ('active') AND name LIKE 'J%' AND deleted_at IS NULL
	// This is a complex test combining all operators with AND
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
		{Type: models.TokenTypeWhere, Literal: "WHERE"},
		{Type: models.TokenTypeIdentifier, Literal: "age"},
		{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
		{Type: models.TokenTypeNumber, Literal: "18"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeNumber, Literal: "65"},
		{Type: models.TokenTypeAnd, Literal: "AND"},
		{Type: models.TokenTypeIdentifier, Literal: "status"},
		{Type: models.TokenTypeIn, Literal: "IN"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeString, Literal: "active"},
		{Type: models.TokenTypeRParen, Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// The WHERE clause should be a binary expression (AND)
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "AND" {
		t.Errorf("expected AND operator, got %q", binExpr.Operator)
	}
}

// TestParser_OperatorErrors tests error cases
func TestParser_OperatorErrors(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name: "BETWEEN without AND",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeBetween, Literal: "BETWEEN"},
				{Type: models.TokenTypeNumber, Literal: "1"},
				{Type: models.TokenTypeNumber, Literal: "10"}, // Missing AND
			},
		},
		{
			name: "IN without closing paren",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeIn, Literal: "IN"},
				{Type: models.TokenTypeLParen, Literal: "("},
				{Type: models.TokenTypeNumber, Literal: "1"},
				// Missing )
			},
		},
		{
			name: "IS without NULL",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "t"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "x"},
				{Type: models.TokenTypeIs, Literal: "IS"},
				{Type: models.TokenTypeNumber, Literal: "1"}, // Should be NULL
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			_, err := parser.Parse(tt.tokens)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestParser_StringConcatenation tests || (string concatenation) operator
func TestParser_StringConcatenation(t *testing.T) {
	// SELECT 'Hello' || ' ' || 'World'
	// Must include ModelType for tokens to be properly recognized
	// Use TokenTypeSingleQuotedString (31) for string literals, matching tokenizer output
	// Include EOF token at the end
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeString, Literal: "Hello"},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeString, Literal: " "},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeString, Literal: "World"},
		{Type: models.TokenTypeEOF, Literal: ""},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The expression should be: ('Hello' || ' ') || 'World'
	// This is left-associative
	outerBinExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Columns[0])
	}

	if outerBinExpr.Operator != "||" {
		t.Errorf("expected outer operator '||', got %q", outerBinExpr.Operator)
	}

	// Left side should be another binary expression
	innerBinExpr, ok := outerBinExpr.Left.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected left to be BinaryExpression, got %T", outerBinExpr.Left)
	}

	if innerBinExpr.Operator != "||" {
		t.Errorf("expected inner operator '||', got %q", innerBinExpr.Operator)
	}

	// Verify left side is 'Hello'
	leftLit, ok := innerBinExpr.Left.(*ast.LiteralValue)
	if !ok || leftLit.Value != "Hello" {
		t.Error("expected left to be 'Hello'")
	}

	// Verify middle is ' '
	middleLit, ok := innerBinExpr.Right.(*ast.LiteralValue)
	if !ok || middleLit.Value != " " {
		t.Error("expected middle to be ' '")
	}

	// Verify right side is 'World'
	rightLit, ok := outerBinExpr.Right.(*ast.LiteralValue)
	if !ok || rightLit.Value != "World" {
		t.Error("expected right to be 'World'")
	}
}

// TestParser_StringConcatWithColumns tests || with column names
func TestParser_StringConcatWithColumns(t *testing.T) {
	// SELECT first_name || ' ' || last_name FROM users
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "first_name"},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeString, Literal: " "},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeIdentifier, Literal: "last_name"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// Should be a binary expression
	binExpr, ok := stmt.Columns[0].(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression, got %T", stmt.Columns[0])
	}

	if binExpr.Operator != "||" {
		t.Errorf("expected operator '||', got %q", binExpr.Operator)
	}
}

// TestParser_StringConcatWithAlias tests || with AS alias
func TestParser_StringConcatWithAlias(t *testing.T) {
	// SELECT first_name || last_name AS fullname FROM users
	tokens := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeIdentifier, Literal: "first_name"},
		{Type: models.TokenTypeStringConcat, Literal: "||"},
		{Type: models.TokenTypeIdentifier, Literal: "last_name"},
		{Type: models.TokenTypeAs, Literal: "AS"},
		{Type: models.TokenTypeIdentifier, Literal: "fullname"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt := tree.Statements[0].(*ast.SelectStatement)
	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an AliasedExpression
	aliased, ok := stmt.Columns[0].(*ast.AliasedExpression)
	if !ok {
		t.Fatalf("expected AliasedExpression, got %T", stmt.Columns[0])
	}

	// The expression should be a BinaryExpression with ||
	binExpr, ok := aliased.Expr.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected BinaryExpression in alias, got %T", aliased.Expr)
	}

	if binExpr.Operator != "||" {
		t.Errorf("expected operator '||', got %q", binExpr.Operator)
	}

	// Verify alias name
	if aliased.Alias != "fullname" {
		t.Errorf("expected alias 'fullname', got %q", aliased.Alias)
	}
}

// TestParser_PostgreSQLRegexOperators tests PostgreSQL regex matching operators (~, ~*, !~, !~*)
// Issue #190: Support PostgreSQL regular expression operators
func TestParser_PostgreSQLRegexOperators(t *testing.T) {
	tests := []struct {
		name     string
		tokens   []token.Token
		operator string
	}{
		{
			name: "Tilde operator - case-sensitive regex match",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeTilde, Literal: "~"},
				{Type: models.TokenTypeString, Literal: "^J.*"},
			},
			operator: "~",
		},
		{
			name: "Tilde-asterisk operator - case-insensitive regex match",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "products"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "description"},
				{Type: models.TokenTypeTildeAsterisk, Literal: "~*"},
				{Type: models.TokenTypeString, Literal: "sale|discount"},
			},
			operator: "~*",
		},
		{
			name: "Exclamation-tilde operator - case-sensitive regex non-match",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "logs"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "message"},
				{Type: models.TokenTypeExclamationMarkTilde, Literal: "!~"},
				{Type: models.TokenTypeString, Literal: "DEBUG"},
			},
			operator: "!~",
		},
		{
			name: "Exclamation-tilde-asterisk operator - case-insensitive regex non-match",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "emails"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "subject"},
				{Type: models.TokenTypeExclamationMarkTildeAsterisk, Literal: "!~*"},
				{Type: models.TokenTypeString, Literal: "spam"},
			},
			operator: "!~*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(tt.tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer ast.ReleaseAST(tree)

			stmt := tree.Statements[0].(*ast.SelectStatement)
			if stmt.Where == nil {
				t.Fatal("expected WHERE clause")
			}

			binExpr, ok := stmt.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
			}

			if binExpr.Operator != tt.operator {
				t.Errorf("expected operator %q, got %q", tt.operator, binExpr.Operator)
			}

			// Verify left side is an identifier
			_, ok = binExpr.Left.(*ast.Identifier)
			if !ok {
				t.Errorf("expected left side to be Identifier, got %T", binExpr.Left)
			}

			// Verify right side is a literal value (the regex pattern)
			_, ok = binExpr.Right.(*ast.LiteralValue)
			if !ok {
				t.Errorf("expected right side to be LiteralValue, got %T", binExpr.Right)
			}
		})
	}
}

// TestParser_PostgreSQLRegexWithComplexExpressions tests regex operators in complex expressions
func TestParser_PostgreSQLRegexWithComplexExpressions(t *testing.T) {
	tests := []struct {
		name   string
		tokens []token.Token
	}{
		{
			name: "Regex with AND condition",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "users"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeTilde, Literal: "~"},
				{Type: models.TokenTypeString, Literal: "^[A-Z]"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "email"},
				{Type: models.TokenTypeTildeAsterisk, Literal: "~*"},
				{Type: models.TokenTypeString, Literal: "@example\\.com$"},
			},
		},
		{
			name: "Regex with OR condition",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "products"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "name"},
				{Type: models.TokenTypeExclamationMarkTilde, Literal: "!~"},
				{Type: models.TokenTypeString, Literal: "deprecated"},
				{Type: models.TokenTypeOr, Literal: "OR"},
				{Type: models.TokenTypeIdentifier, Literal: "status"},
				{Type: models.TokenTypeEq, Literal: "="},
				{Type: models.TokenTypeString, Literal: "active"},
			},
		},
		{
			name: "Multiple regex operators",
			tokens: []token.Token{
				{Type: models.TokenTypeSelect, Literal: "SELECT"},
				{Type: models.TokenTypeAsterisk, Literal: "*"},
				{Type: models.TokenTypeFrom, Literal: "FROM"},
				{Type: models.TokenTypeIdentifier, Literal: "logs"},
				{Type: models.TokenTypeWhere, Literal: "WHERE"},
				{Type: models.TokenTypeIdentifier, Literal: "message"},
				{Type: models.TokenTypeTilde, Literal: "~"},
				{Type: models.TokenTypeString, Literal: "ERROR"},
				{Type: models.TokenTypeAnd, Literal: "AND"},
				{Type: models.TokenTypeIdentifier, Literal: "message"},
				{Type: models.TokenTypeExclamationMarkTildeAsterisk, Literal: "!~*"},
				{Type: models.TokenTypeString, Literal: "ignored"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(tt.tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer ast.ReleaseAST(tree)

			stmt := tree.Statements[0].(*ast.SelectStatement)
			if stmt.Where == nil {
				t.Fatal("expected WHERE clause")
			}

			// The WHERE clause should contain a complex expression with regex operators
			_, ok := stmt.Where.(*ast.BinaryExpression)
			if !ok {
				t.Fatalf("expected BinaryExpression, got %T", stmt.Where)
			}
		})
	}
}
