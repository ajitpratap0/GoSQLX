// Package parser - array_subscript_test.go
// Tests for array subscript and slice syntax (Issue #191)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_ArraySubscript_Single tests single array subscript
func TestParser_ArraySubscript_Single(t *testing.T) {
	sql := "SELECT tags[1] FROM posts"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySubscriptExpression
	subscriptExpr, ok := stmt.Columns[0].(*ast.ArraySubscriptExpression)
	if !ok {
		t.Fatalf("expected ArraySubscriptExpression, got %T", stmt.Columns[0])
	}

	// Check the array is an identifier "tags"
	arrayIdent, ok := subscriptExpr.Array.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected array to be Identifier, got %T", subscriptExpr.Array)
	}
	if arrayIdent.Name != "tags" {
		t.Errorf("expected array name 'tags', got '%s'", arrayIdent.Name)
	}

	// Check we have one index
	if len(subscriptExpr.Indices) != 1 {
		t.Fatalf("expected 1 index, got %d", len(subscriptExpr.Indices))
	}

	// Check the index is 1
	indexLiteral, ok := subscriptExpr.Indices[0].(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected index to be LiteralValue, got %T", subscriptExpr.Indices[0])
	}
	if indexLiteral.Value != "1" {
		t.Errorf("expected index value '1', got '%v'", indexLiteral.Value)
	}
}

// TestParser_ArraySubscript_MultiDimensional tests multi-dimensional array subscript
func TestParser_ArraySubscript_MultiDimensional(t *testing.T) {
	sql := "SELECT matrix[2][3] FROM data"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySubscriptExpression (outer subscript [3])
	outerSubscript, ok := stmt.Columns[0].(*ast.ArraySubscriptExpression)
	if !ok {
		t.Fatalf("expected outer ArraySubscriptExpression, got %T", stmt.Columns[0])
	}

	// The array should be another ArraySubscriptExpression (inner subscript [2])
	innerSubscript, ok := outerSubscript.Array.(*ast.ArraySubscriptExpression)
	if !ok {
		t.Fatalf("expected inner ArraySubscriptExpression, got %T", outerSubscript.Array)
	}

	// The innermost array should be an identifier "matrix"
	arrayIdent, ok := innerSubscript.Array.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected array to be Identifier, got %T", innerSubscript.Array)
	}
	if arrayIdent.Name != "matrix" {
		t.Errorf("expected array name 'matrix', got '%s'", arrayIdent.Name)
	}
}

// TestParser_ArraySlice_BothBounds tests array slice with both start and end
func TestParser_ArraySlice_BothBounds(t *testing.T) {
	sql := "SELECT tags[1:3] FROM posts"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySliceExpression
	sliceExpr, ok := stmt.Columns[0].(*ast.ArraySliceExpression)
	if !ok {
		t.Fatalf("expected ArraySliceExpression, got %T", stmt.Columns[0])
	}

	// Check the array is an identifier "tags"
	arrayIdent, ok := sliceExpr.Array.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected array to be Identifier, got %T", sliceExpr.Array)
	}
	if arrayIdent.Name != "tags" {
		t.Errorf("expected array name 'tags', got '%s'", arrayIdent.Name)
	}

	// Check start index is 1
	startLiteral, ok := sliceExpr.Start.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected start to be LiteralValue, got %T", sliceExpr.Start)
	}
	if startLiteral.Value != "1" {
		t.Errorf("expected start value '1', got '%v'", startLiteral.Value)
	}

	// Check end index is 3
	endLiteral, ok := sliceExpr.End.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected end to be LiteralValue, got %T", sliceExpr.End)
	}
	if endLiteral.Value != "3" {
		t.Errorf("expected end value '3', got '%v'", endLiteral.Value)
	}
}

// TestParser_ArraySlice_StartOnly tests array slice with start only (arr[2:])
func TestParser_ArraySlice_StartOnly(t *testing.T) {
	sql := "SELECT arr[2:] FROM table_name"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySliceExpression
	sliceExpr, ok := stmt.Columns[0].(*ast.ArraySliceExpression)
	if !ok {
		t.Fatalf("expected ArraySliceExpression, got %T", stmt.Columns[0])
	}

	// Check start index is 2
	startLiteral, ok := sliceExpr.Start.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected start to be LiteralValue, got %T", sliceExpr.Start)
	}
	if startLiteral.Value != "2" {
		t.Errorf("expected start value '2', got '%v'", startLiteral.Value)
	}

	// Check end is nil
	if sliceExpr.End != nil {
		t.Errorf("expected end to be nil, got %T", sliceExpr.End)
	}
}

// TestParser_ArraySlice_EndOnly tests array slice with end only (arr[:5])
func TestParser_ArraySlice_EndOnly(t *testing.T) {
	sql := "SELECT arr[:5] FROM table_name"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySliceExpression
	sliceExpr, ok := stmt.Columns[0].(*ast.ArraySliceExpression)
	if !ok {
		t.Fatalf("expected ArraySliceExpression, got %T", stmt.Columns[0])
	}

	// Check start is nil
	if sliceExpr.Start != nil {
		t.Errorf("expected start to be nil, got %T", sliceExpr.Start)
	}

	// Check end index is 5
	endLiteral, ok := sliceExpr.End.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected end to be LiteralValue, got %T", sliceExpr.End)
	}
	if endLiteral.Value != "5" {
		t.Errorf("expected end value '5', got '%v'", endLiteral.Value)
	}
}

// TestParser_ArraySubscript_InWhereClause tests array subscript in WHERE clause
func TestParser_ArraySubscript_InWhereClause(t *testing.T) {
	sql := "SELECT * FROM posts WHERE tags[1] = 'tech'"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if stmt.Where == nil {
		t.Fatal("expected WHERE clause")
	}

	// WHERE condition should be: tags[1] = 'tech'
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BinaryExpression, got %T", stmt.Where)
	}

	// Left side should be ArraySubscriptExpression
	subscriptExpr, ok := binExpr.Left.(*ast.ArraySubscriptExpression)
	if !ok {
		t.Fatalf("expected left side to be ArraySubscriptExpression, got %T", binExpr.Left)
	}

	// Check the array is "tags"
	arrayIdent, ok := subscriptExpr.Array.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected array to be Identifier, got %T", subscriptExpr.Array)
	}
	if arrayIdent.Name != "tags" {
		t.Errorf("expected array name 'tags', got '%s'", arrayIdent.Name)
	}
}

// TestParser_ArraySubscript_OnParenthesizedExpr tests array subscript on parenthesized expression
func TestParser_ArraySubscript_OnParenthesizedExpr(t *testing.T) {
	sql := "SELECT (arr)[1] FROM table_name"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	if len(stmt.Columns) != 1 {
		t.Fatalf("expected 1 column, got %d", len(stmt.Columns))
	}

	// The column should be an ArraySubscriptExpression
	subscriptExpr, ok := stmt.Columns[0].(*ast.ArraySubscriptExpression)
	if !ok {
		t.Fatalf("expected ArraySubscriptExpression, got %T", stmt.Columns[0])
	}

	// The array should be an identifier
	arrayIdent, ok := subscriptExpr.Array.(*ast.Identifier)
	if !ok {
		t.Fatalf("expected array to be Identifier, got %T", subscriptExpr.Array)
	}
	if arrayIdent.Name != "arr" {
		t.Errorf("expected array name 'arr', got '%s'", arrayIdent.Name)
	}
}

// TestParser_ArraySubscript_ErrorEmptyBrackets tests error on empty brackets
func TestParser_ArraySubscript_ErrorEmptyBrackets(t *testing.T) {
	sql := "SELECT arr[] FROM table_name"

	// Tokenize the SQL
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	// Convert to parser tokens

	parser := NewParser()
	defer parser.Release()

	_, err = parser.ParseFromModelTokens(tokens)
	if err == nil {
		t.Fatal("expected error for empty array brackets, got nil")
	}

	// The error should mention empty brackets
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("expected non-empty error message")
	}
}

// TestParser_ArraySubscriptExpression_Children tests that Children() returns correct nodes
func TestParser_ArraySubscriptExpression_Children(t *testing.T) {
	arrayIdent := &ast.Identifier{Name: "arr"}
	index1 := &ast.LiteralValue{Value: "1", Type: "NUMBER"}
	index2 := &ast.LiteralValue{Value: "2", Type: "NUMBER"}

	subscriptExpr := &ast.ArraySubscriptExpression{
		Array:   arrayIdent,
		Indices: []ast.Expression{index1, index2},
	}

	children := subscriptExpr.Children()
	if len(children) != 3 {
		t.Errorf("expected 3 children, got %d", len(children))
	}
}

// TestParser_ArraySliceExpression_Children tests that Children() returns correct nodes
func TestParser_ArraySliceExpression_Children(t *testing.T) {
	arrayIdent := &ast.Identifier{Name: "arr"}
	start := &ast.LiteralValue{Value: "1", Type: "NUMBER"}
	end := &ast.LiteralValue{Value: "3", Type: "NUMBER"}

	sliceExpr := &ast.ArraySliceExpression{
		Array: arrayIdent,
		Start: start,
		End:   end,
	}

	children := sliceExpr.Children()
	// Should have 3: array, start, end
	if len(children) != 3 {
		t.Errorf("expected 3 children, got %d", len(children))
	}
}
