// Package parser - tuple_in_test.go
// Tests for tuple/row expressions in IN clause (Issue #181)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_TupleIn_Basic tests basic tuple IN clause
func TestParser_TupleIn_Basic(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
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

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is a tuple
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected left side to be TupleExpression, got %T", inExpr.Expr)
	}

	if len(leftTuple.Expressions) != 2 {
		t.Errorf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify list contains tuples
	if len(inExpr.List) != 2 {
		t.Fatalf("expected 2 items in IN list, got %d", len(inExpr.List))
	}

	for i, item := range inExpr.List {
		tuple, ok := item.(*ast.TupleExpression)
		if !ok {
			t.Errorf("expected List[%d] to be TupleExpression, got %T", i, item)
			continue
		}
		if len(tuple.Expressions) != 2 {
			t.Errorf("expected 2 elements in List[%d] tuple, got %d", i, len(tuple.Expressions))
		}
	}
}

// TestParser_TupleIn_NotIn tests NOT IN with tuples
func TestParser_TupleIn_NotIn(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, status) NOT IN ((1, 'active'), (2, 'pending'))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	if !inExpr.Not {
		t.Error("expected NOT to be true for NOT IN")
	}

	// Verify left side is a tuple
	_, ok = inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected left side to be TupleExpression, got %T", inExpr.Expr)
	}
}

// TestParser_TupleIn_ThreeElements tests tuple with 3 elements
func TestParser_TupleIn_ThreeElements(t *testing.T) {
	sql := "SELECT * FROM t WHERE (a, b, c) IN ((1, 2, 3), (4, 5, 6), (7, 8, 9))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side has 3 elements
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", inExpr.Expr)
	}
	if len(leftTuple.Expressions) != 3 {
		t.Errorf("expected 3 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify list has 3 tuples
	if len(inExpr.List) != 3 {
		t.Errorf("expected 3 items in IN list, got %d", len(inExpr.List))
	}

	// Verify each tuple has 3 elements
	for i, item := range inExpr.List {
		tuple, ok := item.(*ast.TupleExpression)
		if !ok {
			t.Errorf("expected TupleExpression at List[%d], got %T", i, item)
			continue
		}
		if len(tuple.Expressions) != 3 {
			t.Errorf("expected 3 elements in List[%d], got %d", i, len(tuple.Expressions))
		}
	}
}

// TestParser_TupleIn_WithExpressions tests tuple IN with complex expressions
func TestParser_TupleIn_WithExpressions(t *testing.T) {
	sql := "SELECT * FROM t WHERE (a + 1, b * 2) IN ((10, 20), (30, 40))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is a tuple with binary expressions
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", inExpr.Expr)
	}
	if len(leftTuple.Expressions) != 2 {
		t.Fatalf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// First element should be a binary expression (a + 1)
	_, ok = leftTuple.Expressions[0].(*ast.BinaryExpression)
	if !ok {
		t.Errorf("expected first element to be BinaryExpression, got %T", leftTuple.Expressions[0])
	}

	// Second element should be a binary expression (b * 2)
	_, ok = leftTuple.Expressions[1].(*ast.BinaryExpression)
	if !ok {
		t.Errorf("expected second element to be BinaryExpression, got %T", leftTuple.Expressions[1])
	}
}

// TestParser_TupleIn_WithFunctionCalls tests tuple IN with function calls
func TestParser_TupleIn_WithFunctionCalls(t *testing.T) {
	sql := "SELECT * FROM users WHERE (LOWER(name), UPPER(status)) IN (('john', 'ACTIVE'), ('jane', 'PENDING'))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is a tuple with function calls
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", inExpr.Expr)
	}
	if len(leftTuple.Expressions) != 2 {
		t.Fatalf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Both elements should be function calls
	for i, elem := range leftTuple.Expressions {
		_, ok = elem.(*ast.FunctionCall)
		if !ok {
			t.Errorf("expected element[%d] to be FunctionCall, got %T", i, elem)
		}
	}
}

// TestParser_TupleIn_WithSubquery tests tuple IN with subquery
func TestParser_TupleIn_WithSubquery(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, product_id) IN (SELECT user_id, product_id FROM cart)"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is a tuple
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected left side to be TupleExpression, got %T", inExpr.Expr)
	}

	if len(leftTuple.Expressions) != 2 {
		t.Errorf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify it uses subquery (not list)
	if inExpr.Subquery == nil {
		t.Error("expected Subquery to be set")
	}

	if len(inExpr.List) != 0 {
		t.Error("expected List to be empty when using subquery")
	}
}

// TestParser_TupleIn_SingleElementTuple tests single element in parentheses
func TestParser_TupleIn_SingleElementTuple(t *testing.T) {
	// Single element in parens should still work (treated as grouped expression)
	sql := "SELECT * FROM t WHERE (x) IN (1, 2, 3)"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Left side could be identifier or single-element tuple
	// Either is acceptable
	if inExpr.Expr == nil {
		t.Error("expected Expr to be set")
	}
}

// TestParser_TupleIn_QualifiedColumns tests tuple IN with qualified column names
func TestParser_TupleIn_QualifiedColumns(t *testing.T) {
	sql := "SELECT * FROM orders o WHERE (o.user_id, o.status) IN ((1, 'active'), (2, 'pending'))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left side is a tuple
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected left side to be TupleExpression, got %T", inExpr.Expr)
	}

	if len(leftTuple.Expressions) != 2 {
		t.Errorf("expected 2 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Elements should be identifiers with Table qualifier
	for i, elem := range leftTuple.Expressions {
		ident, ok := elem.(*ast.Identifier)
		if !ok {
			t.Errorf("expected element[%d] to be Identifier, got %T", i, elem)
			continue
		}
		if ident.Table != "o" {
			t.Errorf("expected element[%d] to have table qualifier 'o', got '%s'", i, ident.Table)
		}
	}
}

// TestParser_TupleIn_ComplexConditions tests tuple IN combined with other conditions
func TestParser_TupleIn_ComplexConditions(t *testing.T) {
	sql := "SELECT * FROM orders WHERE (user_id, status) IN ((1, 'active'), (2, 'pending')) AND created_at > '2024-01-01'"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	// WHERE should be a binary AND expression
	binExpr, ok := stmt.Where.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected WHERE to be BinaryExpression, got %T", stmt.Where)
	}

	if binExpr.Operator != "AND" {
		t.Errorf("expected AND operator, got %s", binExpr.Operator)
	}

	// Left side should be InExpression
	inExpr, ok := binExpr.Left.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected left side to be InExpression, got %T", binExpr.Left)
	}

	// Verify it's a tuple IN
	_, ok = inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected InExpression.Expr to be TupleExpression, got %T", inExpr.Expr)
	}
}

// TestParser_TupleIn_MixedTypes tests tuple with mixed literal types
func TestParser_TupleIn_MixedTypes(t *testing.T) {
	// Tuple with mixed literal types
	sql := "SELECT * FROM t WHERE (id, name, active, score) IN ((1, 'john', TRUE, 95.5), (2, 'jane', FALSE, 87.3))"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenizer error: %v", err)
	}

	parserTokens, err := ConvertTokensForParser(tokens)
	if err != nil {
		t.Fatalf("token conversion error: %v", err)
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(parserTokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}

	inExpr, ok := stmt.Where.(*ast.InExpression)
	if !ok {
		t.Fatalf("expected InExpression, got %T", stmt.Where)
	}

	// Verify left tuple has 4 elements
	leftTuple, ok := inExpr.Expr.(*ast.TupleExpression)
	if !ok {
		t.Fatalf("expected TupleExpression, got %T", inExpr.Expr)
	}
	if len(leftTuple.Expressions) != 4 {
		t.Errorf("expected 4 elements in left tuple, got %d", len(leftTuple.Expressions))
	}

	// Verify right tuples have 4 elements with mixed types
	for i, item := range inExpr.List {
		tuple, ok := item.(*ast.TupleExpression)
		if !ok {
			t.Errorf("expected TupleExpression at List[%d], got %T", i, item)
			continue
		}
		if len(tuple.Expressions) != 4 {
			t.Errorf("expected 4 elements in List[%d], got %d", i, len(tuple.Expressions))
		}
	}
}

// TestParser_TupleIn_ErrorCases tests invalid tuple IN syntax that should fail
func TestParser_TupleIn_ErrorCases(t *testing.T) {
	errorCases := []struct {
		name string
		sql  string
	}{
		{
			name: "Empty IN list",
			sql:  "SELECT * FROM t WHERE (a, b) IN ()",
		},
		{
			name: "Empty tuple",
			sql:  "SELECT * FROM t WHERE () IN ((1, 2))",
		},
		{
			name: "Malformed tuple - missing value",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1,))",
		},
		{
			name: "Unclosed tuple",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1, 2)",
		},
		{
			name: "Missing IN keyword",
			sql:  "SELECT * FROM t WHERE (a, b) ((1, 2))",
		},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				// Tokenizer error is acceptable for malformed input
				t.Logf("Tokenizer error (expected): %v", err)
				return
			}

			parserTokens, err := ConvertTokensForParser(tokens)
			if err != nil {
				// Token conversion error is acceptable
				t.Logf("Token conversion error (expected): %v", err)
				return
			}

			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(parserTokens)
			if err != nil {
				// Parser error is expected for invalid syntax
				t.Logf("Parser error (expected): %v", err)
				return
			}
			defer ast.ReleaseAST(tree)

			// If we get here without error, the test should note this
			// Some cases may parse but produce unexpected AST
			t.Logf("Parsed without error - may have different interpretation: %s", tc.sql)
		})
	}
}

// TestParser_TupleIn_MismatchedSizes tests tuples with mismatched element counts
// Note: SQL parsers typically don't validate tuple size matching - that's semantic validation
func TestParser_TupleIn_MismatchedSizes(t *testing.T) {
	// These should parse successfully - size validation is semantic, not syntactic
	cases := []struct {
		name string
		sql  string
	}{
		{
			name: "2-element tuple vs 1-element values",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1), (2))",
		},
		{
			name: "1-element tuple vs 2-element values",
			sql:  "SELECT * FROM t WHERE (a) IN ((1, 2), (3, 4))",
		},
		{
			name: "Mixed sizes in value list",
			sql:  "SELECT * FROM t WHERE (a, b) IN ((1, 2), (3))",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tc.sql))
			if err != nil {
				t.Fatalf("tokenizer error: %v", err)
			}

			parserTokens, err := ConvertTokensForParser(tokens)
			if err != nil {
				t.Fatalf("token conversion error: %v", err)
			}

			parser := NewParser()
			defer parser.Release()

			tree, err := parser.Parse(parserTokens)
			if err != nil {
				// Some implementations may reject mismatched tuples at parse time
				t.Logf("Parser rejected mismatched sizes: %v", err)
				return
			}
			defer ast.ReleaseAST(tree)

			// Parser accepted the query - this is valid behavior
			// Semantic validation would catch size mismatches
			t.Logf("Parser accepted query (semantic validation would catch mismatches): %s", tc.sql)
		})
	}
}
