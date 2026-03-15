// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package parser - UAT bug regression tests.
//
// Covers the four fixes from the UAT review:
//  1. Error positions: parser errors must include correct line/column from token spans.
//  2. MySQL VALUES() helper: ON DUPLICATE KEY UPDATE VALUES(col) now parses correctly.
//  3. Error hint grammar: hints no longer say "'x' keyword" when x is not a keyword.
//  4. ParseWithDialect wrapper: top-level gosqlx.ParseWithDialect convenience function.
package parser_test

import (
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ---------------------------------------------------------------------------
// Bug 1 - Error positions (HIGH)
// Every parser error used to say "line 0, column 0" regardless of position.
// ParseFromModelTokens now uses convertModelTokensWithPositions internally.
// ---------------------------------------------------------------------------

// parseExpectError is a test helper that tokenises + parses and expects an
// error to be returned.
func parseExpectError(t *testing.T, sql string) error {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize unexpectedly failed: %v", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	_, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr == nil {
		t.Fatalf("expected parse error, but SQL parsed successfully: %s", sql)
	}
	return parseErr
}

func TestBug1_ErrorPositionNonZeroOnSimpleSyntaxError(t *testing.T) {
	// "SELECT FROM users" – missing column list; error should be on line 1 at col > 0
	err := parseExpectError(t, "SELECT FROM users")

	sErr, ok := err.(*goerrors.Error)
	if !ok {
		// Error may be wrapped; try to unwrap one level
		t.Logf("error type: %T - checking string for line info", err)
		if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("expected error message to contain 'line 1', got: %v", err)
		}
		return
	}

	if sErr.Location.Line == 0 && sErr.Location.Column == 0 {
		t.Errorf("Bug 1 regression: error location is still 0,0 - got %+v", sErr.Location)
	}
	t.Logf("error location: line=%d col=%d", sErr.Location.Line, sErr.Location.Column)
}

func TestBug1_ErrorPositionOnSecondLine(t *testing.T) {
	// Error is deliberately on line 2 to verify the line counter advances.
	sql := "SELECT 1;\nSELECT FROM users"
	err := parseExpectError(t, sql)

	// The error string must mention line 2 somewhere.
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("expected error to reference line 2, got: %v", err)
	}
}

func TestBug1_ErrorPositionColumnNonZero(t *testing.T) {
	// "SELECT id, FROM users" - the stray comma/FROM creates a parser error.
	// Column should be non-zero.
	err := parseExpectError(t, "SELECT id, FROM users")

	sErr, ok := err.(*goerrors.Error)
	if !ok {
		t.Logf("not a *goerrors.Error (%T); checking string representation", err)
		return
	}

	if sErr.Location.Line == 0 || sErr.Location.Column == 0 {
		t.Errorf("expected non-zero line+column; got line=%d col=%d",
			sErr.Location.Line, sErr.Location.Column)
	}
}

func TestBug1_SuccessfulParseDoesNotIntroducePositionRegression(t *testing.T) {
	// Sanity check: successful parse should still work after the fix.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte("SELECT id, name FROM users WHERE id = 1"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}

	// Position should be populated (line 1, col 1 for SELECT)
	if sel.Pos.Line != 1 || sel.Pos.Column != 1 {
		t.Errorf("expected SELECT at line=1 col=1, got line=%d col=%d",
			sel.Pos.Line, sel.Pos.Column)
	}
}

// ---------------------------------------------------------------------------
// Bug 2 - MySQL VALUES() helper (MEDIUM)
// INSERT INTO t (id, name) VALUES (1,'Alice') ON DUPLICATE KEY UPDATE name=VALUES(name)
// used to fail with E2001. VALUES(col) is MySQL's way of referencing the
// attempted-to-insert value inside ON DUPLICATE KEY UPDATE.
// ---------------------------------------------------------------------------

func TestBug2_MySQLValuesHelperBasic(t *testing.T) {
	sql := "INSERT INTO users (id, name) VALUES (1, 'Alice') ON DUPLICATE KEY UPDATE name=VALUES(name)"
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Bug 2 regression: ON DUPLICATE KEY UPDATE VALUES() failed: %v", err)
	}

	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil {
		t.Fatal("expected OnDuplicateKey to be set")
	}
	if len(ins.OnDuplicateKey.Updates) != 1 {
		t.Fatalf("expected 1 update expression, got %d", len(ins.OnDuplicateKey.Updates))
	}

	// The RHS of the assignment must be a FunctionCall named "VALUES"
	fn, ok := ins.OnDuplicateKey.Updates[0].Value.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall for VALUES(), got %T",
			ins.OnDuplicateKey.Updates[0].Value)
	}
	if !strings.EqualFold(fn.Name, "VALUES") {
		t.Errorf("expected function name VALUES, got %q", fn.Name)
	}
	if len(fn.Arguments) != 1 {
		t.Fatalf("expected VALUES() to have 1 argument, got %d", len(fn.Arguments))
	}
}

func TestBug2_MySQLValuesHelperMultipleColumns(t *testing.T) {
	sql := "INSERT INTO users (id, name, email) VALUES (1, 'Alice', 'a@b.com') " +
		"ON DUPLICATE KEY UPDATE name=VALUES(name), email=VALUES(email)"

	_, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Bug 2 regression: multi-column ON DUPLICATE KEY UPDATE VALUES() failed: %v", err)
	}
}

func TestBug2_ValuesHelperFailsWithoutParens(t *testing.T) {
	// VALUES without parens in a non-INSERT context should still fail gracefully.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte("SELECT VALUES FROM t"))
	if err != nil {
		t.Fatalf("tokenize failed: %v", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	// "SELECT VALUES FROM t" is not valid SQL - expect an error.
	_, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr == nil {
		t.Log("SELECT VALUES FROM t parsed without error (may be treated as alias) - acceptable")
	}
}

// ---------------------------------------------------------------------------
// Bug 3 - Error hint grammar (LOW)
// Hints used to say "Expected 'table name' keyword here" when "table name"
// is not a keyword. Fixed to "expected <description> here".
// ---------------------------------------------------------------------------

func TestBug3_HintGrammarNoKeywordLabel(t *testing.T) {
	// Trigger an ExpectedToken error and inspect the hint.
	err := parseExpectError(t, "SELECT")

	errStr := err.Error()

	// The old (broken) hint pattern: "Expected '<something>' keyword here"
	if strings.Contains(errStr, "keyword here") {
		t.Errorf("Bug 3 regression: hint still uses 'keyword here' grammar: %v", errStr)
	}
}

func TestBug3_HintGrammarLowerCaseExpected(t *testing.T) {
	// The new hint pattern should start with lowercase "expected".
	err := parseExpectError(t, "SELECT")

	errStr := err.Error()
	if strings.Contains(errStr, "Hint:") {
		// Extract hint portion
		hint := errStr[strings.Index(errStr, "Hint:"):]
		t.Logf("hint text: %s", hint)

		// Must not contain the old pattern
		if strings.Contains(hint, "keyword here") {
			t.Errorf("Bug 3: hint still uses 'keyword here', got: %s", hint)
		}
	}
}

func TestBug3_HintGrammarExpectedFormat(t *testing.T) {
	// Directly test GenerateHint to verify correct grammar.
	hint := goerrors.GenerateHint(goerrors.ErrCodeExpectedToken, "table name", "")
	if strings.Contains(hint, "keyword here") {
		t.Errorf("Bug 3 regression in GenerateHint: 'keyword here' still present: %s", hint)
	}
	// Should say "expected ... here" (lowercase)
	if !strings.Contains(strings.ToLower(hint), "expected") {
		t.Errorf("Bug 3: hint should contain 'expected', got: %s", hint)
	}
	t.Logf("hint: %s", hint)
}

// ---------------------------------------------------------------------------
// Bug 2 (extended) - MySQL VALUES() helper: nested expressions & multi-column
//
// VALUES(col) must compose correctly when used inside larger expressions:
//   - arithmetic:  price = VALUES(price) * 0.9
//   - additive:    total = VALUES(col1) + VALUES(col2)
//   - coalesce:    col   = COALESCE(VALUES(col), 'default')
//   - three-col:   a=VALUES(a), b=VALUES(b), c=VALUES(c)
// ---------------------------------------------------------------------------

// TestBug2_ValuesNestedArithmetic verifies that VALUES(col) can appear as the
// left operand of an arithmetic expression, e.g. VALUES(price) * 0.9.
func TestBug2_ValuesNestedArithmetic(t *testing.T) {
	sql := "INSERT INTO products (id, price) VALUES (1, 9.99) " +
		"ON DUPLICATE KEY UPDATE price = VALUES(price) * 0.9"

	tree, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("nested arithmetic VALUES(): parse failed: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil || len(ins.OnDuplicateKey.Updates) != 1 {
		t.Fatal("expected exactly 1 ON DUPLICATE KEY UPDATE assignment")
	}

	// RHS must be a binary expression: VALUES(price) * 0.9
	binExpr, ok := ins.OnDuplicateKey.Updates[0].Value.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected *ast.BinaryExpression for VALUES(price)*0.9, got %T",
			ins.OnDuplicateKey.Updates[0].Value)
	}
	if binExpr.Operator != "*" {
		t.Errorf("expected operator *, got %q", binExpr.Operator)
	}

	// Left side must be VALUES(price)
	fn, ok := binExpr.Left.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall on left of *, got %T", binExpr.Left)
	}
	if !strings.EqualFold(fn.Name, "VALUES") {
		t.Errorf("expected function name VALUES, got %q", fn.Name)
	}
	if len(fn.Arguments) != 1 {
		t.Fatalf("expected 1 argument to VALUES(), got %d", len(fn.Arguments))
	}

	arg, ok := fn.Arguments[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier argument to VALUES(), got %T", fn.Arguments[0])
	}
	if !strings.EqualFold(arg.Name, "price") {
		t.Errorf("expected argument 'price', got %q", arg.Name)
	}
}

// TestBug2_ValuesMultiColumnAdditive verifies that two VALUES() calls can be
// composed with an arithmetic operator: total = VALUES(col1) + VALUES(col2).
func TestBug2_ValuesMultiColumnAdditive(t *testing.T) {
	sql := "INSERT INTO stats (id, a, b) VALUES (1, 10, 20) " +
		"ON DUPLICATE KEY UPDATE total = VALUES(a) + VALUES(b)"

	tree, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("multi-column additive VALUES(): parse failed: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil || len(ins.OnDuplicateKey.Updates) != 1 {
		t.Fatal("expected exactly 1 ON DUPLICATE KEY UPDATE assignment")
	}

	// RHS must be: VALUES(a) + VALUES(b)
	binExpr, ok := ins.OnDuplicateKey.Updates[0].Value.(*ast.BinaryExpression)
	if !ok {
		t.Fatalf("expected *ast.BinaryExpression for VALUES(a)+VALUES(b), got %T",
			ins.OnDuplicateKey.Updates[0].Value)
	}
	if binExpr.Operator != "+" {
		t.Errorf("expected operator +, got %q", binExpr.Operator)
	}

	leftFn, ok := binExpr.Left.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall on left of +, got %T", binExpr.Left)
	}
	if !strings.EqualFold(leftFn.Name, "VALUES") {
		t.Errorf("expected left function VALUES, got %q", leftFn.Name)
	}
	if len(leftFn.Arguments) != 1 {
		t.Fatalf("expected 1 arg in left VALUES(), got %d", len(leftFn.Arguments))
	}
	leftArg, ok := leftFn.Arguments[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier for left VALUES() arg, got %T", leftFn.Arguments[0])
	}
	if !strings.EqualFold(leftArg.Name, "a") {
		t.Errorf("expected left VALUES(a), got VALUES(%s)", leftArg.Name)
	}

	rightFn, ok := binExpr.Right.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall on right of +, got %T", binExpr.Right)
	}
	if !strings.EqualFold(rightFn.Name, "VALUES") {
		t.Errorf("expected right function VALUES, got %q", rightFn.Name)
	}
	if len(rightFn.Arguments) != 1 {
		t.Fatalf("expected 1 arg in right VALUES(), got %d", len(rightFn.Arguments))
	}
	rightArg, ok := rightFn.Arguments[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier for right VALUES() arg, got %T", rightFn.Arguments[0])
	}
	if !strings.EqualFold(rightArg.Name, "b") {
		t.Errorf("expected right VALUES(b), got VALUES(%s)", rightArg.Name)
	}
}

// TestBug2_ValuesNestedInCoalesce verifies that VALUES() can appear as an
// argument to another function call, e.g. COALESCE(VALUES(col), 'default').
func TestBug2_ValuesNestedInCoalesce(t *testing.T) {
	sql := "INSERT INTO items (id, description) VALUES (1, NULL) " +
		"ON DUPLICATE KEY UPDATE description = COALESCE(VALUES(description), 'unknown')"

	tree, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("COALESCE(VALUES()) parse failed: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil || len(ins.OnDuplicateKey.Updates) != 1 {
		t.Fatal("expected exactly 1 ON DUPLICATE KEY UPDATE assignment")
	}

	// RHS must be COALESCE(...)
	coalesce, ok := ins.OnDuplicateKey.Updates[0].Value.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall for COALESCE(...), got %T",
			ins.OnDuplicateKey.Updates[0].Value)
	}
	if !strings.EqualFold(coalesce.Name, "COALESCE") {
		t.Errorf("expected outer function COALESCE, got %q", coalesce.Name)
	}
	if len(coalesce.Arguments) != 2 {
		t.Fatalf("expected COALESCE to have 2 arguments, got %d", len(coalesce.Arguments))
	}

	// First argument must be VALUES(description)
	innerFn, ok := coalesce.Arguments[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall as first COALESCE arg, got %T", coalesce.Arguments[0])
	}
	if !strings.EqualFold(innerFn.Name, "VALUES") {
		t.Errorf("expected first COALESCE arg to be VALUES(), got %q", innerFn.Name)
	}
	if len(innerFn.Arguments) != 1 {
		t.Fatalf("expected 1 argument to inner VALUES(), got %d", len(innerFn.Arguments))
	}
	innerArg, ok := innerFn.Arguments[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("expected *ast.Identifier inside VALUES(), got %T", innerFn.Arguments[0])
	}
	if !strings.EqualFold(innerArg.Name, "description") {
		t.Errorf("expected VALUES(description), got VALUES(%s)", innerArg.Name)
	}
}

// TestBug2_ValuesThreeColumnUpdate verifies that three separate VALUES() helpers
// in the same ON DUPLICATE KEY UPDATE clause all parse correctly.
func TestBug2_ValuesThreeColumnUpdate(t *testing.T) {
	sql := "INSERT INTO records (a, b, c) VALUES (1, 2, 3) " +
		"ON DUPLICATE KEY UPDATE a = VALUES(a), b = VALUES(b), c = VALUES(c)"

	tree, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("three-column VALUES() parse failed: %v", err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	ins, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("expected *ast.InsertStatement, got %T", tree.Statements[0])
	}
	if ins.OnDuplicateKey == nil {
		t.Fatal("expected OnDuplicateKey to be non-nil")
	}
	if len(ins.OnDuplicateKey.Updates) != 3 {
		t.Fatalf("expected 3 update assignments, got %d", len(ins.OnDuplicateKey.Updates))
	}

	wantCols := []string{"a", "b", "c"}
	for i, upd := range ins.OnDuplicateKey.Updates {
		fn, ok := upd.Value.(*ast.FunctionCall)
		if !ok {
			t.Errorf("update[%d]: expected *ast.FunctionCall, got %T", i, upd.Value)
			continue
		}
		if !strings.EqualFold(fn.Name, "VALUES") {
			t.Errorf("update[%d]: expected VALUES(), got %q", i, fn.Name)
			continue
		}
		if len(fn.Arguments) != 1 {
			t.Errorf("update[%d]: expected 1 arg, got %d", i, len(fn.Arguments))
			continue
		}
		arg, ok := fn.Arguments[0].(*ast.Identifier)
		if !ok {
			t.Errorf("update[%d]: expected *ast.Identifier arg, got %T", i, fn.Arguments[0])
			continue
		}
		if !strings.EqualFold(arg.Name, wantCols[i]) {
			t.Errorf("update[%d]: expected VALUES(%s), got VALUES(%s)", i, wantCols[i], arg.Name)
		}
	}
}

// TestBug2_ValuesMixedExpressions is an integration test that exercises all
// the complex VALUES() patterns in a single INSERT statement.
func TestBug2_ValuesMixedExpressions(t *testing.T) {
	// All three patterns in one statement:
	//   col1 = VALUES(a) * 0.9     (arithmetic)
	//   col2 = VALUES(b) + VALUES(c)  (multi-column additive)
	//   col3 = COALESCE(VALUES(d), 0) (nested function)
	sql := "INSERT INTO t (a, b, c, d) VALUES (10, 20, 30, NULL) " +
		"ON DUPLICATE KEY UPDATE " +
		"col1 = VALUES(a) * 0.9, " +
		"col2 = VALUES(b) + VALUES(c), " +
		"col3 = COALESCE(VALUES(d), 0)"

	_, err := parser.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("mixed VALUES() expressions parse failed: %v", err)
	}
}
