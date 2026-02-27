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

// Package parser — regression tests for CORE-1, CORE-2, CORE-3 bug fixes.
package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// helper: tokenize + parse, returning (AST, error). Does NOT call t.Fatal so callers
// can assert errors themselves.
func parseSQLMayFail(t *testing.T, sql string) (*ast.AST, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, err
	}
	p := NewParser()
	defer p.Release()
	return p.ParseFromModelTokens(tokens)
}

// =============================================================================
// CORE-1: KEY reserved keyword blocks a.key qualified identifiers
// =============================================================================

// TestParser_QualifiedNameWithKeyword verifies that KEY (and similar reserved words)
// can be used as the column portion of a qualified identifier (table.KEY).
func TestParser_QualifiedNameWithKeyword(t *testing.T) {
	sql := "SELECT a.key FROM t1 a JOIN t2 b ON a.key = b.key"
	tree, err := parseSQLMayFail(t, sql)
	if err != nil {
		t.Fatalf("CORE-1: qualified name with KEY keyword failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) == 0 {
		t.Fatal("CORE-1: expected at least one statement")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("CORE-1: expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.Columns) == 0 {
		t.Fatal("CORE-1: expected at least one column in SELECT list")
	}
	// The column should be an Identifier with Table="a" and Name="key"
	ident, ok := sel.Columns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("CORE-1: expected Identifier, got %T", sel.Columns[0])
	}
	if ident.Table != "a" || ident.Name != "key" {
		t.Errorf("CORE-1: expected a.key, got %q.%q", ident.Table, ident.Name)
	}
}

// TestParser_QualifiedNameWithKeyword_OtherKeywords tests additional reserved words
// that may appear after a dot.
func TestParser_QualifiedNameWithKeyword_OtherKeywords(t *testing.T) {
	cases := []struct {
		name string
		sql  string
	}{
		{"table.key", "SELECT a.key FROM t a"},
		{"table.index", "SELECT a.index FROM t a"},
		{"table.view", "SELECT a.view FROM t a"},
		{"table.column", "SELECT a.column FROM t a"},
		{"table.database", "SELECT a.database FROM t a"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tree, err := parseSQLMayFail(t, tc.sql)
			if err != nil {
				t.Fatalf("CORE-1 (%s): parse failed: %v", tc.name, err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

// =============================================================================
// CORE-2: NATURAL JOIN stored as "NATURAL INNER" instead of "NATURAL"
// =============================================================================

// TestParser_NaturalJoin verifies that NATURAL JOIN without an explicit type keyword
// produces joinType == "NATURAL" (not "NATURAL INNER").
func TestParser_NaturalJoin(t *testing.T) {
	sql := "SELECT * FROM t1 NATURAL JOIN t2"
	tree, err := parseSQLMayFail(t, sql)
	if err != nil {
		t.Fatalf("CORE-2: NATURAL JOIN failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) == 0 {
		t.Fatal("CORE-2: no statements parsed")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("CORE-2: expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.Joins) == 0 {
		t.Fatal("CORE-2: expected at least one JOIN clause")
	}
	joinType := sel.Joins[0].Type
	if joinType != "NATURAL" {
		t.Fatalf("CORE-2: expected joinType \"NATURAL\", got %q", joinType)
	}
}

// TestParser_NaturalJoinExplicit tests NATURAL INNER JOIN, NATURAL LEFT JOIN, etc.
// — these should still produce "NATURAL INNER", "NATURAL LEFT", etc.
func TestParser_NaturalJoinExplicit(t *testing.T) {
	cases := []struct {
		sql      string
		wantType string
	}{
		{"SELECT * FROM t1 NATURAL INNER JOIN t2", "NATURAL INNER"},
		{"SELECT * FROM t1 NATURAL LEFT JOIN t2", "NATURAL LEFT"},
		{"SELECT * FROM t1 NATURAL RIGHT JOIN t2", "NATURAL RIGHT"},
		{"SELECT * FROM t1 NATURAL FULL JOIN t2", "NATURAL FULL"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.wantType, func(t *testing.T) {
			tree, err := parseSQLMayFail(t, tc.sql)
			if err != nil {
				t.Fatalf("CORE-2 (%s): parse failed: %v", tc.wantType, err)
			}
			defer ast.ReleaseAST(tree)

			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("CORE-2: expected SelectStatement, got %T", tree.Statements[0])
			}
			if len(sel.Joins) == 0 {
				t.Fatal("CORE-2: expected at least one JOIN")
			}
			if sel.Joins[0].Type != tc.wantType {
				t.Errorf("CORE-2: expected %q, got %q", tc.wantType, sel.Joins[0].Type)
			}
		})
	}
}

// =============================================================================
// CORE-3: OVER <window_name> (bare name, no parens) not supported
// =============================================================================

// TestParser_OverWindowName verifies that OVER w (a bare window name reference)
// is parsed correctly. The WINDOW clause definition (WINDOW w AS (...)) is a
// separate parser feature; here we focus only on the OVER <name> syntax.
func TestParser_OverWindowName(t *testing.T) {
	// Using a bare OVER w without an inline WINDOW clause definition — the
	// parser accepts the reference even if no corresponding WINDOW clause is
	// present (the semantic check would be a linting concern, not a parse error).
	sql := "SELECT SUM(amount) OVER w FROM orders"
	tree, err := parseSQLMayFail(t, sql)
	if err != nil {
		t.Fatalf("CORE-3: OVER window_name failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	if len(tree.Statements) == 0 {
		t.Fatal("CORE-3: no statements parsed")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("CORE-3: expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.Columns) == 0 {
		t.Fatal("CORE-3: expected at least one column")
	}
	funcCall, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("CORE-3: expected FunctionCall, got %T", sel.Columns[0])
	}
	if funcCall.Over == nil {
		t.Fatal("CORE-3: expected OVER clause on SUM(amount)")
	}
	if funcCall.Over.Name != "w" {
		t.Errorf("CORE-3: expected window name \"w\", got %q", funcCall.Over.Name)
	}
}

// TestParser_OverWindowName_Simple tests a simpler bare window name reference
// without a WINDOW clause (the parser should still accept it).
func TestParser_OverWindowName_Simple(t *testing.T) {
	sql := "SELECT ROW_NUMBER() OVER w FROM t"
	tree, err := parseSQLMayFail(t, sql)
	if err != nil {
		t.Fatalf("CORE-3: bare OVER window_name failed: %v", err)
	}
	defer ast.ReleaseAST(tree)

	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("CORE-3: expected SelectStatement, got %T", tree.Statements[0])
	}
	funcCall, ok := sel.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("CORE-3: expected FunctionCall, got %T", sel.Columns[0])
	}
	if funcCall.Over == nil {
		t.Fatal("CORE-3: expected OVER clause")
	}
	if funcCall.Over.Name != "w" {
		t.Errorf("CORE-3: expected Name=\"w\", got %q", funcCall.Over.Name)
	}
}
