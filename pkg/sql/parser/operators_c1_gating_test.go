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

// Package parser - operators_c1_gating_test.go
// Dialect gating, node fields and regressions for the operator and predicate
// work in operators_c1_test.go.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestOperatorsC1_Rejected pins the statements that must keep failing: syntax
// that is dialect specific must not leak into other dialects, and the
// operators that need a second token must not swallow unrelated input.
func TestOperatorsC1_Rejected(t *testing.T) {
	tests := []struct {
		name string
		d    keywords.SQLDialect
		sql  string
	}{
		{"is expr only in sqlite", keywords.DialectPostgreSQL, "SELECT * FROM t WHERE a IS b"},
		{"is expr not in mysql", keywords.DialectMySQL, "SELECT * FROM t WHERE a IS b"},
		{"empty in only in sqlite pg", keywords.DialectPostgreSQL, "SELECT a FROM t WHERE a IN ()"},
		{"empty in only in sqlite mysql", keywords.DialectMySQL, "SELECT a FROM t WHERE a IN ()"},
		{"in table only in sqlite", keywords.DialectPostgreSQL, "SELECT a FROM t WHERE a IN u"},
		{"comparison does not chain", keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE a = b = c"},
		{"is distinct needs from", keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE a IS DISTINCT b"},
		{"global needs in", keywords.DialectClickHouse, "SELECT a FROM t WHERE a GLOBAL"},
		{"split shift is not a shift", keywords.DialectPostgreSQL, "SELECT a < < b FROM t"},
		{"split null safe equals", keywords.DialectMySQL, "SELECT * FROM t WHERE a <= > b"},
		{"glob only in sqlite", keywords.DialectPostgreSQL, "SELECT * FROM t WHERE p GLOB 'x'"},
		{"not glob only in sqlite", keywords.DialectMySQL, "SELECT * FROM t WHERE p NOT GLOB 'x'"},
		{"escape needs a value", keywords.DialectPostgreSQL, "SELECT a FROM t WHERE a LIKE 'x' ESCAPE"},
		{"any needs parentheses", keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE a = ANY tags"},
		{"ternary needs colon", keywords.DialectClickHouse, "SELECT a ? 1"},
		{"div only in mysql family", keywords.DialectPostgreSQL, "SELECT a DIV 3 FROM t"},
		{"mod word only in mysql family", keywords.DialectSQLServer, "SELECT a MOD 3 FROM t"},
		{"xor only in mysql family", keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE a XOR b"},
		{"sounds like only in mysql family", keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE a SOUNDS LIKE b"},
		{"isnull not in mysql", keywords.DialectMySQL, "SELECT 1 FROM t WHERE a ISNULL"},
		{"ternary only in clickhouse", keywords.DialectPostgreSQL, "SELECT a ? 1 : 2 FROM t"},
		{"bang not only in mysql family", keywords.DialectPostgreSQL, "SELECT !a FROM t"},
		{"assignment only in mysql family", keywords.DialectPostgreSQL, "SELECT @a := 1"},
		{"collate needs a name", keywords.DialectPostgreSQL, "SELECT a COLLATE FROM t"},
	}
	for _, tc := range tests {
		t.Run(string(tc.d)+"/"+tc.name, func(t *testing.T) {
			tree, err := c1Parse(tc.sql, tc.d)
			if err == nil {
				defer ast.ReleaseAST(tree)
				t.Fatalf("parse(%q) succeeded, want an error", tc.sql)
			}
		})
	}
}

// TestOperatorsC1_NodeFields checks the fields the new constructs record.
func TestOperatorsC1_NodeFields(t *testing.T) {
	t.Run("any array quantifier and operator", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT 1 FROM t WHERE id <> ALL(tags)", keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		any, ok := stmt.Where.(*ast.AnyAllExpression)
		if !ok {
			t.Fatalf("WHERE is %T, want *ast.AnyAllExpression", stmt.Where)
		}
		if any.Quantifier != "ALL" || any.Operator != "<>" {
			t.Errorf("got %s %s, want ALL <>", any.Quantifier, any.Operator)
		}
		if _, ok := any.Array.(*ast.Identifier); !ok {
			t.Errorf("Array is %T, want *ast.Identifier", any.Array)
		}
		if n := len(any.Children()); n != 2 {
			t.Errorf("Children() = %d nodes, want 2", n)
		}
	})

	t.Run("any subquery stays AnyExpression", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT 1 FROM t WHERE id = ANY (SELECT id FROM u)", keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		if _, ok := stmt.Where.(*ast.AnyExpression); !ok {
			t.Fatalf("WHERE is %T, want *ast.AnyExpression", stmt.Where)
		}
	})

	t.Run("global in", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT a FROM t WHERE a GLOBAL NOT IN (SELECT 1)", keywords.DialectClickHouse)
		defer ast.ReleaseAST(tree)
		in, ok := stmt.Where.(*ast.InExpression)
		if !ok {
			t.Fatalf("WHERE is %T, want *ast.InExpression", stmt.Where)
		}
		if !in.Global || !in.Not || in.Subquery == nil {
			t.Errorf("Global=%v Not=%v Subquery=%v, want true true non-nil", in.Global, in.Not, in.Subquery)
		}
	})

	t.Run("bare in", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT a FROM t WHERE a IN main.u", keywords.DialectSQLite)
		defer ast.ReleaseAST(tree)
		in, ok := stmt.Where.(*ast.InExpression)
		if !ok {
			t.Fatalf("WHERE is %T, want *ast.InExpression", stmt.Where)
		}
		if !in.Bare || len(in.List) != 1 {
			t.Errorf("Bare=%v len(List)=%d, want true 1", in.Bare, len(in.List))
		}
	})

	t.Run("collate quoted", func(t *testing.T) {
		stmt, tree := c1Select(t, `SELECT a COLLATE "C" FROM t`, keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		c, ok := stmt.Columns[0].(*ast.CollateExpression)
		if !ok {
			t.Fatalf("column is %T, want *ast.CollateExpression", stmt.Columns[0])
		}
		if c.Collation != "C" || !c.Quoted || c.Literal {
			t.Errorf("Collation=%q Quoted=%v Literal=%v, want C true false", c.Collation, c.Quoted, c.Literal)
		}
	})

	t.Run("like escape", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT a FROM t WHERE a LIKE 'x!%' ESCAPE '!'", keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		bin, ok := stmt.Where.(*ast.BinaryExpression)
		if !ok {
			t.Fatalf("WHERE is %T, want *ast.BinaryExpression", stmt.Where)
		}
		esc, ok := bin.Escape.(*ast.LiteralValue)
		if !ok {
			t.Fatalf("Escape is %T, want *ast.LiteralValue", bin.Escape)
		}
		if esc.Value != "!" {
			t.Errorf("Escape = %v, want !", esc.Value)
		}
		if n := len(bin.Children()); n != 3 {
			t.Errorf("Children() = %d nodes, want 3 (left, pattern, escape)", n)
		}
	})

	t.Run("and or are canonical upper case", func(t *testing.T) {
		stmt, tree := c1Select(t, "select a from t where a = 1 and b = 2 or c = 3", keywords.DialectPostgreSQL)
		defer ast.ReleaseAST(tree)
		or, ok := stmt.Where.(*ast.BinaryExpression)
		if !ok || or.Operator != "OR" {
			t.Fatalf("WHERE = %T %v, want OR binary", stmt.Where, stmt.Where)
		}
		and, ok := or.Left.(*ast.BinaryExpression)
		if !ok || and.Operator != "AND" {
			t.Fatalf("left of OR = %T, want AND binary", or.Left)
		}
	})

	t.Run("mysql pipes or keeps its flag", func(t *testing.T) {
		stmt, tree := c1Select(t, "SELECT 1 FROM t WHERE a || b", keywords.DialectMySQL)
		defer ast.ReleaseAST(tree)
		or, ok := stmt.Where.(*ast.BinaryExpression)
		if !ok || or.Operator != "OR" || !or.PipesOr {
			t.Fatalf("WHERE = %#v, want OR with PipesOr", stmt.Where)
		}
	})
}

// TestOperatorsC1_NotStillPrefixesOnlyPredicates guards the NOT lookahead:
// NOT after an operand belongs to the operand only when a predicate operator
// follows it.
func TestOperatorsC1_NotStillPrefixesOnlyPredicates(t *testing.T) {
	tests := []struct {
		d   keywords.SQLDialect
		sql string
	}{
		{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE NOT active AND name LIKE 'x%'"},
		{keywords.DialectPostgreSQL, "CREATE TABLE t (a INT DEFAULT 0 NOT NULL)"},
		{keywords.DialectPostgreSQL, "CREATE TABLE t (a TEXT DEFAULT 'x' NOT NULL, b INT)"},
		{keywords.DialectMySQL, "SELECT a FROM t WHERE NOT MATCH (a) AGAINST ('x')"},
		{keywords.DialectSQLite, "SELECT a FROM t WHERE a NOT IN (1, 2) AND b NOT BETWEEN 1 AND 2"},
		{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE a NOT SIMILAR TO 'x' AND b NOT LIKE 'y' ESCAPE '!'"},
	}
	for _, tc := range tests {
		t.Run(string(tc.d)+"/"+tc.sql, func(t *testing.T) {
			tree, err := c1Parse(tc.sql, tc.d)
			if err != nil {
				t.Fatalf("parse(%q): %v", tc.sql, err)
			}
			ast.ReleaseAST(tree)
		})
	}
}

// TestOperatorsC1_IndexColumnCollate checks COLLATE on CREATE INDEX columns.
func TestOperatorsC1_IndexColumnCollate(t *testing.T) {
	tree, err := c1Parse("CREATE INDEX i ON t (a COLLATE NOCASE DESC, b)", keywords.DialectSQLite)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	idx, ok := tree.Statements[0].(*ast.CreateIndexStatement)
	if !ok {
		t.Fatalf("got %T, want *ast.CreateIndexStatement", tree.Statements[0])
	}
	if len(idx.Columns) != 2 {
		t.Fatalf("got %d columns, want 2", len(idx.Columns))
	}
	if idx.Columns[0].Collate != "NOCASE" || idx.Columns[0].Direction != "DESC" || idx.Columns[1].Collate != "" {
		t.Errorf("columns = %+v, want a COLLATE NOCASE DESC and plain b", idx.Columns)
	}
}

// TestOperatorsC1_ReleaseAST parses statements that use every new node and
// releases them repeatedly: the pool release walks the new nodes' children
// and must neither panic nor double-put.
func TestOperatorsC1_ReleaseAST(t *testing.T) {
	sqls := []struct {
		d   keywords.SQLDialect
		sql string
	}{
		{keywords.DialectPostgreSQL, `SELECT c AT TIME ZONE 'UTC', x COLLATE "C", ARRAY[1] FROM t WHERE id = ANY(ARRAY[1, 2]) AND a LIKE 'x' ESCAPE '!'`},
		{keywords.DialectClickHouse, "SELECT a ? 1 : 2 FROM t WHERE a GLOBAL IN (SELECT 1)"},
		{keywords.DialectSQLite, "SELECT a FROM t WHERE a IN u AND b IS NOT c"},
	}
	for i := 0; i < 20; i++ {
		for _, tc := range sqls {
			tree, err := c1Parse(tc.sql, tc.d)
			if err != nil {
				t.Fatalf("parse(%q): %v", tc.sql, err)
			}
			ast.ReleaseAST(tree)
		}
	}
}
