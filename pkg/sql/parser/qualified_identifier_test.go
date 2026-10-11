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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseQualifiedSQL tokenizes and parses sql, returning the AST. The caller
// must release the returned AST.
func parseQualifiedSQL(t *testing.T, sql string, opts ...ParserOption) (*ast.AST, error) {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	p := NewParser(opts...)
	defer p.Release()
	return p.ParseFromModelTokens(toks)
}

func TestParser_QualifiedIdentifier_Shape(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantTable string
		wantName  string
		wantLine  int
		wantCol   int
		checkPos  bool
	}{
		{"qualified column", "SELECT t.col FROM t", "t", "col", 1, 8, true},
		{"qualified asterisk", "SELECT t.* FROM t", "t", "*", 1, 8, true},
		{"quoted qualified", `SELECT "T"."Col" FROM t`, "T", "Col", 1, 8, true},
		{"reserved word after dot", "SELECT t.key FROM t", "t", "key", 1, 8, true},
		{"unqualified column", "SELECT col FROM t", "", "col", 1, 8, true},
		{"bare asterisk", "SELECT * FROM t", "", "*", 0, 0, false},
		{"multi-line", "SELECT\n  t.col FROM t", "t", "col", 2, 3, true},
		{"three-part column", "SELECT db.t.col FROM db.t", "db.t", "col", 1, 8, true},
		{"backtick three-part", "SELECT `sakila`.`city`.`city` FROM t", "sakila.city", "city", 1, 8, true},
		{"three-part asterisk", "SELECT db.t.* FROM db.t", "db.t", "*", 1, 8, true},
		{"four-part column", "SELECT c.s.t.col FROM t", "c.s.t", "col", 1, 8, true},
		{"reserved word as later part", "SELECT db.t.key FROM t", "db.t", "key", 1, 8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := parseQualifiedSQL(t, tt.sql)
			if err != nil {
				t.Fatalf("parse %q: %v", tt.sql, err)
			}
			defer ast.ReleaseAST(tree)

			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
			}
			id, ok := sel.Columns[0].(*ast.Identifier)
			if !ok {
				t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[0])
			}
			if id.Table != tt.wantTable || id.Name != tt.wantName {
				t.Errorf("got Table=%q Name=%q, want Table=%q Name=%q", id.Table, id.Name, tt.wantTable, tt.wantName)
			}
			if tt.checkPos && (id.Pos.Line != tt.wantLine || id.Pos.Column != tt.wantCol) {
				t.Errorf("got Pos=%d:%d, want %d:%d", id.Pos.Line, id.Pos.Column, tt.wantLine, tt.wantCol)
			}
		})
	}

	t.Run("join on condition", func(t *testing.T) {
		tree, err := parseQualifiedSQL(t, "SELECT 1 FROM a JOIN b ON a.id = b.aid")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer ast.ReleaseAST(tree)

		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.Joins) != 1 {
			t.Fatalf("expected 1 join, got %d", len(sel.Joins))
		}
		bin, ok := sel.Joins[0].Condition.(*ast.BinaryExpression)
		if !ok {
			t.Fatalf("expected *ast.BinaryExpression, got %T", sel.Joins[0].Condition)
		}
		left, ok := bin.Left.(*ast.Identifier)
		if !ok {
			t.Fatalf("expected left *ast.Identifier, got %T", bin.Left)
		}
		right, ok := bin.Right.(*ast.Identifier)
		if !ok {
			t.Fatalf("expected right *ast.Identifier, got %T", bin.Right)
		}
		if left.Table != "a" || left.Name != "id" {
			t.Errorf("left = %q.%q, want a.id", left.Table, left.Name)
		}
		if right.Table != "b" || right.Name != "aid" {
			t.Errorf("right = %q.%q, want b.aid", right.Table, right.Name)
		}
	})
}

func TestParser_QualifiedIdentifier_MultiPartUnchanged(t *testing.T) {
	t.Run("three-part name folds qualifiers into Table", func(t *testing.T) {
		tree, err := parseQualifiedSQL(t, "SELECT a.b.c FROM t")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer ast.ReleaseAST(tree)
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		id, ok := sel.Columns[0].(*ast.Identifier)
		if !ok {
			t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[0])
		}
		if id.Table != "a.b" || id.Name != "c" {
			t.Errorf("got Table=%q Name=%q, want Table=\"a.b\" Name=\"c\"", id.Table, id.Name)
		}
	})

	t.Run("subscript wraps promoted identifier", func(t *testing.T) {
		tree, err := parseQualifiedSQL(t, "SELECT t.col[1] FROM t")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer ast.ReleaseAST(tree)

		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		sub, ok := sel.Columns[0].(*ast.ArraySubscriptExpression)
		if !ok {
			t.Fatalf("expected *ast.ArraySubscriptExpression, got %T", sel.Columns[0])
		}
		id, ok := sub.Array.(*ast.Identifier)
		if !ok {
			t.Fatalf("expected *ast.Identifier array, got %T", sub.Array)
		}
		if id.Table != "t" || id.Name != "col" {
			t.Errorf("array = %q.%q, want t.col", id.Table, id.Name)
		}
	})

	t.Run("clickhouse numeric element access", func(t *testing.T) {
		tree, err := parseQualifiedSQL(t, "SELECT d.1 FROM t ARRAY JOIN arr AS d", WithDialect("clickhouse"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer ast.ReleaseAST(tree)

		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		id, ok := sel.Columns[0].(*ast.Identifier)
		if !ok {
			t.Fatalf("expected *ast.Identifier, got %T", sel.Columns[0])
		}
		if id.Table != "d" || id.Name != "1" {
			t.Errorf("got %q.%q, want d.1", id.Table, id.Name)
		}
	})
}

// TestParser_QualifiedIdentifier_Allocs guards the single-allocation shape of
// a qualified reference (table.column): the first Identifier is promoted in
// place instead of being discarded and re-allocated.
func TestParser_QualifiedIdentifier_Allocs(t *testing.T) {
	if raceEnabled {
		// The race detector makes sync.Pool drop entries at random, which
		// inflates allocation counts and makes this guard non-deterministic.
		t.Skip("allocation counts are not stable under the race detector")
	}
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	toks, err := tkz.Tokenize([]byte("SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id"))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	// Copy: the tokenizer may recycle its internal buffer.
	tokens := append([]models.TokenWithSpan(nil), toks...)

	p := NewParser()
	defer p.Release()

	var parseErr error
	n := testing.AllocsPerRun(1000, func() {
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			parseErr = err
			return
		}
		ast.ReleaseAST(tree)
	})
	if parseErr != nil {
		t.Fatalf("parse: %v", parseErr)
	}
	// Baseline before in-place promotion was 17 allocs (4 qualified refs).
	const maxAllocs = 13
	if n > maxAllocs {
		t.Errorf("AllocsPerRun = %v, want <= %d", n, maxAllocs)
	}
}
