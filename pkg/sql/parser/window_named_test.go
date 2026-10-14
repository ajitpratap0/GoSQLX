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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// firstOver returns the window spec of the first select column, which must be
// a function call with an OVER clause.
func firstOver(t *testing.T, tree *ast.AST) *ast.WindowSpec {
	t.Helper()
	if len(tree.Statements) == 0 {
		t.Fatal("no statements parsed")
	}
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if len(stmt.Columns) == 0 {
		t.Fatal("no select columns")
	}
	fn, ok := stmt.Columns[0].(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall, got %T", stmt.Columns[0])
	}
	if fn.Over == nil {
		t.Fatal("expected OVER clause")
	}
	return fn.Over
}

// TestParser_NamedWindowReferenceAndRefinement covers issue #608: the bare
// OVER w reference sets Name, while an existing window name written inside the
// parentheses (SQL:2003 §7.11 <existing window name>) sets BaseWindow.
func TestParser_NamedWindowReferenceAndRefinement(t *testing.T) {
	t.Run("bare reference", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		over := firstOver(t, tree)
		if over.Name != "w" || over.BaseWindow != "" {
			t.Errorf("got Name=%q BaseWindow=%q, want Name=%q BaseWindow=%q", over.Name, over.BaseWindow, "w", "")
		}
	})

	t.Run("refinement", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y)")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		over := firstOver(t, tree)
		if over.Name != "" || over.BaseWindow != "w" {
			t.Errorf("got Name=%q BaseWindow=%q, want Name=%q BaseWindow=%q", over.Name, over.BaseWindow, "", "w")
		}
		if len(over.OrderBy) != 1 {
			t.Errorf("got %d ORDER BY items, want 1", len(over.OrderBy))
		}
	})

	t.Run("parenthesized reference", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER (w) FROM t WINDOW w AS (PARTITION BY y)")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		over := firstOver(t, tree)
		if over.Name != "" || over.BaseWindow != "w" {
			t.Errorf("got Name=%q BaseWindow=%q, want Name=%q BaseWindow=%q", over.Name, over.BaseWindow, "", "w")
		}
		if len(over.PartitionBy) != 0 || len(over.OrderBy) != 0 || over.FrameClause != nil {
			t.Errorf("expected no window parts, got %+v", over)
		}
	})

	t.Run("quoted base window", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, `SELECT sum(x) OVER ("w") FROM t WINDOW w AS (PARTITION BY y)`)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		if over := firstOver(t, tree); over.BaseWindow != "w" {
			t.Errorf("got BaseWindow=%q, want %q", over.BaseWindow, "w")
		}
	})

	t.Run("window chain definitions", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER w2 FROM t WINDOW w1 AS (PARTITION BY a), w2 AS (w1 ORDER BY b)")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		stmt, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Windows) != 2 {
			t.Fatalf("got %d windows, want 2", len(stmt.Windows))
		}
		if w := stmt.Windows[0]; w.Name != "w1" || w.BaseWindow != "" {
			t.Errorf("Windows[0] Name=%q BaseWindow=%q, want w1/\"\"", w.Name, w.BaseWindow)
		}
		if w := stmt.Windows[1]; w.Name != "w2" || w.BaseWindow != "w1" || len(w.OrderBy) != 1 {
			t.Errorf("Windows[1] Name=%q BaseWindow=%q OrderBy=%d, want w2/w1/1", w.Name, w.BaseWindow, len(w.OrderBy))
		}
	})

	t.Run("legacy bare definition", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER w FROM t WINDOW w AS w2")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		stmt, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Windows) != 1 {
			t.Fatalf("got %d windows, want 1", len(stmt.Windows))
		}
		if w := stmt.Windows[0]; w.Name != "w" || w.BaseWindow != "w2" {
			t.Errorf("Windows[0] Name=%q BaseWindow=%q, want w/w2", w.Name, w.BaseWindow)
		}
	})

	for _, sql := range []string{
		"SELECT sum(x) OVER (w w2) FROM t",
		"SELECT sum(x) OVER (PARTITION BY a w) FROM t",
		"SELECT sum(x) OVER (w PARTITION) FROM t",
	} {
		sql := sql
		t.Run("rejects/"+sql, func(t *testing.T) {
			tree, err := parseSQLMayFail(t, sql)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("expected parse error for %q", sql)
			}
		})
	}
}
