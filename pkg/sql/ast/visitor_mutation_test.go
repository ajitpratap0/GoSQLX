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

package ast_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Before #557, Children() handed visitors heap copies of value-typed nodes,
// so these mutations were silently lost. They must now reach the AST.

func mustParse(t *testing.T, sql string, dialect keywords.SQLDialect) *ast.AST {
	t.Helper()
	tree, err := parser.ParseWithDialect(sql, dialect)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q: got %d statements, want 1", sql, len(tree.Statements))
	}
	return tree
}

func mustSelect(t *testing.T, tree *ast.AST) *ast.SelectStatement {
	t.Helper()
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	return sel
}

func mustFunc(t *testing.T, e ast.Expression) *ast.FunctionCall {
	t.Helper()
	fn, ok := e.(*ast.FunctionCall)
	if !ok {
		t.Fatalf("expected *ast.FunctionCall, got %T", e)
	}
	return fn
}

func TestWalk_VisitorMutationReachesAST(t *testing.T) {
	t.Run("TableReference_and_OrderBy", func(t *testing.T) {
		tree := mustParse(t, "SELECT a FROM t1 JOIN t2 ON t1.id = t2.id ORDER BY a DESC", keywords.DialectGeneric)
		sel := mustSelect(t, tree)
		ast.Inspect(sel, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.TableReference:
				if x.Name != "" && !strings.HasPrefix(x.Name, "x_") {
					x.Name = "x_" + x.Name
				}
			case *ast.OrderByExpression:
				x.Ascending = true
			}
			return true
		})
		if got := sel.From[0].Name; got != "x_t1" {
			t.Errorf("From[0].Name = %q, want x_t1", got)
		}
		if len(sel.Joins) != 1 {
			t.Fatalf("got %d joins, want 1", len(sel.Joins))
		}
		if got := sel.Joins[0].Right.Name; got != "x_t2" {
			t.Errorf("Joins[0].Right.Name = %q, want x_t2", got)
		}
		if !sel.OrderBy[0].Ascending {
			t.Errorf("OrderBy[0].Ascending was not flipped")
		}
		for _, out := range []string{sel.SQL(), formatter.FormatAST(tree, ast.FormatOptions{})} {
			if !strings.Contains(out, "FROM x_t1") || !strings.Contains(out, "JOIN x_t2") {
				t.Errorf("renamed tables missing from rendered SQL: %s", out)
			}
			if strings.Contains(out, "DESC") {
				t.Errorf("rendered SQL still has DESC: %s", out)
			}
		}
	})

	t.Run("Window_Aggregate_WithinGroup_Frame", func(t *testing.T) {
		tree := mustParse(t, "SELECT SUM(x) OVER (PARTITION BY g ORDER BY y DESC ROWS BETWEEN 1 PRECEDING AND CURRENT ROW), "+
			"STRING_AGG(n, ',' ORDER BY n DESC), PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY v DESC) FROM t", keywords.DialectPostgreSQL)
		sel := mustSelect(t, tree)
		ast.Inspect(sel, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.OrderByExpression:
				x.Ascending = true
			case *ast.WindowFrameBound:
				if x.Type == "PRECEDING" {
					x.Type = "FOLLOWING"
				}
			}
			return true
		})
		if len(sel.Columns) != 3 {
			t.Fatalf("got %d columns, want 3", len(sel.Columns))
		}
		sum, agg, pct := mustFunc(t, sel.Columns[0]), mustFunc(t, sel.Columns[1]), mustFunc(t, sel.Columns[2])
		if sum.Over == nil || len(sum.Over.OrderBy) != 1 || !sum.Over.OrderBy[0].Ascending {
			t.Errorf("window ORDER BY was not flipped: %+v", sum.Over)
		}
		if sum.Over.FrameClause == nil || sum.Over.FrameClause.Start.Type != "FOLLOWING" {
			t.Errorf("WindowFrame.Start mutation did not reach the AST: %+v", sum.Over.FrameClause)
		}
		if len(agg.OrderBy) != 1 || !agg.OrderBy[0].Ascending {
			t.Errorf("aggregate ORDER BY was not flipped")
		}
		if len(pct.WithinGroup) != 1 || !pct.WithinGroup[0].Ascending {
			t.Errorf("WITHIN GROUP ORDER BY was not flipped")
		}
		if out := sel.SQL(); strings.Contains(out, "DESC") || !strings.Contains(out, "FOLLOWING") {
			t.Errorf("mutations not visible in SQL(): %s", out)
		}
	})

	t.Run("WhenClause", func(t *testing.T) {
		tree := mustParse(t, "SELECT CASE WHEN a = 1 THEN 'x' WHEN a = 2 THEN 'y' ELSE 'z' END FROM t", keywords.DialectGeneric)
		sel := mustSelect(t, tree)
		ast.Inspect(sel, func(n ast.Node) bool {
			if w, ok := n.(*ast.WhenClause); ok {
				w.Result = &ast.LiteralValue{Value: "changed", Type: "STRING"}
			}
			return true
		})
		out := sel.SQL()
		if strings.Count(out, "'changed'") != 2 || strings.Contains(out, "'x'") {
			t.Errorf("WhenClause mutation not visible in SQL(): %s", out)
		}
	})

	t.Run("UpdateExpression", func(t *testing.T) {
		tree := mustParse(t, "UPDATE t SET a = 1", keywords.DialectGeneric)
		upd, ok := tree.Statements[0].(*ast.UpdateStatement)
		if !ok {
			t.Fatalf("expected *ast.UpdateStatement, got %T", tree.Statements[0])
		}
		repl := &ast.LiteralValue{Value: 42, Type: "INTEGER"}
		ast.Inspect(upd, func(n ast.Node) bool {
			if u, ok := n.(*ast.UpdateExpression); ok {
				u.Value = repl
				return false
			}
			return true
		})
		if upd.Assignments[0].Value != ast.Expression(repl) {
			t.Fatalf("UpdateExpression mutation did not reach the AST")
		}
		if out := upd.SQL(); !strings.Contains(out, "42") {
			t.Errorf("UpdateExpression mutation not visible in SQL(): %s", out)
		}
	})

	t.Run("MergeTargetSource", func(t *testing.T) {
		tree := mustParse(t, "MERGE INTO tgt AS t USING src AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.v = s.v "+
			"WHEN NOT MATCHED THEN INSERT (id, v) VALUES (s.id, s.v);", keywords.DialectSQLServer)
		m, ok := tree.Statements[0].(*ast.MergeStatement)
		if !ok {
			t.Fatalf("expected *ast.MergeStatement, got %T", tree.Statements[0])
		}
		ast.Inspect(m, func(n ast.Node) bool {
			if tr, ok := n.(*ast.TableReference); ok && tr.Name != "" {
				tr.Name = "x_" + tr.Name
			}
			return true
		})
		if m.TargetTable.Name != "x_tgt" || m.SourceTable.Name != "x_src" {
			t.Fatalf("MERGE table rename did not reach the AST: target=%q source=%q", m.TargetTable.Name, m.SourceTable.Name)
		}
		if out := m.SQL(); !strings.Contains(out, "x_tgt") || !strings.Contains(out, "x_src") {
			t.Errorf("MERGE rename not visible in SQL(): %s", out)
		}
	})
}

// TestInspect_ConcurrentPooledTrees walks pooled trees from several
// goroutines. Children now alias pooled storage, so this checks under -race
// that walks stay deterministic and never observe another tree's nodes.
func TestInspect_ConcurrentPooledTrees(t *testing.T) {
	queries := []string{
		"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id LEFT JOIN t3 ON t3.id = t2.id ORDER BY a DESC, b",
		"SELECT SUM(x) OVER (PARTITION BY g ORDER BY y ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t ORDER BY 1",
		"SELECT CASE WHEN a = 1 THEN 'x' WHEN a = 2 THEN 'y' ELSE 'z' END FROM t JOIN u ON u.id = t.id",
	}
	type counts struct{ tables, orderBys int }
	countTree := func(sql string) (counts, error) {
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			return counts{}, err
		}
		p := parser.GetParser()
		defer parser.PutParser(p)
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			return counts{}, err
		}
		defer ast.ReleaseAST(tree)
		var c counts
		for _, stmt := range tree.Statements {
			ast.Inspect(stmt, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.TableReference:
					c.tables++
				case *ast.OrderByExpression:
					c.orderBys++
				}
				return true
			})
		}
		return c, nil
	}

	want := make([]counts, len(queries))
	for i, q := range queries {
		c, err := countTree(q)
		if err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if c.tables == 0 {
			t.Fatalf("query %d: no table references visited", i)
		}
		want[i] = c
	}

	const goroutines, iterations = 8, 200
	var wg sync.WaitGroup
	errs := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				qi := (g + i) % len(queries)
				got, err := countTree(queries[qi])
				if err != nil {
					errs <- err.Error()
					return
				}
				if got != want[qi] {
					errs <- "query " + queries[qi] + ": counts changed across pooled trees"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
