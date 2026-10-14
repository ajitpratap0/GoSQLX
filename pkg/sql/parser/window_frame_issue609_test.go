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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// firstFrame returns the frame clause of the first select column's OVER spec.
func firstFrame(t *testing.T, tree *ast.AST) *ast.WindowFrame {
	t.Helper()
	over := firstOver(t, tree)
	if over.FrameClause == nil {
		t.Fatal("expected a frame clause")
	}
	return over.FrameClause
}

// firstColumn returns the first select-list expression of the first statement.
func firstColumn(t *testing.T, tree *ast.AST) ast.Expression {
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
	return stmt.Columns[0]
}

// TestParser_WindowFrameGroups covers issue #609: GROUPS is a valid frame unit
// (SQL:2011) next to ROWS and RANGE.
func TestParser_WindowFrameGroups(t *testing.T) {
	tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER (ORDER BY y GROUPS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	defer ast.ReleaseAST(tree)

	f := firstFrame(t, tree)
	if f.Type != "GROUPS" {
		t.Errorf("Type = %q, want GROUPS", f.Type)
	}
	if f.Start.Type != "PRECEDING" {
		t.Errorf("Start.Type = %q, want PRECEDING", f.Start.Type)
	}
	lit, ok := f.Start.Value.(*ast.LiteralValue)
	if !ok {
		t.Fatalf("Start.Value = %T, want *ast.LiteralValue", f.Start.Value)
	}
	if v, _ := lit.Value.(string); v != "1" {
		t.Errorf("Start.Value = %#v, want \"1\"", lit.Value)
	}
	if f.End == nil || f.End.Type != "CURRENT ROW" {
		t.Errorf("End = %+v, want CURRENT ROW", f.End)
	}
	if f.Exclude != "" {
		t.Errorf("Exclude = %q, want empty", f.Exclude)
	}
}

// TestParser_WindowFrameExclude covers the optional EXCLUDE clause after the
// frame bounds.
func TestParser_WindowFrameExclude(t *testing.T) {
	cases := []struct {
		name  string
		frame string
		want  string
	}{
		{"current row", "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE CURRENT ROW", "CURRENT ROW"},
		{"group", "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE GROUP", "GROUP"},
		{"ties", "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE TIES", "TIES"},
		{"no others", "ROWS BETWEEN 1 PRECEDING AND CURRENT ROW EXCLUDE NO OTHERS", "NO OTHERS"},
		{"lowercase no others", "rows between 1 preceding and current row exclude no others", "NO OTHERS"},
		{"single bound", "RANGE UNBOUNDED PRECEDING EXCLUDE TIES", "TIES"},
		{"groups frame", "GROUPS BETWEEN 1 PRECEDING AND 1 FOLLOWING EXCLUDE GROUP", "GROUP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql := "SELECT sum(x) OVER (ORDER BY y " + tc.frame + ") FROM t"
			tree, err := parseSQLMayFail(t, sql)
			if err != nil {
				t.Fatalf("parse(%q) error: %v", sql, err)
			}
			defer ast.ReleaseAST(tree)
			if got := firstFrame(t, tree).Exclude; got != tc.want {
				t.Errorf("Exclude = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParser_WindowFrameExclude_Errors checks that an invalid frame unit or
// EXCLUDE continuation is a parse error rather than silently dropped tokens.
func TestParser_WindowFrameExclude_Errors(t *testing.T) {
	cases := []string{
		"SELECT sum(x) OVER (ORDER BY y ROWS CURRENT ROW EXCLUDE FOO) FROM t",
		"SELECT sum(x) OVER (ORDER BY y ROWS CURRENT ROW EXCLUDE NO) FROM t",
		"SELECT sum(x) OVER (ORDER BY y ROWS CURRENT ROW EXCLUDE CURRENT) FROM t",
		"SELECT sum(x) OVER (ORDER BY y ROWS CURRENT ROW EXCLUDE) FROM t",
		"SELECT sum(x) OVER (ORDER BY y GROUPS) FROM t",
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) {
			tree, err := parseSQLMayFail(t, sql)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("parse(%q) succeeded, want an error", sql)
			}
		})
	}
}

// intervalOf asserts that e is an *ast.IntervalExpression and returns it.
func intervalOf(t *testing.T, e ast.Expression) *ast.IntervalExpression {
	t.Helper()
	iv, ok := e.(*ast.IntervalExpression)
	if !ok {
		t.Fatalf("expected *ast.IntervalExpression, got %T", e)
	}
	return iv
}

// TestParser_IntervalQualifier covers the ANSI interval qualifier written after
// the quoted value: INTERVAL '1' DAY, INTERVAL '1-2' YEAR TO MONTH.
func TestParser_IntervalQualifier(t *testing.T) {
	t.Run("frame bound DAY", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT sum(x) OVER (ORDER BY d RANGE BETWEEN INTERVAL '1' DAY PRECEDING AND CURRENT ROW) FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		f := firstFrame(t, tree)
		if f.Start.Type != "PRECEDING" {
			t.Errorf("Start.Type = %q, want PRECEDING", f.Start.Type)
		}
		iv := intervalOf(t, f.Start.Value)
		if iv.Value != "1" || iv.Qualifier != "DAY" {
			t.Errorf("got Value=%q Qualifier=%q, want 1/DAY", iv.Value, iv.Qualifier)
		}
	})

	t.Run("YEAR TO MONTH", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT INTERVAL '1-2' YEAR TO MONTH FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		iv := intervalOf(t, firstColumn(t, tree))
		if iv.Value != "1-2" || iv.Qualifier != "YEAR TO MONTH" {
			t.Errorf("got Value=%q Qualifier=%q, want 1-2/YEAR TO MONTH", iv.Value, iv.Qualifier)
		}
	})

	t.Run("lowercase day to second", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT INTERVAL '1 02:03:04' day to second FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		iv := intervalOf(t, firstColumn(t, tree))
		if iv.Qualifier != "DAY TO SECOND" {
			t.Errorf("Qualifier = %q, want DAY TO SECOND", iv.Qualifier)
		}
	})

	t.Run("MySQL YEAR_MONTH", func(t *testing.T) {
		tree, err := ParseWithDialect("SELECT INTERVAL '1-2' YEAR_MONTH FROM t", keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		iv := intervalOf(t, firstColumn(t, tree))
		if iv.Value != "1-2" || iv.Qualifier != "YEAR_MONTH" {
			t.Errorf("got Value=%q Qualifier=%q, want 1-2/YEAR_MONTH", iv.Value, iv.Qualifier)
		}
	})

	t.Run("arithmetic is not aliased", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT d + INTERVAL '1' DAY FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		bin, ok := firstColumn(t, tree).(*ast.BinaryExpression)
		if !ok {
			t.Fatalf("expected *ast.BinaryExpression, got %T", firstColumn(t, tree))
		}
		if iv := intervalOf(t, bin.Right); iv.Value != "1" || iv.Qualifier != "DAY" {
			t.Errorf("got Value=%q Qualifier=%q, want 1/DAY", iv.Value, iv.Qualifier)
		}
	})
}

// TestParser_IntervalQualifier_Unchanged pins the interval forms whose AST must
// not change: no qualifier, quoted aliases, the MySQL numeric form and a TO
// with no trailing field.
func TestParser_IntervalQualifier_Unchanged(t *testing.T) {
	t.Run("no qualifier", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT INTERVAL '1 day' FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		iv := intervalOf(t, firstColumn(t, tree))
		if iv.Value != "1 day" || iv.Qualifier != "" {
			t.Errorf("got Value=%q Qualifier=%q, want \"1 day\"/\"\"", iv.Value, iv.Qualifier)
		}
	})

	t.Run("quoted alias stays an alias", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, `SELECT INTERVAL '1' "day" FROM t`)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		al, ok := firstColumn(t, tree).(*ast.AliasedExpression)
		if !ok {
			t.Fatalf("expected *ast.AliasedExpression, got %T", firstColumn(t, tree))
		}
		if al.Alias != "day" {
			t.Errorf("Alias = %q, want day", al.Alias)
		}
		if iv := intervalOf(t, al.Expr); iv.Qualifier != "" {
			t.Errorf("Qualifier = %q, want empty", iv.Qualifier)
		}
	})

	t.Run("plural word stays an alias", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT INTERVAL '1 day' days FROM t")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		al, ok := firstColumn(t, tree).(*ast.AliasedExpression)
		if !ok {
			t.Fatalf("expected *ast.AliasedExpression, got %T", firstColumn(t, tree))
		}
		if al.Alias != "days" {
			t.Errorf("Alias = %q, want days", al.Alias)
		}
	})

	t.Run("MySQL numeric form", func(t *testing.T) {
		tree, err := ParseWithDialect("SELECT d + INTERVAL 30 DAY FROM t", keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		defer ast.ReleaseAST(tree)
		bin, ok := firstColumn(t, tree).(*ast.BinaryExpression)
		if !ok {
			t.Fatalf("expected *ast.BinaryExpression, got %T", firstColumn(t, tree))
		}
		if iv := intervalOf(t, bin.Right); iv.Value != "30 DAY" || iv.Qualifier != "" {
			t.Errorf("got Value=%q Qualifier=%q, want \"30 DAY\"/\"\"", iv.Value, iv.Qualifier)
		}
	})

	t.Run("TO without trailing field is not consumed", func(t *testing.T) {
		tree, err := parseSQLMayFail(t, "SELECT INTERVAL '1' DAY TO FROM t")
		if err != nil {
			return // an error is acceptable; only a TO qualifier is not
		}
		defer ast.ReleaseAST(tree)
		var iv *ast.IntervalExpression
		switch e := firstColumn(t, tree).(type) {
		case *ast.IntervalExpression:
			iv = e
		case *ast.AliasedExpression:
			iv = intervalOf(t, e.Expr)
		default:
			t.Fatalf("unexpected column type %T", e)
		}
		if strings.Contains(iv.Qualifier, "TO") {
			t.Errorf("Qualifier = %q consumed a dangling TO", iv.Qualifier)
		}
	})
}
