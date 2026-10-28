// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast_test

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestSQLHandBuiltOperatorGrouping(t *testing.T) {
	id := func(n string) ast.Expression { return &ast.Identifier{Name: n} }
	bin := func(op string, l, r ast.Expression) *ast.BinaryExpression {
		return &ast.BinaryExpression{Operator: op, Left: l, Right: r}
	}
	tests := []struct {
		name string
		expr ast.Expression
		want string
	}{
		{"logical", bin("AND", bin("OR", id("a"), id("b")), id("c")), "(a OR b) AND c"},
		{"right subtraction", bin("-", id("a"), bin("-", id("b"), id("c"))), "a - (b - c)"},
		{"multiply sum", bin("*", bin("+", id("a"), id("b")), id("c")), "(a + b) * c"},
		{"division", bin("/", id("a"), bin("*", id("b"), id("c"))), "a / (b * c)"},
		{"comparison", bin("=", bin("=", id("a"), id("b")), id("c")), "(a = b) = c"},
		{"concat", bin("+", bin("||", id("a"), id("b")), id("c")), "(a || b) + c"},
		{"json power", bin("^", bin("->", id("a"), &ast.LiteralValue{Type: "STRING", Value: "k"}), id("c")), "(a -> 'k') ^ c"},
		{"minus", &ast.UnaryExpression{Operator: ast.Minus, Expr: bin("+", id("a"), id("b"))}, "-(a + b)"},
		{"not", &ast.UnaryExpression{Operator: ast.Not, Expr: bin("OR", id("a"), id("b"))}, "NOT (a OR b)"},
		{"not operand", bin("=", &ast.UnaryExpression{Operator: ast.Not, Expr: id("a")}, id("b")), "(NOT a) = b"},
		{"abs operand", bin("^", &ast.UnaryExpression{Operator: ast.PGAbs, Expr: id("a")}, id("b")), "(@ a) ^ b"},
		{"sqrt operand", bin("^", &ast.UnaryExpression{Operator: ast.PGSquareRoot, Expr: id("a")}, id("b")), "(|/a) ^ b"},
		{"cbrt operand", bin("^", &ast.UnaryExpression{Operator: ast.PGCubeRoot, Expr: id("a")}, id("b")), "(||/a) ^ b"},
		{"abs json", &ast.UnaryExpression{Operator: ast.PGAbs, Expr: bin("->", id("a"), id("b"))}, "@ (a -> b)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := tt.expr.(interface{ SQL() string })
			if !ok {
				t.Fatalf("no SQL for %T", tt.expr)
			}
			if got := s.SQL(); got != tt.want {
				t.Fatalf("SQL=%q want %q", got, tt.want)
			}
			a, err := gosqlx.ParseWithDialect("SELECT "+tt.want, "postgresql")
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(a)
			if got := a.SQL(); got != "SELECT "+tt.want {
				t.Fatalf("round trip = %q", got)
			}
			stmt, ok := a.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SELECT, got %T", a.Statements[0])
			}
			if want, got := operatorTree(tt.expr), operatorTree(stmt.Columns[0]); want != got {
				t.Fatalf("tree changed: %s -> %s", want, got)
			}
		})
	}
}

func operatorTree(e ast.Expression) string {
	switch x := e.(type) {
	case *ast.ParenthesizedExpression:
		return operatorTree(x.Expr)
	case *ast.BinaryExpression:
		return "(" + operatorTree(x.Left) + " " + x.Operator + " " + operatorTree(x.Right) + ")"
	case *ast.UnaryExpression:
		return x.Operator.String() + "(" + operatorTree(x.Expr) + ")"
	case *ast.Identifier:
		return x.Name
	case *ast.LiteralValue:
		return fmt.Sprint(x.Value)
	default:
		return fmt.Sprintf("%T", e)
	}
}

func TestSQLHandBuiltChildInParsedTree(t *testing.T) {
	// A hand-built operand inserted into a parsed tree is grouped by its own
	// (missing) position, not by its parsed parent's.
	id := func(n string) ast.Expression { return &ast.Identifier{Name: n} }
	or := func() ast.Expression { return &ast.BinaryExpression{Left: id("c"), Operator: "OR", Right: id("d")} }
	tests := []struct {
		name, sql string
		edit      func(*ast.BinaryExpression)
		want      string
	}{
		{"and right", "SELECT * FROM t WHERE a AND b", func(b *ast.BinaryExpression) { b.Right = or() }, "SELECT * FROM t WHERE a AND (c OR d)"},
		{"plus left", "SELECT * FROM t WHERE a + b", func(b *ast.BinaryExpression) { b.Left = or() }, "SELECT * FROM t WHERE (c OR d) + b"},
		{"minus right", "SELECT * FROM t WHERE a - b", func(b *ast.BinaryExpression) {
			b.Right = &ast.BinaryExpression{Left: id("c"), Operator: "-", Right: id("d")}
		}, "SELECT * FROM t WHERE a - (c - d)"},
		{"parsed child unchanged", "SELECT * FROM t WHERE a AND b OR c", func(*ast.BinaryExpression) {}, "SELECT * FROM t WHERE a AND b OR c"},
		{"not over hand-built", "SELECT * FROM t WHERE NOT a", nil, "SELECT * FROM t WHERE NOT (c OR d)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, "postgresql")
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			sel, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SELECT, got %T", tree.Statements[0])
			}
			switch w := sel.Where.(type) {
			case *ast.BinaryExpression:
				tt.edit(w)
			case *ast.UnaryExpression:
				w.Expr = or()
			default:
				t.Fatalf("unexpected WHERE %T", sel.Where)
			}
			if got := tree.SQL(); got != tt.want {
				t.Fatalf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}
