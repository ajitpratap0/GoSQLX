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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestPostgreSQLJSONOperatorPrecedence(t *testing.T) {
	for _, op := range []string{"->", "->>", "#>", "#>>", "@>", "<@", "#-", "?", "?|", "?&"} {
		t.Run(op, func(t *testing.T) {
			for _, tc := range []struct{ expression, leftOp, rightOp string }{
				{"a " + op + " b ^ 2", "", "^"},
				{"a ^ 2 " + op + " b", "^", ""},
				{"a + b " + op + " c * d", "+", "*"},
			} {
				tree, err := parser.ParseWithDialect("SELECT "+tc.expression, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatalf("parse %q: %v", tc.expression, err)
				}
				defer ast.ReleaseAST(tree)
				stmt, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected SELECT, got %T", tree.Statements[0])
				}
				expr, ok := stmt.Columns[0].(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("expected binary expression, got %T", stmt.Columns[0])
				}
				if expr.Operator != op {
					t.Fatalf("%s: root operator = %q, want %q", tc.expression, expr.Operator, op)
				}
				for _, child := range []struct {
					expr ast.Expression
					op   string
				}{{expr.Left, tc.leftOp}, {expr.Right, tc.rightOp}} {
					binary, ok := child.expr.(*ast.BinaryExpression)
					if child.op == "" {
						if ok {
							t.Errorf("unexpected child operator %q", binary.Operator)
						}
						continue
					}
					if !ok || binary.Operator != child.op {
						t.Errorf("%s: expected child operator %q, got %#v", tc.expression, child.op, child.expr)
					}
				}
			}
		})
	}
}

func TestPostgreSQLOtherOperatorsSharePrecedence(t *testing.T) {
	for _, op := range []string{"|", "&", "#", "<<", ">>", "||", "->", "@>"} {
		t.Run(op, func(t *testing.T) {
			for _, tc := range []struct{ sql, root, left string }{
				{"SELECT a -> b " + op + " c", op, "->"},
				{"SELECT a " + op + " b -> c", "->", op},
			} {
				tree, err := parser.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatal(err)
				}
				defer ast.ReleaseAST(tree)
				stmt, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected SELECT, got %T", tree.Statements[0])
				}
				expr, ok := stmt.Columns[0].(*ast.BinaryExpression)
				if !ok || expr.Operator != tc.root {
					t.Fatalf("%s: expected root %q, got %#v", tc.sql, tc.root, stmt.Columns[0])
				}
				left, ok := expr.Left.(*ast.BinaryExpression)
				if !ok || left.Operator != tc.left {
					t.Fatalf("%s: expected left %s expression, got %#v", tc.sql, tc.left, expr.Left)
				}
			}
		})
	}
}

func TestJSONOperatorPrecedenceOtherDialects(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectGeneric, keywords.DialectMySQL, keywords.DialectMariaDB} {
		t.Run(string(dialect), func(t *testing.T) {
			tree, err := parser.ParseWithDialect("SELECT a -> b ^ 2", dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("expected SELECT, got %T", tree.Statements[0])
			}
			expr, ok := stmt.Columns[0].(*ast.BinaryExpression)
			if !ok || expr.Operator != "^" {
				t.Fatalf("expected root ^, got %#v", stmt.Columns[0])
			}
			left, ok := expr.Left.(*ast.BinaryExpression)
			if !ok || left.Operator != "->" {
				t.Fatalf("expected left -> expression, got %#v", expr.Left)
			}
		})
	}
}

func TestPostgreSQLPositionOtherOperators(t *testing.T) {
	for _, sql := range []string{
		"SELECT POSITION('a' || 'b' IN text_value)",
		"SELECT POSITION(data ->> 'key' IN text_value)",
	} {
		tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		defer ast.ReleaseAST(tree)
	}
}

func TestXorPrecedenceMetadataRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		dialect  keywords.SQLDialect
		additive bool
	}{
		{keywords.DialectSQLServer, true}, {keywords.DialectMySQL, false}, {keywords.DialectMariaDB, false},
	} {
		t.Run(string(tc.dialect), func(t *testing.T) {
			tree, err := parser.ParseWithDialect("SELECT a ^ b", tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			output := tree.SQL()
			again, err := parser.ParseWithDialect(output, tc.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", output, err)
			}
			defer ast.ReleaseAST(again)
			for _, candidate := range []*ast.AST{tree, again} {
				stmt, ok := candidate.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected SELECT, got %T", candidate.Statements[0])
				}
				expr, ok := stmt.Columns[0].(*ast.BinaryExpression)
				if !ok {
					t.Fatalf("expected binary, got %T", stmt.Columns[0])
				}
				if !expr.BitwiseXor || expr.XorAtAdditive != tc.additive {
					t.Errorf("XOR metadata = %v/%v, want true/%v", expr.BitwiseXor, expr.XorAtAdditive, tc.additive)
				}
			}
		})
	}
}

func TestPostgreSQLJSONLegacyCastAssociation(t *testing.T) {
	for _, sql := range []string{
		`SELECT * FROM events WHERE data @> '{"type": "click"}'::jsonb`,
		`SELECT * FROM events WHERE data @> '{"type": "click"}'::text::jsonb`,
	} {
		tree, err := parser.ParseWithDialect(sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(tree)
		stmt, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected SELECT, got %T", tree.Statements[0])
		}
		cast, ok := stmt.Where.(*ast.CastExpression)
		if !ok {
			t.Fatalf("expected legacy cast of JSON expression, got %T", stmt.Where)
		}
		for {
			nested, ok := cast.Expr.(*ast.CastExpression)
			if !ok {
				break
			}
			cast = nested
		}
		expr, ok := cast.Expr.(*ast.BinaryExpression)
		if !ok || expr.Operator != "@>" {
			t.Fatalf("expected JSON expression inside cast, got %#v", cast.Expr)
		}
		if sql == `SELECT * FROM events WHERE data @> '{"type": "click"}'::jsonb` {
			want := `SELECT * FROM events WHERE CAST(data @> '{"type": "click"}' AS jsonb)`
			if got := tree.SQL(); got != want {
				t.Errorf("SQL = %s, want %s", got, want)
			}
		}
	}
	tree, err := parser.ParseWithDialect("SELECT a -> b::int ^ 2", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SELECT, got %T", tree.Statements[0])
	}
	expr, ok := stmt.Columns[0].(*ast.BinaryExpression)
	if !ok || expr.Operator != "->" {
		t.Fatalf("expected JSON root, got %#v", stmt.Columns[0])
	}
	power, ok := expr.Right.(*ast.BinaryExpression)
	if !ok || power.Operator != "^" {
		t.Fatalf("expected power RHS, got %#v", expr.Right)
	}
	if _, ok := power.Left.(*ast.CastExpression); !ok {
		t.Fatalf("expected cast of power's left operand, got %T", power.Left)
	}
}

func TestPostgreSQLJSONExplicitCastAssociation(t *testing.T) {
	for _, tc := range []struct{ sql, want string }{
		{`SELECT data @> CAST('x' AS jsonb)`, `SELECT data @> CAST('x' AS jsonb)`},
		{`SELECT data @> CAST('x' AS text)::jsonb`, `SELECT CAST(data @> CAST('x' AS text) AS jsonb)`},
		{`SELECT data @> ('x'::jsonb)`, `SELECT data @> (CAST('x' AS jsonb))`},
	} {
		tree, err := parser.ParseWithDialect(tc.sql, keywords.DialectPostgreSQL)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(tree)
		if got := tree.SQL(); got != tc.want {
			t.Errorf("parse %s: SQL = %s, want %s", tc.sql, got, tc.want)
		}
	}
}
