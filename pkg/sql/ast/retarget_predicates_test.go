// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestOperatorNeedsRetarget(t *testing.T) {
	ident := func() Expression { return &Identifier{Name: "x"} }
	binary := func(op string) *BinaryExpression {
		return &BinaryExpression{Operator: op, Left: ident(), Right: ident()}
	}
	power := binary("^")
	xor := binary("^")
	xor.BitwiseXor = true
	additiveXor := binary("^")
	additiveXor.BitwiseXor, additiveXor.XorAtAdditive = true, true
	jsonPower := binary("^")
	jsonPower.Left = binary("->")
	jsonPower.Pos = models.Location{Line: 1, Column: 4}
	sum := binary("+")
	sum.Right = binary("+")
	groupedSum := binary("+")
	groupedSum.Right = &ParenthesizedExpression{Expr: binary("+")}
	for _, tc := range []struct {
		name, target string
		expr         Expression
		want         bool
	}{
		{"plain cast operand", "mysql", ident(), false},
		{"nil binary", "mysql", (*BinaryExpression)(nil), false},
		{"power PostgreSQL", "postgresql", power, false},
		{"power generic", "generic", power, false},
		{"power mysql", "mysql", power, true},
		{"power PostgreSQL grouping with position", "postgresql", jsonPower, true},
		{"power uppercase target", "POSTGRESQL", power, false},
		{"xor same family", "mariadb", xor, false},
		{"xor different family", "sqlserver", xor, true},
		{"xor additive same family", "sqlserver", additiveXor, false},
		{"xor unknown target", "oracle", xor, true},
		{"xor generic target", "generic", xor, true},
		{"arithmetic unchanged", "mysql", binary("+"), false},
		{"arithmetic grouping", "mysql", sum, true},
		{"existing arithmetic grouping", "mysql", groupedSum, false},
		{"lowercase keyword", "mysql", binary("div"), false},
		{"comparison unchanged", "mysql", binary("is distinct from"), false},
		{"abs same dialect", "postgresql", &UnaryExpression{Operator: PGAbs, Expr: ident()}, false},
		{"abs conversion", "mysql", &UnaryExpression{Operator: PGAbs, Expr: ident()}, true},
		{"factorial rejection", "mysql", &UnaryExpression{Operator: PGPrefixFactorial, Expr: ident()}, true},
		{"ordinary unary", "mysql", &UnaryExpression{Operator: Minus, Expr: ident()}, false},
		{"unicode same dialect", "postgresql", &UnicodeEscapeExpression{RawSQL: `U&'x'`}, false},
		{"unicode rejection", "mysql", &UnicodeEscapeExpression{RawSQL: `U&'x'`}, true},
		{"object same dialect", "snowflake", &ObjectLiteral{}, false},
		{"object rejection", "postgresql", &ObjectLiteral{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprintf("%#v", tc.expr)
			if got := OperatorNeedsRetarget(tc.expr, tc.target); got != tc.want {
				t.Fatalf("needs retarget = %v, want %v", got, tc.want)
			}
			if allocs := testing.AllocsPerRun(100, func() { OperatorNeedsRetarget(tc.expr, tc.target) }); allocs != 0 {
				t.Errorf("predicate allocated %g times", allocs)
			}
			if fmt.Sprintf("%#v", tc.expr) != before {
				t.Fatal("predicate changed input")
			}
			stmt := &SelectStatement{Columns: []Expression{tc.expr}}
			err := RetargetOperators(stmt, "", tc.target)
			if changed := err != nil || stmt.Columns[0] != tc.expr; changed != tc.want {
				t.Errorf("actual retarget changed/rejected = %v, want %v (error %v)", changed, tc.want, err)
			}
		})
	}
}

func TestDataTypeNeedsRestyleForDialect(t *testing.T) {
	for _, typ := range []string{
		"INT", "VARCHAR(64)", "INT[]", "INT[3]", `"char"`, "`MyType`", "[MyType][]", "[123]", "[a]]b]", `"a""b"`,
		"Tuple(`x y` UInt8, \"z\" String)", `DateTime64(3, 'a"b')`, `Enum('a''"b', 'c')`,
		`"unfinished`, `"valid"."unfinished`, `"valid"('unfinished)`,
	} {
		for _, target := range []string{"", "generic", "postgresql", "mysql", "mariadb", "sqlserver", "clickhouse", "MYSQL"} {
			t.Run(target+"/"+typ, func(t *testing.T) {
				cast := &CastExpression{Type: typ}
				defer PutCastExpression(cast)
				got := DataTypeNeedsRestyleForDialect(typ, target)
				if allocs := testing.AllocsPerRun(100, func() { DataTypeNeedsRestyleForDialect(typ, target) }); allocs != 0 {
					t.Errorf("predicate allocated %g times", allocs)
				}
				if cast.Type != typ {
					t.Fatal("predicate changed input")
				}
				RestyleDataTypesForDialect(cast, target)
				if want := cast.Type != typ; got != want {
					t.Errorf("needs restyle = %v, actual changed = %v (%q -> %q)", got, want, typ, cast.Type)
				}
			})
		}
	}
}
