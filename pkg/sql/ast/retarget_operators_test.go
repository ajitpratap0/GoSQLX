// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestRetargetOperatorsUnknownSource(t *testing.T) {
	for _, tc := range []struct {
		name, target, operator, function       string
		xor, additive, wantAdditive, wantError bool
	}{
		{name: "power to mysql", target: "mysql", function: "POWER"},
		{name: "power to postgresql", target: "postgresql", operator: "^"},
		{name: "mysql xor to mariadb", target: "mariadb", xor: true, operator: "^"},
		{name: "sqlserver xor to mysql", target: "mysql", xor: true, additive: true, operator: "^"},
		{name: "mysql xor to sqlserver", target: "sqlserver", xor: true, operator: "^", wantAdditive: true},
		{name: "sqlserver xor to postgresql", target: "postgresql", xor: true, additive: true, operator: "#"},
		{name: "xor to generic", target: "generic", xor: true, wantError: true},
		{name: "xor to empty target", xor: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "^", Right: &Identifier{Name: "b"}, BitwiseXor: tc.xor, XorAtAdditive: tc.additive}
			stmt := &SelectStatement{Columns: []Expression{original}}
			defer PutSelectStatement(stmt)
			err := RetargetOperators(stmt, "", tc.target)
			if tc.wantError {
				if err == nil || !strings.Contains(err.Error(), "XOR") {
					t.Fatalf("expected XOR error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.function != "" {
				fn, ok := stmt.Columns[0].(*FunctionCall)
				if !ok || fn.Name != tc.function {
					t.Fatalf("expected %s function, got %#v", tc.function, stmt.Columns[0])
				}
				return
			}
			expr, ok := stmt.Columns[0].(*BinaryExpression)
			if !ok || expr.Operator != tc.operator {
				t.Fatalf("expected %s operator, got %#v", tc.operator, stmt.Columns[0])
			}
			if expr.XorAtAdditive != tc.wantAdditive {
				t.Errorf("XorAtAdditive = %v, want %v", expr.XorAtAdditive, tc.wantAdditive)
			}
			if tc.target == "mariadb" && expr != original {
				t.Error("same-family XOR was unnecessarily rewritten")
			}
		})
	}
}

func TestRetargetOperatorsUnknownPGPrefix(t *testing.T) {
	stmt := &SelectStatement{Columns: []Expression{&UnaryExpression{Operator: PGAbs, Expr: &Identifier{Name: "a"}}}}
	defer PutSelectStatement(stmt)
	if err := RetargetOperators(stmt, "", "mysql"); err != nil {
		t.Fatal(err)
	}
	fn, ok := stmt.Columns[0].(*FunctionCall)
	if !ok || fn.Name != "ABS" {
		t.Fatalf("expected ABS function, got %#v", stmt.Columns[0])
	}
}

func TestRetargetOperatorsUnicodeEscape(t *testing.T) {
	for _, tc := range []struct {
		from, to  string
		wantError bool
	}{
		{"postgresql", "postgresql", false}, {"", "postgresql", false},
		{"postgresql", "mysql", true}, {"", "generic", true},
	} {
		t.Run(tc.from+"_to_"+tc.to, func(t *testing.T) {
			stmt := &SelectStatement{Columns: []Expression{&UnicodeEscapeExpression{RawSQL: `U&'d\0061t'`}}}
			defer PutSelectStatement(stmt)
			err := RetargetOperators(stmt, tc.from, tc.to)
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError %v", err, tc.wantError)
			}
		})
	}
}

func TestXorAtAdditiveReleaseModes(t *testing.T) {
	for _, mode := range []releaseMode{releaseAll, releaseDrawn} {
		expr := &BinaryExpression{Operator: "^", BitwiseXor: true, XorAtAdditive: true}
		releaseExpression(expr, mode)
		want := mode != releaseAll
		if expr.XorAtAdditive != want {
			t.Errorf("mode %v: XorAtAdditive = %v, want %v", mode, expr.XorAtAdditive, want)
		}
	}
}

func TestRetargetPowerPostgreSQLGrouping(t *testing.T) {
	for _, tc := range []struct {
		name                string
		leftJSON, rightJSON bool
		want                string
	}{
		{"left JSON", true, false, "SELECT (a -> b) ^ c"},
		{"right JSON", false, true, "SELECT a ^ (b -> c)"},
		{"plain PostgreSQL", false, false, "SELECT a ^ c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expr := &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "^", Right: &Identifier{Name: "c"}, Pos: models.Location{Line: 1, Column: 15}}
			if tc.leftJSON {
				expr.Left = &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "->", Right: &Identifier{Name: "b"}, Pos: models.Location{Line: 1, Column: 10}}
			}
			if tc.rightJSON {
				expr.Right = &BinaryExpression{Left: &Identifier{Name: "b"}, Operator: "->", Right: &Identifier{Name: "c"}, Pos: models.Location{Line: 1, Column: 15}}
			}
			stmt := &SelectStatement{Columns: []Expression{expr}}
			defer PutSelectStatement(stmt)
			if err := RetargetOperators(stmt, "", "postgresql"); err != nil {
				t.Fatal(err)
			}
			if got := stmt.SQL(); got != tc.want {
				t.Fatalf("SQL = %s, want %s", got, tc.want)
			}
			grouped, ok := stmt.Columns[0].(*BinaryExpression)
			if !ok {
				t.Fatalf("expected binary, got %T", stmt.Columns[0])
			}
			if grouped.Pos != expr.Pos {
				t.Errorf("operator position changed: %v vs %v", grouped.Pos, expr.Pos)
			}
			if !tc.leftJSON && !tc.rightJSON && grouped != expr {
				t.Error("plain PostgreSQL power unnecessarily copied")
			}
		})
	}
}

func TestRetargetOperatorsMapExpressions(t *testing.T) {
	named := map[string]Expression{"OFFSET": &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "^", Right: &Identifier{Name: "b"}}}
	stmt := &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}, From: []TableReference{{Name: "t", TimeTravel: &TimeTravelClause{Kind: "AT", Named: named}}}}
	defer PutSelectStatement(stmt)
	if err := RetargetOperators(stmt, "", "snowflake"); err != nil {
		t.Fatal(err)
	}
	call, ok := named["OFFSET"].(*FunctionCall)
	if !ok || call.Name != "POWER" {
		t.Fatalf("expected POWER in map value, got %#v", named["OFFSET"])
	}
}

func TestRetargetPostgreSQLNestedBinaryGrouping(t *testing.T) {
	position := models.Location{Line: 1, Column: 12}
	ident := func(name string) Expression { return &Identifier{Name: name} }
	binary := func(left Expression, op string, right Expression) *BinaryExpression {
		return &BinaryExpression{Left: left, Operator: op, Right: right, Pos: position}
	}
	for _, tc := range []struct {
		name string
		expr Expression
		want string
	}{
		{"generic nested power", binary(&ParenthesizedExpression{Expr: binary(binary(ident("a"), "->", ident("b")), "+", ident("c"))}, "^", ident("d")), "SELECT ((a -> b) + c) ^ d"},
		{"generic function argument", &FunctionCall{Name: "F", Arguments: []Expression{binary(binary(ident("a"), "->", ident("b")), "+", ident("c"))}}, "SELECT F((a -> b) + c)"},
		{"PostgreSQL precedence unchanged", binary(ident("a"), "->", binary(ident("b"), "+", binary(ident("c"), "^", ident("d")))), "SELECT a -> b + c ^ d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stmt := &SelectStatement{Columns: []Expression{tc.expr}}
			defer PutSelectStatement(stmt)
			if err := RetargetOperators(stmt, "", "postgresql"); err != nil {
				t.Fatal(err)
			}
			if got := stmt.SQL(); got != tc.want {
				t.Fatalf("SQL = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRetargetPowerMySQLJSONGrouping(t *testing.T) {
	pos := models.Location{Line: 1, Column: 12}
	power := &BinaryExpression{Left: &Identifier{Name: "c"}, Operator: "^", Right: &Identifier{Name: "d"}, Pos: pos}
	sum := &BinaryExpression{Left: &Identifier{Name: "b"}, Operator: "+", Right: power, Pos: pos}
	expr := &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "->", Right: sum, Pos: pos}
	stmt := &SelectStatement{Columns: []Expression{expr}}
	defer PutSelectStatement(stmt)
	if err := RetargetOperators(stmt, "", "mysql"); err != nil {
		t.Fatal(err)
	}
	want := "SELECT a -> (b + POWER(c, d))"
	if got := stmt.SQL(); got != want {
		t.Fatalf("SQL = %s, want %s", got, want)
	}
}

func TestRetargetMySQLBitwisePrecedence(t *testing.T) {
	pos := models.Location{Line: 1, Column: 12}
	binary := func(left Expression, op string, right Expression) *BinaryExpression {
		return &BinaryExpression{Left: left, Operator: op, Right: right, Pos: pos}
	}
	or := binary(&Identifier{Name: "a"}, "|", &Identifier{Name: "b"})
	and := binary(or, "&", &Identifier{Name: "c"})
	xor := binary(and, "^", &Identifier{Name: "d"})
	xor.BitwiseXor, xor.XorAtAdditive = true, true
	stmt := &SelectStatement{Columns: []Expression{xor}}
	defer PutSelectStatement(stmt)
	if err := RetargetOperators(stmt, "sqlserver", "mysql"); err != nil {
		t.Fatal(err)
	}
	want := "SELECT ((a | b) & c) ^ d"
	if got := stmt.SQL(); got != want {
		t.Fatalf("SQL = %s, want %s", got, want)
	}
}

func TestRetargetPostgreSQLBitwiseAndOnlyOperators(t *testing.T) {
	id := func(n string) Expression { return &Identifier{Name: n} }
	bin := func(op string) Expression { return &BinaryExpression{Left: id("a"), Operator: op, Right: id("b")} }
	for _, tc := range []struct {
		name, target string
		expr         Expression
		want         string // rendered column, or "error"
	}{
		{"xor mysql", "mysql", bin("#"), "a ^ b"},
		{"xor mariadb", "mariadb", bin("#"), "a ^ b"},
		{"xor sqlserver", "sqlserver", bin("#"), "a ^ b"},
		{"xor snowflake", "snowflake", bin("#"), "BITXOR(a, b)"},
		{"xor clickhouse", "clickhouse", bin("#"), "bitXor(a, b)"},
		{"xor oracle", "oracle", bin("#"), "error"},
		{"xor sqlite", "sqlite", bin("#"), "error"},
		{"xor generic", "generic", bin("#"), "error"},
		{"xor postgresql", "postgresql", bin("#"), "a # b"},
		{"not snowflake", "snowflake", &UnaryExpression{Operator: PGBitwiseNot, Expr: id("a")}, "BITNOT(a)"},
		{"not clickhouse", "clickhouse", &UnaryExpression{Operator: PGBitwiseNot, Expr: id("a")}, "bitNot(a)"},
		{"not oracle", "oracle", &UnaryExpression{Operator: PGBitwiseNot, Expr: id("a")}, "error"},
		{"not mysql", "mysql", &UnaryExpression{Operator: PGBitwiseNot, Expr: id("a")}, "~a"},
		{"shift sqlserver", "sqlserver", bin("<<"), "LEFT_SHIFT(a, b)"},
		{"shift snowflake", "snowflake", bin(">>"), "BITSHIFTRIGHT(a, b)"},
		{"shift clickhouse", "clickhouse", bin("<<"), "bitShiftLeft(a, b)"},
		{"shift oracle", "oracle", bin("<<"), "error"},
		{"shift mysql", "mysql", bin("<<"), "a << b"},
		{"and oracle", "oracle", bin("&"), "BITAND(a, b)"},
		{"or oracle", "oracle", bin("|"), "error"},
		{"or snowflake", "snowflake", bin("|"), "BITOR(a, b)"},
		{"and clickhouse", "clickhouse", bin("&"), "bitAnd(a, b)"},
		{"concat mysql", "mysql", &BinaryExpression{Left: bin("||"), Operator: "||", Right: id("c")}, "CONCAT(a, b, c)"},
		{"pipes or mysql", "mysql", &BinaryExpression{Left: id("a"), Operator: "OR", Right: id("b"), PipesOr: true}, "a || b"},
		{"concat oracle", "oracle", bin("||"), "a || b"},
		{"contains mysql", "mysql", bin("@>"), "error"},
		{"regex snowflake", "snowflake", bin("~"), "error"},
		{"json key sqlite", "sqlite", bin("?"), "error"},
		{"overlap generic", "generic", bin("&&"), "a && b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig, ok := tc.expr.(interface{ SQL() string })
			if !ok {
				t.Fatalf("no SQL for %T", tc.expr)
			}
			// The cheap pre-check must agree with the rewrite.
			if got, want := OperatorNeedsRetarget(tc.expr, tc.target) || childrenNeedRetarget(tc.expr, tc.target), tc.want != orig.SQL(); got != want {
				t.Errorf("OperatorNeedsRetarget = %v, want %v", got, want)
			}
			stmt := &SelectStatement{Columns: []Expression{tc.expr}}
			err := RetargetOperators(stmt, "", tc.target)
			if tc.want == "error" {
				if err == nil {
					t.Fatalf("expected error, got %s", stmt.Columns[0].(interface{ SQL() string }).SQL())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s, ok := stmt.Columns[0].(interface{ SQL() string })
			if !ok {
				t.Fatalf("no SQL for %T", stmt.Columns[0])
			}
			if got := s.SQL(); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// childrenNeedRetarget reports whether any operand of e needs retargeting.
func childrenNeedRetarget(e Expression, target string) bool {
	for _, c := range e.Children() {
		if ce, ok := c.(Expression); ok && (OperatorNeedsRetarget(ce, target) || childrenNeedRetarget(ce, target)) {
			return true
		}
	}
	return false
}
