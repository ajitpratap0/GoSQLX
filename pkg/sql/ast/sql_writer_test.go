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

package ast

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// writeSQLOf renders n through its writeSQL method into a fresh buffer.
func writeSQLOf(n sqlWriter) string {
	var buf bytes.Buffer
	n.writeSQL(&buf)
	return buf.String()
}

func TestLiteralValue_SQL_Table(t *testing.T) {
	tests := []struct {
		name string
		lit  *LiteralValue
		want string
	}{
		{"string", &LiteralValue{Value: "paid", Type: "string"}, `'paid'`},
		{"string quote", &LiteralValue{Value: "it's", Type: "string"}, `'it''s'`},
		{"string escapes", &LiteralValue{Value: "a\\b\n\r\x1a", Type: "STRING"}, `'a\\b\n\r\Z'`},
		{"string NUL dropped", &LiteralValue{Value: "a\x00b", Type: "string"}, `'ab'`},
		{"string non-ASCII", &LiteralValue{Value: "héllo", Type: "string"}, `'héllo'`},
		{"string invalid UTF-8", &LiteralValue{Value: "\xff", Type: "string"}, "'\xef\xbf\xbd'"},
		{"string non-string value", &LiteralValue{Value: 42, Type: "string"}, `'42'`},
		{"int string value", &LiteralValue{Value: "1000", Type: "int"}, `1000`},
		{"int value INTEGER", &LiteralValue{Value: int(1000), Type: "INTEGER"}, `1000`},
		{"float", &LiteralValue{Value: float64(3.5), Type: "float"}, `3.5`},
		{"BOOLEAN uppercases", &LiteralValue{Value: true, Type: "BOOLEAN"}, `TRUE`},
		{"bool keeps case as typed", &LiteralValue{Value: "true", Type: "bool"}, `true`},
		{"bool upper as typed", &LiteralValue{Value: "TRUE", Type: "bool"}, `TRUE`},
		{"nil value", &LiteralValue{Value: nil, Type: "string"}, `NULL`},
		{"null type", &LiteralValue{Value: "x", Type: "null"}, `NULL`},
		{"empty type (fingerprint)", &LiteralValue{Value: "?", Type: ""}, `?`},
		{"placeholder", &LiteralValue{Value: "$1", Type: "placeholder"}, `$1`},
		{"nil receiver", nil, ``},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.lit.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			if got := writeSQLOf(tt.lit); got != tt.want {
				t.Errorf("writeSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBinaryExpression_SQL_Table(t *testing.T) {
	a := &Identifier{Name: "a"}
	b := &Identifier{Name: "b"}
	tests := []struct {
		name string
		expr *BinaryExpression
		want string
	}{
		{"infix", &BinaryExpression{Left: a, Operator: "=", Right: b}, `a = b`},
		{"lowercase like kept as stored", &BinaryExpression{Left: a, Operator: "like", Right: b}, `a like b`},
		{"not like", &BinaryExpression{Left: a, Operator: "like", Right: b, Not: true}, `a NOT LIKE b`},
		{"not ilike", &BinaryExpression{Left: a, Operator: "ILIKE", Right: b, Not: true}, `a NOT ILIKE b`},
		{"not similar to", &BinaryExpression{Left: a, Operator: "similar to", Right: b, Not: true}, `a NOT SIMILAR TO b`},
		{"not other operator", &BinaryExpression{Left: a, Operator: "=", Right: b, Not: true}, `NOT (a = b)`},
		{"is null", &BinaryExpression{Left: a, Operator: "IS NULL"}, `a IS NULL`},
		{"is not null", &BinaryExpression{Left: a, Operator: "IS NULL", Not: true}, `a IS NOT NULL`},
		{"is null lowercase", &BinaryExpression{Left: a, Operator: "is null"}, `a IS NULL`},
		{"custom operator", &BinaryExpression{Left: a, Operator: "=", Right: b, CustomOp: &CustomBinaryOperator{Parts: []string{"pg_catalog", "="}}}, `a OPERATOR(pg_catalog.=) b`},
		{"nil left", &BinaryExpression{Operator: "=", Right: b}, ` = b`},
		{"nil receiver", nil, ``},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.expr.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			if got := writeSQLOf(tt.expr); got != tt.want {
				t.Errorf("writeSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIdentifier_SQL_Quoting(t *testing.T) {
	tests := []struct {
		name string
		id   *Identifier
		want string
	}{
		{"plain", &Identifier{Name: "col"}, `col`},
		{"qualified", &Identifier{Table: "t", Name: "col"}, `t.col`},
		{"star", &Identifier{Name: "*"}, `*`},
		{"qualified star", &Identifier{Table: "t", Name: "*"}, `t.*`},
		{"space", &Identifier{Name: "my col"}, `"my col"`},
		{"embedded quote", &Identifier{Name: `we"ird`}, `"we""ird"`},
		{"unsafe table safe name", &Identifier{Table: "my t", Name: "col"}, `"my t".col`},
		{"safe table unsafe name", &Identifier{Table: "t", Name: "a-b"}, `t."a-b"`},
		{"unicode letters", &Identifier{Name: "naïve_列"}, `naïve_列`},
		{"empty", &Identifier{}, `""`},
		{"nil receiver", nil, ``},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
			if got := writeSQLOf(tt.id); got != tt.want {
				t.Errorf("writeSQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// sqlOnlyExpr implements SQL() but not writeSQL.
type sqlOnlyExpr struct{}

func (sqlOnlyExpr) TokenLiteral() string { return "tok" }
func (sqlOnlyExpr) Children() []Node     { return nil }
func (sqlOnlyExpr) expressionNode()      {}
func (sqlOnlyExpr) SQL() string          { return "sql-only" }

// tokenOnlyExpr implements neither SQL() nor writeSQL.
type tokenOnlyExpr struct{}

func (tokenOnlyExpr) TokenLiteral() string { return "token-only" }
func (tokenOnlyExpr) Children() []Node     { return nil }
func (tokenOnlyExpr) expressionNode()      {}

func TestWriteExpr_Dispatch(t *testing.T) {
	var (
		nilIdent *Identifier
		nilLit   *LiteralValue
		nilBin   *BinaryExpression
	)
	tests := []struct {
		name string
		expr Expression
		want string
	}{
		{"nil interface", nil, ""},
		{"SQL() fallback", sqlOnlyExpr{}, "sql-only"},
		{"TokenLiteral fallback", tokenOnlyExpr{}, "token-only"},
		{"typed nil identifier", nilIdent, ""},
		{"typed nil literal", nilLit, ""},
		{"typed nil binary", nilBin, ""},
		{"writer", &Identifier{Name: "x"}, "x"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeExpr(&buf, tt.expr)
			if got := buf.String(); got != tt.want {
				t.Errorf("writeExpr() = %q, want %q", got, tt.want)
			}
			if got := exprSQL(tt.expr); got != tt.want {
				t.Errorf("exprSQL() = %q, want %q (writeExpr must mirror exprSQL)", got, tt.want)
			}
		})
	}
}

func TestWriteExprList_JoinParity(t *testing.T) {
	lists := [][]Expression{
		nil,
		{},
		{&Identifier{Name: "a"}},
		{&LiteralValue{Value: "1", Type: "int"}, nil, &LiteralValue{Value: "3", Type: "int"}},
		{nil, nil},
		{sqlOnlyExpr{}, tokenOnlyExpr{}, &Ident{Name: "x"}},
	}
	for _, list := range lists {
		parts := make([]string, len(list))
		for i, e := range list {
			parts[i] = exprSQL(e)
		}
		want := strings.Join(parts, ", ")
		var buf bytes.Buffer
		writeExprList(&buf, list)
		if got := buf.String(); got != want {
			t.Errorf("writeExprList(%d items) = %q, want %q", len(list), got, want)
		}
		if got := exprListSQL(list); got != want {
			t.Errorf("exprListSQL(%d items) = %q, want %q", len(list), got, want)
		}
	}
}

func TestWriteStmt_Dispatch(t *testing.T) {
	var nilSel *SelectStatement
	tests := []struct {
		name string
		stmt Statement
		want string
	}{
		{"nil interface", nil, ""},
		{"typed nil select", nilSel, ""},
		{"writer", &Values{Rows: [][]Expression{{&LiteralValue{Value: "1", Type: "int"}}}}, "VALUES (1)"},
		{"SQL() fallback", &DropStatement{ObjectType: "TABLE", Names: []string{"t"}}, "DROP TABLE t"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeStmt(&buf, tt.stmt)
			if got := buf.String(); got != tt.want {
				t.Errorf("writeStmt() = %q, want %q", got, tt.want)
			}
			if got := stmtSQL(tt.stmt); got != tt.want {
				t.Errorf("stmtSQL() = %q, want %q (writeStmt must mirror stmtSQL)", got, tt.want)
			}
		})
	}
}

func TestAST_SQL_Separators(t *testing.T) {
	var nilSel *SelectStatement
	one := &Values{Rows: [][]Expression{{&LiteralValue{Value: "1", Type: "int"}}}}
	tests := []struct {
		name string
		tree AST
		want string
	}{
		{"empty", AST{}, ""},
		{"single", AST{Statements: []Statement{one}}, "VALUES (1)"},
		{"nil statement skipped", AST{Statements: []Statement{one, nil, one}}, "VALUES (1);\nVALUES (1)"},
		{"typed nil kept as empty part", AST{Statements: []Statement{one, nilSel, one}}, "VALUES (1);\n;\nVALUES (1)"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tree.SQL(); got != tt.want {
				t.Errorf("AST.SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// poolTestSelect builds the AST of the 7-line benchmark query by hand
// (the parser cannot be imported from an internal test).
func poolTestSelect() *SelectStatement {
	col := func(table, name string) *Identifier { return &Identifier{Table: table, Name: name} }
	limit := 100
	countO := &FunctionCall{Name: "COUNT", Arguments: []Expression{col("o", "id")}}
	return &SelectStatement{
		Columns: []Expression{col("u", "id"), col("u", "name"), &AliasedExpression{Expr: countO, Alias: "order_count"}},
		From:    []TableReference{{Name: "users", Alias: "u"}},
		Joins: []JoinClause{{
			Type:      "LEFT",
			Right:     TableReference{Name: "orders", Alias: "o"},
			Condition: &BinaryExpression{Left: col("u", "id"), Operator: "=", Right: col("o", "user_id")},
		}},
		Where: &BinaryExpression{
			Left:     &BinaryExpression{Left: col("u", "active"), Operator: "=", Right: &LiteralValue{Value: "TRUE", Type: "bool"}},
			Operator: "AND",
			Right:    &BinaryExpression{Left: col("u", "created_at"), Operator: ">", Right: &LiteralValue{Value: "2024-01-01", Type: "string"}},
		},
		GroupBy: []Expression{col("u", "id"), col("u", "name")},
		Having:  &BinaryExpression{Left: countO, Operator: ">", Right: &LiteralValue{Value: "5", Type: "int"}},
		OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "order_count"}, Ascending: false}},
		Limit:   &limit,
	}
}

const poolTestSelectSQL = "SELECT u.id, u.name, COUNT(o.id) AS order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = TRUE AND u.created_at > '2024-01-01' GROUP BY u.id, u.name HAVING COUNT(o.id) > 5 ORDER BY order_count DESC LIMIT 100"

func TestBufPool_NoContaminationAndNoAliasing(t *testing.T) {
	sel := poolTestSelect()
	first := sel.SQL()
	if first != poolTestSelectSQL {
		t.Fatalf("SelectStatement.SQL() = %q, want %q", first, poolTestSelectSQL)
	}

	t.Run("pooled content never leaks", func(t *testing.T) {
		buf := getBuf()
		buf.WriteString(strings.Repeat("Z", 1024))
		putBuf(buf)
		if got := (&LiteralValue{Value: "x", Type: "string"}).SQL(); got != `'x'` {
			t.Fatalf("literal after dirty put = %q", got)
		}
		if got := (&BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "=", Right: &Identifier{Name: "b"}}).SQL(); got != "a = b" {
			t.Fatalf("binary after dirty put = %q", got)
		}
		if got := sel.SQL(); got != first {
			t.Fatalf("select after dirty put = %q, want %q", got, first)
		}
		if b := getBuf(); b.Len() != 0 {
			t.Fatalf("getBuf returned non-empty buffer (len %d)", b.Len())
		}
	})

	t.Run("putBuf nil is safe", func(t *testing.T) {
		putBuf(nil)
	})

	t.Run("oversized buffer is dropped", func(t *testing.T) {
		buf := getBuf()
		buf.Grow(128 * 1024)
		buf.WriteString(strings.Repeat("y", 70*1024))
		putBuf(buf)
		if got := sel.SQL(); got != first {
			t.Fatalf("select after oversized put = %q", got)
		}
	})

	t.Run("returned strings do not alias pooled buffers", func(t *testing.T) {
		s := sel.SQL()
		bin := (&BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "=", Right: &Identifier{Name: "b"}}).SQL()
		for i := 0; i < 8; i++ {
			buf := getBuf()
			buf.WriteString(strings.Repeat("#", 512))
			putBuf(buf)
		}
		if s != first {
			t.Fatalf("earlier SQL() result was mutated: %q", s)
		}
		if bin != "a = b" {
			t.Fatalf("earlier binary SQL() result was mutated: %q", bin)
		}
	})

	t.Run("concurrent use", func(t *testing.T) {
		other := &InsertStatement{
			TableName: "t",
			Columns:   []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}},
			Values:    [][]Expression{{&LiteralValue{Value: "1", Type: "int"}, &LiteralValue{Value: "it's", Type: "string"}}},
		}
		const otherSQL = "INSERT INTO t (a, b) VALUES (1, 'it''s')"
		var wg sync.WaitGroup
		errs := make(chan string, 8)
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 2000; i++ {
					if (g+i)%2 == 0 {
						if got := sel.SQL(); got != first {
							errs <- got
							return
						}
					} else if got := other.SQL(); got != otherSQL {
						errs <- got
						return
					}
				}
			}(g)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Errorf("concurrent SQL() produced %q", e)
		}
	})
}

func TestSQL_LeafAllocationBudget(t *testing.T) {
	intLit := &LiteralValue{Value: "1000", Type: "int"}
	strLit := &LiteralValue{Value: "paid", Type: "string"}
	ident := &Identifier{Table: "u", Name: "a"}
	bin := &BinaryExpression{Left: &Identifier{Table: "u", Name: "a"}, Operator: "=", Right: &Identifier{Table: "o", Name: "b"}}

	var sink string
	if n := testing.AllocsPerRun(200, func() { sink = intLit.SQL() }); n != 0 {
		t.Errorf("int LiteralValue.SQL() allocs = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(200, func() { sink = strLit.SQL() }); n > 1 {
		t.Errorf("string LiteralValue.SQL() allocs = %v, want <= 1", n)
	}
	if n := testing.AllocsPerRun(200, func() { sink = ident.SQL() }); n > 1 {
		t.Errorf("qualified Identifier.SQL() allocs = %v, want <= 1", n)
	}
	if raceDetectorEnabled {
		// sync.Pool randomly drops items under the race detector, so
		// pool-backed budgets are only meaningful without it.
		_ = sink
		return
	}
	if n := testing.AllocsPerRun(200, func() { sink = bin.SQL() }); n > 1 {
		t.Errorf("BinaryExpression.SQL() allocs = %v, want <= 1", n)
	}
	sel := poolTestSelect()
	if n := testing.AllocsPerRun(200, func() { sink = sel.SQL() }); n > 1 {
		t.Errorf("SelectStatement.SQL() allocs = %v, want <= 1", n)
	}
	_ = sink
}
