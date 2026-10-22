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
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// firstTableRef parses sql in dialect d and returns the first FROM table
// reference of the single SELECT statement.
func firstTableRef(t *testing.T, sql string, d keywords.SQLDialect) ast.TableReference {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("ParseWithDialect(%s) %q: %v", d, sql, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) == 0 {
		t.Fatal("expected a FROM table reference")
	}
	return sel.From[0]
}

// TestBigQueryPivot_Issue854 verifies BigQuery PIVOT is parsed now that the
// parser gates PIVOT/UNPIVOT on Capabilities().SupportsPivotUnpivot.
func TestBigQueryPivot_Issue854(t *testing.T) {
	bq := keywords.DialectBigQuery
	tests := []struct {
		name       string
		sql        string
		aggAlias   string
		extraAggs  []string // aliases of the extra aggregates
		pivotCol   string
		inValues   []string
		tableAlias string
	}{
		{
			name:     "issue repro",
			sql:      "SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2'))",
			pivotCol: "quarter",
			inValues: []string{"'Q1'", "'Q2'"},
		},
		{
			name:       "IN value aliases with and without AS, table alias",
			sql:        "SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1' AS first_quarter, 'Q2' second_quarter)) AS pivoted",
			pivotCol:   "quarter",
			inValues:   []string{"'Q1' AS first_quarter", "'Q2' AS second_quarter"},
			tableAlias: "pivoted",
		},
		{
			name:      "multiple aliased aggregates",
			sql:       "SELECT * FROM produce PIVOT (SUM(sales) AS total_sales, COUNT(*) AS num_records FOR quarter IN ('Q1', 'Q2'))",
			aggAlias:  "total_sales",
			extraAggs: []string{"num_records"},
			pivotCol:  "quarter",
			inValues:  []string{"'Q1'", "'Q2'"},
		},
		{
			name:       "aggregate alias without AS, unaliased extra aggregate",
			sql:        "SELECT * FROM produce PIVOT (SUM(sales) s, AVG(sales) FOR quarter IN (1, 2)) p",
			aggAlias:   "s",
			extraAggs:  []string{""},
			pivotCol:   "quarter",
			inValues:   []string{"1", "2"},
			tableAlias: "p",
		},
		{
			name:     "backtick quoted names",
			sql:      "SELECT * FROM `proj.ds.sales` PIVOT (SUM(amount) FOR `quarter` IN ('Q1' AS `q 1`))",
			pivotCol: "quarter",
			inValues: []string{"'Q1' AS `q 1`"},
		},
		{
			name:     "quoted aggregate aliases preserve source form",
			sql:      "SELECT * FROM sales PIVOT (SUM(amount) AS `日本`, COUNT(*) `a``b` FOR quarter IN ('Q1'))",
			aggAlias: "`日本`", extraAggs: []string{"`a``b`"}, pivotCol: "quarter", inValues: []string{"'Q1'"},
		},
		{
			name:     "subquery source",
			sql:      "SELECT * FROM (SELECT product, sales, quarter FROM produce) PIVOT (SUM(sales) FOR quarter IN ('Q1', 'Q2'))",
			pivotCol: "quarter",
			inValues: []string{"'Q1'", "'Q2'"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref := firstTableRef(t, tc.sql, bq)
			if ref.Pivot == nil {
				t.Fatal("expected Pivot clause")
			}
			pv := ref.Pivot
			if pv.AggregateFunction == nil {
				t.Fatal("expected AggregateFunction")
			}
			if pv.AggregateAlias != tc.aggAlias {
				t.Errorf("AggregateAlias = %q, want %q", pv.AggregateAlias, tc.aggAlias)
			}
			if len(pv.ExtraAggregates) != len(tc.extraAggs) {
				t.Fatalf("ExtraAggregates = %d, want %d", len(pv.ExtraAggregates), len(tc.extraAggs))
			}
			for i, a := range pv.ExtraAggregates {
				if a.Function == nil {
					t.Errorf("ExtraAggregates[%d].Function is nil", i)
				}
				if a.Alias != tc.extraAggs[i] {
					t.Errorf("ExtraAggregates[%d].Alias = %q, want %q", i, a.Alias, tc.extraAggs[i])
				}
			}
			if pv.PivotColumn != tc.pivotCol {
				t.Errorf("PivotColumn = %q, want %q", pv.PivotColumn, tc.pivotCol)
			}
			if !reflect.DeepEqual(pv.InValues, tc.inValues) {
				t.Errorf("InValues = %q, want %q", pv.InValues, tc.inValues)
			}
			if ref.Alias != tc.tableAlias {
				t.Errorf("Alias = %q, want %q", ref.Alias, tc.tableAlias)
			}
			if got := len(pv.Children()); got != 1+len(tc.extraAggs) {
				t.Errorf("Children() = %d nodes, want %d", got, 1+len(tc.extraAggs))
			}
		})
	}
}

// TestBigQueryUnpivot_Issue854 verifies BigQuery UNPIVOT, including the
// INCLUDE/EXCLUDE NULLS modifier, row-value aliases with and without AS and
// the multi-column form.
func TestBigQueryUnpivot_Issue854(t *testing.T) {
	bq := keywords.DialectBigQuery
	tests := []struct {
		name         string
		sql          string
		nullHandling string
		valueCol     string
		valueCols    []string
		nameCol      string
		inColumns    []string
		tableAlias   string
	}{
		{
			name:      "basic",
			sql:       "SELECT * FROM produce UNPIVOT (sales FOR quarter IN (Q1, Q2, Q3, Q4))",
			valueCol:  "sales",
			nameCol:   "quarter",
			inColumns: []string{"Q1", "Q2", "Q3", "Q4"},
		},
		{
			name:         "INCLUDE NULLS with row value aliases and table alias",
			sql:          "SELECT * FROM produce UNPIVOT INCLUDE NULLS (sales FOR quarter IN (Q1 AS 'first', Q2 'second')) AS u",
			nullHandling: "INCLUDE NULLS",
			valueCol:     "sales",
			nameCol:      "quarter",
			inColumns:    []string{"Q1 AS 'first'", "Q2 AS 'second'"},
			tableAlias:   "u",
		},
		{
			name:         "EXCLUDE NULLS with INT64 row value aliases",
			sql:          "SELECT * FROM produce UNPIVOT exclude nulls (sales FOR quarter IN (Q1 AS 1, Q2 2))",
			nullHandling: "EXCLUDE NULLS",
			valueCol:     "sales",
			nameCol:      "quarter",
			inColumns:    []string{"Q1 AS 1", "Q2 AS 2"},
		},
		{
			name:      "multi-column",
			sql:       "SELECT * FROM produce UNPIVOT ((first_half_sales, second_half_sales) FOR semesters IN ((Q1, Q2) AS 'semester_1', (Q3, Q4) AS 'semester_2'))",
			valueCols: []string{"first_half_sales", "second_half_sales"},
			nameCol:   "semesters",
			inColumns: []string{"(Q1, Q2) AS 'semester_1'", "(Q3, Q4) AS 'semester_2'"},
		},
		{
			name: "quoted single value column", sql: "SELECT * FROM produce UNPIVOT (`日本` FOR quarter IN (Q1, Q2))",
			valueCol: "`日本`", nameCol: "quarter", inColumns: []string{"Q1", "Q2"},
		},
		{
			name: "quoted multiple value columns", sql: "SELECT * FROM produce UNPIVOT ((`日本`, `a``b`) FOR quarter IN ((Q1, Q2)))",
			valueCols: []string{"`日本`", "`a``b`"}, nameCol: "quarter", inColumns: []string{"(Q1, Q2)"},
		},
		{
			name:         "multi-column with NULLS modifier, unaliased sets and alias",
			sql:          "SELECT * FROM produce UNPIVOT INCLUDE NULLS ((a, b) FOR k IN ((Q1, Q2), (Q3, Q4))) unp",
			nullHandling: "INCLUDE NULLS",
			valueCols:    []string{"a", "b"},
			nameCol:      "k",
			inColumns:    []string{"(Q1, Q2)", "(Q3, Q4)"},
			tableAlias:   "unp",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ref := firstTableRef(t, tc.sql, bq)
			if ref.Unpivot == nil {
				t.Fatal("expected Unpivot clause")
			}
			u := ref.Unpivot
			if u.NullHandling != tc.nullHandling {
				t.Errorf("NullHandling = %q, want %q", u.NullHandling, tc.nullHandling)
			}
			if u.ValueColumn != tc.valueCol {
				t.Errorf("ValueColumn = %q, want %q", u.ValueColumn, tc.valueCol)
			}
			if !reflect.DeepEqual(u.ValueColumns, tc.valueCols) {
				t.Errorf("ValueColumns = %q, want %q", u.ValueColumns, tc.valueCols)
			}
			if u.NameColumn != tc.nameCol {
				t.Errorf("NameColumn = %q, want %q", u.NameColumn, tc.nameCol)
			}
			if !reflect.DeepEqual(u.InColumns, tc.inColumns) {
				t.Errorf("InColumns = %q, want %q", u.InColumns, tc.inColumns)
			}
			if ref.Alias != tc.tableAlias {
				t.Errorf("Alias = %q, want %q", ref.Alias, tc.tableAlias)
			}
		})
	}
}

// TestBigQueryPivot_Invalid_Issue854 verifies malformed BigQuery PIVOT /
// UNPIVOT is still rejected.
func TestBigQueryPivot_Invalid_Issue854(t *testing.T) {
	bad := []string{
		"SELECT * FROM t PIVOT (SUM(x) FOR q IN ())",
		"SELECT * FROM t PIVOT (SUM(x) AS FOR q IN ('a'))",
		"SELECT * FROM t UNPIVOT ((a, b) FOR k IN ((c1, c2, c3) AS 'x'))",
		"SELECT * FROM t UNPIVOT ((a, b) FOR k IN (c1, c2))",
		"SELECT * FROM t UNPIVOT ((a, b FOR k IN ((c1, c2)))",
		"SELECT * FROM t UNPIVOT INCLUDE (v FOR k IN (c1))",
		"SELECT * FROM t PIVOT (SUM(x) FOR q IN ('a' AS))",
		"SELECT * FROM t PIVOT (SUM(x) FOR q IN ('a' 'b'))",
		"SELECT * FROM t UNPIVOT (v FOR k IN (c1 AS))",
		"SELECT * FROM t UNPIVOT (v FOR k IN (c1 c2))",
	}
	for _, q := range bad {
		t.Run(q, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(q, keywords.DialectBigQuery)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("expected parse error for %q", q)
			}
		})
	}
}

// TestPivot_DialectGating_Issue854 pins which dialects recognise PIVOT /
// UNPIVOT now that the gate is Capabilities().SupportsPivotUnpivot: the
// default (no dialect), Generic, PostgreSQL, MySQL, MariaDB, SQLite,
// ClickHouse and Redshift must keep rejecting the clause, and the BigQuery /
// Oracle-only extensions must stay rejected in SQL Server and Snowflake.
func TestPivot_DialectGating_Issue854(t *testing.T) {
	const pivotSQL = "SELECT * FROM sales PIVOT (SUM(amount) FOR quarter IN ('Q1', 'Q2'))"
	const unpivotSQL = "SELECT * FROM sales UNPIVOT (amount FOR quarter IN (q1, q2))"

	t.Run("default dialect rejects", func(t *testing.T) {
		for _, q := range []string{pivotSQL, unpivotSQL} {
			if tree, err := gosqlx.Parse(q); err == nil {
				ast.ReleaseAST(tree)
				t.Errorf("default dialect: expected %q to be rejected", q)
			}
		}
	})

	rejecting := []keywords.SQLDialect{
		keywords.DialectGeneric,
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectMariaDB,
		keywords.DialectSQLite,
		keywords.DialectClickHouse,
		keywords.DialectRedshift,
	}
	for _, d := range rejecting {
		t.Run(string(d)+" rejects", func(t *testing.T) {
			for _, q := range []string{pivotSQL, unpivotSQL} {
				if tree, err := gosqlx.ParseWithDialect(q, d); err == nil {
					ast.ReleaseAST(tree)
					t.Errorf("%s: expected %q to be rejected", d, q)
				}
			}
		})
	}

	accepting := []keywords.SQLDialect{
		keywords.DialectSQLServer,
		keywords.DialectOracle,
		keywords.DialectSnowflake,
		keywords.DialectBigQuery,
	}
	for _, d := range accepting {
		t.Run(string(d)+" accepts", func(t *testing.T) {
			for _, q := range []string{pivotSQL, unpivotSQL} {
				tree, err := gosqlx.ParseWithDialect(q, d)
				if err != nil {
					t.Fatalf("%s: %q: %v", d, q, err)
				}
				ast.ReleaseAST(tree)
			}
		})
	}

	// "pivot" stays usable as a plain table alias where PIVOT is not a clause.
	t.Run("pivot as alias in PostgreSQL", func(t *testing.T) {
		ref := firstTableRef(t, "SELECT * FROM sales pivot", keywords.DialectPostgreSQL)
		if ref.Pivot != nil || ref.Alias != "pivot" {
			t.Fatalf("expected alias %q and no Pivot, got alias %q pivot %v", "pivot", ref.Alias, ref.Pivot)
		}
	})

	extensions := []struct {
		name string
		sql  string
		d    keywords.SQLDialect
	}{
		{"sqlserver multiple aggregates", "SELECT * FROM t PIVOT (SUM(x), COUNT(*) FOR q IN ([a]))", keywords.DialectSQLServer},
		{"sqlserver aggregate alias", "SELECT * FROM t PIVOT (SUM(x) AS s FOR q IN ([a]))", keywords.DialectSQLServer},
		{"sqlserver bare IN alias", "SELECT * FROM t PIVOT (SUM(x) FOR q IN ([a] b))", keywords.DialectSQLServer},
		{"sqlserver INCLUDE NULLS", "SELECT * FROM t UNPIVOT INCLUDE NULLS (v FOR k IN (c1))", keywords.DialectSQLServer},
		{"snowflake multiple aggregates", "SELECT * FROM t PIVOT (SUM(x), COUNT(*) FOR q IN ('a'))", keywords.DialectSnowflake},
		{"snowflake multi-column unpivot", "SELECT * FROM t UNPIVOT ((a, b) FOR k IN ((c1, c2)))", keywords.DialectSnowflake},
		{"oracle bare row value alias", "SELECT * FROM t UNPIVOT (v FOR k IN (c1 'x'))", keywords.DialectOracle},
	}
	for _, tc := range extensions {
		t.Run(tc.name+" rejected", func(t *testing.T) {
			if tree, err := gosqlx.ParseWithDialect(tc.sql, tc.d); err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("%s: expected %q to be rejected", tc.d, tc.sql)
			}
		})
	}

	accepted := []struct {
		name string
		sql  string
		d    keywords.SQLDialect
	}{
		{"oracle multiple aggregates", "SELECT * FROM t PIVOT (SUM(x) AS s, COUNT(*) AS n FOR q IN (1 AS a, 2 AS b))", keywords.DialectOracle},
		{"oracle multi-column unpivot", "SELECT * FROM t UNPIVOT ((a, b) FOR k IN ((c1, c2) AS 'x'))", keywords.DialectOracle},
		{"oracle INCLUDE NULLS", "SELECT * FROM t UNPIVOT INCLUDE NULLS (v FOR k IN (c1))", keywords.DialectOracle},
		{"snowflake INCLUDE NULLS", "SELECT * FROM t UNPIVOT INCLUDE NULLS (v FOR k IN (c1, c2))", keywords.DialectSnowflake},
		{"snowflake bare IN alias", "SELECT * FROM t PIVOT (SUM(x) FOR q IN ('a' qa))", keywords.DialectSnowflake},
	}
	for _, tc := range accepted {
		t.Run(tc.name+" accepted", func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.sql, tc.d)
			if err != nil {
				t.Fatalf("%s: %q: %v", tc.d, tc.sql, err)
			}
			ast.ReleaseAST(tree)
		})
	}
}
