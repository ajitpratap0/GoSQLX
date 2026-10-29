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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// assertRoundTrip parses sql, renders it with SQL() and the formatter, and
// asserts that each rendering reparses to the same tree. It returns the
// parsed tree (released by the caller's cleanup).
func assertRoundTrip(t *testing.T, d keywords.SQLDialect, sql string) *ast.AST {
	t.Helper()
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	t.Cleanup(func() { ast.ReleaseAST(tree) })
	outputs := []string{tree.SQL()}
	for _, opts := range []gosqlx.FormatOptions{gosqlx.DefaultFormatOptions(), {IndentSize: 0}} {
		formatted, err := gosqlx.FormatWithDialect(sql, opts, d)
		if err != nil {
			t.Fatalf("format %q: %v", sql, err)
		}
		outputs = append(outputs, formatted)
	}
	for _, out := range outputs {
		other, err := gosqlx.ParseWithDialect(out, d)
		if err != nil {
			t.Fatalf("reparse %q: %v", out, err)
		}
		clearDDLSourcePositions(reflect.ValueOf(tree))
		clearDDLSourcePositions(reflect.ValueOf(other))
		same := reflect.DeepEqual(tree.Statements, other.Statements)
		ast.ReleaseAST(other)
		if !same {
			t.Fatalf("tree changed after rendering %q", out)
		}
	}
	return tree
}

// reachable reports whether target is visited by ast.Inspect from root.
func reachable(root, target ast.Node) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n == target {
			found = true
		}
		return !found
	})
	return found
}

func TestMySQLPartitionActionsStructured(t *testing.T) {
	type check func(t *testing.T, stmt *ast.AlterStatement, op *ast.AlterTableOperation)
	names := func(want ...string) check {
		return func(t *testing.T, _ *ast.AlterStatement, op *ast.AlterTableOperation) {
			var got []string
			for _, n := range op.PartitionNames {
				got = append(got, n.Name)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("PartitionNames = %v, want %v", got, want)
			}
		}
	}
	all := func(t *testing.T, _ *ast.AlterStatement, op *ast.AlterTableOperation) {
		if !op.PartitionAll || len(op.PartitionNames) != 0 {
			t.Errorf("PartitionAll = %v, names %v", op.PartitionAll, op.PartitionNames)
		}
	}
	count := func(t *testing.T, stmt *ast.AlterStatement, op *ast.AlterTableOperation) {
		if op.PartitionCount == nil || !reachable(stmt, op.PartitionCount) {
			t.Error("PartitionCount missing or unreachable")
		}
	}
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
		keyword string
		ops     int
		check   check
	}{
		{keywords.DialectMySQL, "ALTER TABLE t TRUNCATE PARTITION ALL", "TRUNCATE PARTITION", 1, all},
		{keywords.DialectMariaDB, "ALTER TABLE t TRUNCATE PARTITION ALL", "TRUNCATE PARTITION", 1, all},
		{keywords.DialectMySQL, "ALTER TABLE t DROP PARTITION p0, ALGORITHM=INPLACE, LOCK=NONE", "DROP PARTITION", 3, names("p0")},
		{keywords.DialectMySQL, "ALTER TABLE t DROP PARTITION p0, p1, ALGORITHM INPLACE", "DROP PARTITION", 2, names("p0", "p1")},
		{keywords.DialectMySQL, "ALTER TABLE t ADD PARTITION (PARTITION p2 VALUES LESS THAN (2030)), ALGORITHM=INPLACE", "ADD PARTITION", 2, nil},
		{keywords.DialectMariaDB, "ALTER TABLE t DROP PARTITION IF EXISTS p0", "DROP PARTITION", 1, func(t *testing.T, s *ast.AlterStatement, op *ast.AlterTableOperation) {
			if !op.IfExists {
				t.Error("IfExists not set")
			}
			names("p0")(t, s, op)
		}},
		{keywords.DialectMariaDB, "ALTER TABLE t ADD PARTITION IF NOT EXISTS (PARTITION p VALUES IN (1))", "ADD PARTITION", 1, func(t *testing.T, _ *ast.AlterStatement, op *ast.AlterTableOperation) {
			if !op.IfNotExists || len(op.PartitionDefinitions) != 1 {
				t.Errorf("IfNotExists = %v, defs %d", op.IfNotExists, len(op.PartitionDefinitions))
			}
		}},
		{keywords.DialectMariaDB, "ALTER TABLE t ADD PARTITION (PARTITION p3 CURRENT)", "ADD PARTITION", 1, nil},
		{keywords.DialectMariaDB, "ALTER TABLE t ADD PARTITION (PARTITION p3 HISTORY, PARTITION p4 HISTORY)", "ADD PARTITION", 1, nil},
		{keywords.DialectMySQL, "ALTER TABLE t ADD PARTITION (PARTITION p3)", "ADD PARTITION", 1, nil},
		{keywords.DialectMySQL, "ALTER TABLE t ADD PARTITION PARTITIONS 2", "ADD PARTITION", 1, count},
		{keywords.DialectMySQL, "ALTER TABLE t COALESCE PARTITION 2", "COALESCE PARTITION", 1, count},
		{keywords.DialectMySQL, "ALTER TABLE t EXCHANGE PARTITION p WITH TABLE db.t2", "EXCHANGE PARTITION", 1, func(t *testing.T, s *ast.AlterStatement, op *ast.AlterTableOperation) {
			if op.ExchangeTable.Name != "db.t2" || op.Validation != "" {
				t.Errorf("ExchangeTable = %q, Validation = %q", op.ExchangeTable.Name, op.Validation)
			}
			names("p")(t, s, op)
		}},
		{keywords.DialectMySQL, "ALTER TABLE t EXCHANGE PARTITION p WITH TABLE t2 WITHOUT VALIDATION", "EXCHANGE PARTITION", 1, func(t *testing.T, _ *ast.AlterStatement, op *ast.AlterTableOperation) {
			if op.Validation != "WITHOUT" {
				t.Errorf("Validation = %q", op.Validation)
			}
		}},
		{keywords.DialectMySQL, "ALTER TABLE t EXCHANGE PARTITION p WITH TABLE t2 WITH VALIDATION", "EXCHANGE PARTITION", 1, nil},
		{keywords.DialectMySQL, "ALTER TABLE t ANALYZE PARTITION p0, p1", "ANALYZE PARTITION", 1, names("p0", "p1")},
		{keywords.DialectMySQL, "ALTER TABLE t CHECK PARTITION ALL", "CHECK PARTITION", 1, all},
		{keywords.DialectMySQL, "ALTER TABLE t OPTIMIZE PARTITION p0", "OPTIMIZE PARTITION", 1, names("p0")},
		{keywords.DialectMySQL, "ALTER TABLE t REBUILD PARTITION p0, p1", "REBUILD PARTITION", 1, names("p0", "p1")},
		{keywords.DialectMySQL, "ALTER TABLE t REPAIR PARTITION ALL", "REPAIR PARTITION", 1, all},
		{keywords.DialectMySQL, "ALTER TABLE t DISCARD PARTITION p0, p1 TABLESPACE", "DISCARD PARTITION", 1, names("p0", "p1")},
		{keywords.DialectMySQL, "ALTER TABLE t IMPORT PARTITION ALL TABLESPACE", "IMPORT PARTITION", 1, all},
		{keywords.DialectMySQL, "ALTER TABLE t UPGRADE PARTITIONING", "UPGRADE PARTITIONING", 1, nil},
		{keywords.DialectMySQL, "alter table t reorganize partition p0,p1 into (partition p01 values less than (20))", "REORGANIZE PARTITION", 1, names("p0", "p1")},
	}
	for _, tc := range cases {
		t.Run(string(tc.dialect)+"/"+tc.sql, func(t *testing.T) {
			tree := assertRoundTrip(t, tc.dialect, tc.sql)
			stmt, ok := tree.Statements[0].(*ast.AlterStatement)
			if !ok {
				t.Fatalf("got %T", tree.Statements[0])
			}
			if len(stmt.Operations) != tc.ops {
				t.Fatalf("%d operations, want %d", len(stmt.Operations), tc.ops)
			}
			op, ok := stmt.Operations[0].(*ast.AlterTableOperation)
			if !ok {
				t.Fatalf("got %T", stmt.Operations[0])
			}
			if op.Type != ast.AlterPartitioning || op.Keyword != tc.keyword {
				t.Fatalf("Type %v Keyword %q, want AlterPartitioning %q", op.Type, op.Keyword, tc.keyword)
			}
			for _, extra := range stmt.Operations[1:] {
				if o, ok := extra.(*ast.AlterTableOperation); !ok || o.Type != ast.AlterTableOther {
					t.Errorf("table option parsed as %#v", extra)
				}
			}
			if tc.check != nil {
				tc.check(t, stmt, op)
			}
		})
	}
}

// MySQL has no IF [NOT] EXISTS on partition actions and no HISTORY /
// CURRENT partitions: these keep the as-written fallback earlier releases
// used rather than a structured (MariaDB) reading.
func TestMySQLPartitionMariaDBOnlyFormsNotStructured(t *testing.T) {
	for _, sql := range []string{
		"ALTER TABLE t DROP PARTITION IF EXISTS p0",
		"ALTER TABLE t ADD PARTITION IF NOT EXISTS (PARTITION p VALUES IN (1))",
		"ALTER TABLE t ADD PARTITION (PARTITION p3 HISTORY)",
	} {
		t.Run(sql, func(t *testing.T) {
			tree := assertRoundTrip(t, keywords.DialectMySQL, sql)
			stmt, ok := tree.Statements[0].(*ast.AlterStatement)
			if !ok {
				t.Fatalf("got %T", tree.Statements[0])
			}
			if op, ok := stmt.Operation.(*ast.AlterTableOperation); !ok || op.Type != ast.AlterTableOther {
				t.Fatalf("operation = %#v, want AlterTableOther", stmt.Operation)
			}
		})
	}
}

func TestClickHouseSampleRejectsNonDecimalNumbers(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM t SAMPLE 0x10",
		"SELECT * FROM t AS x FINAL SAMPLE 0x10",
		"SELECT * FROM t SAMPLE 10 OFFSET 0x10",
		"SELECT * FROM t SAMPLE 1/0x10",
		"SELECT * FROM t SAMPLE 1/10 OFFSET 1/0x2",
		"SELECT * FROM t JOIN u SAMPLE 0x10 ON 1",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse)
			if err == nil {
				out := tree.SQL()
				ast.ReleaseAST(tree)
				t.Fatalf("expected syntax error, parsed as %q", out)
			}
		})
	}
}

func TestClickHouseSampleOnJoinedTables(t *testing.T) {
	cases := []struct {
		sql string
		// stmtSample: SAMPLE kept on SelectStatement.Sample (lone table).
		stmtSample bool
		// joinSamples: per joined table, whether it carries a SAMPLE.
		joinSamples []bool
		firstSample bool
	}{
		{"SELECT * FROM t JOIN u SAMPLE 0.5 ON 1", false, []bool{true}, false},
		{"SELECT * FROM t x FINAL SAMPLE 0.1 JOIN u y FINAL SAMPLE 0.2 ON x.a = y.a", false, []bool{true}, true},
		{"SELECT * FROM t FINAL JOIN u FINAL SAMPLE 1/10 OFFSET 1/2 USING (a)", false, []bool{true}, false},
		{"SELECT * FROM t LEFT JOIN (SELECT 1 AS a) AS s SAMPLE 0.5 ON 1", false, []bool{true}, false},
		{"SELECT * FROM hits AS h FINAL SAMPLE 0.1 WHERE x = 1", true, nil, false},
		{"SELECT * FROM t SAMPLE 10 ARRAY JOIN arr", true, nil, false},
		{"SELECT * FROM t SAMPLE 1/10 OFFSET 1/2 LEFT ARRAY JOIN arr AS e PREWHERE a = 1", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree := assertRoundTrip(t, keywords.DialectClickHouse, tc.sql)
			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("got %T", tree.Statements[0])
			}
			if (stmt.Sample != nil) != tc.stmtSample {
				t.Errorf("statement Sample = %v, want %v", stmt.Sample, tc.stmtSample)
			}
			if stmt.Sample != nil && !reachable(stmt, stmt.Sample.Size) {
				t.Error("statement SAMPLE size unreachable")
			}
			hasSample := func(ref *ast.TableReference) bool {
				return ref.Modifiers != nil && ref.Modifiers.Sample != nil
			}
			if got := hasSample(&stmt.From[0]); got != tc.firstSample {
				t.Errorf("first table Sample = %v, want %v", got, tc.firstSample)
			}
			if len(stmt.Joins) != len(tc.joinSamples) {
				t.Fatalf("%d joins, want %d", len(stmt.Joins), len(tc.joinSamples))
			}
			for i, want := range tc.joinSamples {
				ref := &stmt.Joins[i].Right
				if got := hasSample(ref); got != want {
					t.Errorf("join %d Sample = %v, want %v", i, got, want)
				}
				if want && !reachable(stmt, ref.Modifiers.Sample.Size) {
					t.Errorf("join %d SAMPLE size unreachable", i)
				}
			}
		})
	}
	for _, sql := range []string{
		"SELECT * FROM t SAMPLE 0.1 FINAL",
		"SELECT * FROM t SAMPLE 0.1 SAMPLE 0.2",
		"SELECT * FROM t JOIN u SAMPLE 0.1 SAMPLE 0.2 ON 1",
	} {
		t.Run("reject/"+sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected syntax error")
			}
		})
	}
}

func TestNestedGroupingSets(t *testing.T) {
	cases := []struct {
		dialect keywords.SQLDialect
		sql     string
		depth   int
	}{
		{keywords.DialectPostgreSQL, "SELECT a, b FROM t GROUP BY GROUPING SETS (GROUPING SETS ((a), (b)), c)", 2},
		{keywords.DialectPostgreSQL, "SELECT a FROM t GROUP BY GROUPING SETS (GROUPING SETS (GROUPING SETS (a, ROLLUP(b))), ())", 3},
		{keywords.DialectSnowflake, "SELECT a FROM t GROUP BY grouping sets (grouping sets (a), cube(a, b))", 2},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree := assertRoundTrip(t, tc.dialect, tc.sql)
			stmt, ok := tree.Statements[0].(*ast.SelectStatement)
			if !ok {
				t.Fatalf("got %T", tree.Statements[0])
			}
			depth := 0
			ast.Inspect(stmt, func(n ast.Node) bool {
				if _, ok := n.(*ast.GroupingSetsExpression); ok {
					depth++
				}
				return true
			})
			if depth != tc.depth {
				t.Errorf("%d GROUPING SETS nodes, want %d", depth, tc.depth)
			}
		})
	}
	deep := "SELECT a FROM t GROUP BY " + strings.Repeat("GROUPING SETS (", 200) + "a" + strings.Repeat(")", 200)
	if tree, err := gosqlx.ParseWithDialect(deep, keywords.DialectPostgreSQL); err == nil {
		ast.ReleaseAST(tree)
		t.Error("expected recursion depth error for 200 nested GROUPING SETS")
	}
}

func TestColumnValueSourceConflictsRejected(t *testing.T) {
	for _, sql := range []string{
		"CREATE TABLE t (a int GENERATED ALWAYS AS IDENTITY DEFAULT 5)",
		"CREATE TABLE t (a int DEFAULT 5 GENERATED BY DEFAULT AS IDENTITY)",
		"CREATE TABLE t (a int GENERATED ALWAYS AS IDENTITY GENERATED BY DEFAULT AS IDENTITY)",
		"CREATE TABLE t (a int GENERATED ALWAYS AS IDENTITY NOT NULL GENERATED ALWAYS AS IDENTITY)",
		"CREATE TABLE t (a int, b int GENERATED ALWAYS AS (a * 2) STORED GENERATED ALWAYS AS IDENTITY)",
		"CREATE TABLE t (a int, b int GENERATED ALWAYS AS (a * 2) STORED DEFAULT 1)",
		"ALTER TABLE t ADD COLUMN a int GENERATED ALWAYS AS IDENTITY DEFAULT 1",
	} {
		t.Run(sql, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectPostgreSQL)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("expected syntax error")
			}
		})
	}
	// One value source combined with other constraints in any order is fine.
	assertRoundTrip(t, keywords.DialectPostgreSQL, "CREATE TABLE t (a int NOT NULL GENERATED ALWAYS AS IDENTITY PRIMARY KEY, b int DEFAULT 1 NOT NULL, c int GENERATED ALWAYS AS (a + 1) STORED NOT NULL)")
}

func TestIdentityOptionsKeepNumberSign(t *testing.T) {
	cases := []struct {
		sql  string
		want string
	}{
		{"CREATE TABLE t (a int GENERATED ALWAYS AS IDENTITY (INCREMENT -1))", "(INCREMENT -1)"},
		{"CREATE TABLE t (a int GENERATED BY DEFAULT AS IDENTITY (START WITH -5 INCREMENT BY -1 MINVALUE -100))", "(START WITH -5 INCREMENT BY -1 MINVALUE -100)"},
		{"CREATE TABLE t (a int GENERATED ALWAYS AS IDENTITY (START WITH +3))", "(START WITH +3)"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			tree := assertRoundTrip(t, keywords.DialectPostgreSQL, tc.sql)
			if out := tree.SQL(); !strings.Contains(out, tc.want) {
				t.Errorf("SQL() = %q, want it to contain %q", out, tc.want)
			}
		})
	}
}
