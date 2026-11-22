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

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestChildrenReachEveryExpression parses statements that carry marker
// identifiers (mkN) in clauses stored outside the main column/where fields
// and checks ast.Inspect reaches every one, so walkers (security scanner,
// linter, table extraction) do not skip those subtrees.
func TestChildrenReachEveryExpression(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		markers int
	}{
		{"clickhouse engine clauses", keywords.DialectClickHouse,
			"CREATE TABLE t (a Int) ENGINE=MergeTree ORDER BY mk1 PARTITION BY mk2 SAMPLE BY mk3 TTL mk4 + INTERVAL 1 DAY SETTINGS x = mk5", 5},
		{"clickhouse engine args", keywords.DialectClickHouse,
			"CREATE TABLE t (a Int) ENGINE = Distributed(mk1, mk2, t, rand())", 2},
		{"clickhouse materialized view", keywords.DialectClickHouse,
			"CREATE MATERIALIZED VIEW v ENGINE=MergeTree ORDER BY mk1 PARTITION BY mk2 AS SELECT 1", 2},
		{"clickhouse array join", keywords.DialectClickHouse,
			"SELECT * FROM t ARRAY JOIN mk1 AS x", 1},
		{"snowflake clone point", keywords.DialectSnowflake,
			"CREATE TABLE c CLONE s AT (TIMESTAMP => mk1)", 1},
		{"postgres partition from to", keywords.DialectPostgreSQL,
			"CREATE TABLE p PARTITION OF q FOR VALUES FROM (mk1) TO (mk2)", 2},
		{"postgres partition in", keywords.DialectPostgreSQL,
			"CREATE TABLE p PARTITION OF q FOR VALUES IN (mk1, mk2)", 2},
		{"postgres partition hash", keywords.DialectPostgreSQL,
			"CREATE TABLE p PARTITION OF q FOR VALUES WITH (MODULUS mk1, REMAINDER mk2)", 2},
		{"sqlserver top", keywords.DialectSQLServer,
			"SELECT TOP (mk1) a FROM t", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.sql, err)
			}
			seen := map[string]bool{}
			for _, stmt := range tree.Statements {
				ast.Inspect(stmt, func(n ast.Node) bool {
					if id, ok := n.(*ast.Identifier); ok && strings.HasPrefix(id.Name, "mk") {
						seen[id.Name] = true
					}
					return true
				})
			}
			for i := 1; i <= tc.markers; i++ {
				name := "mk" + string(rune('0'+i))
				if !seen[name] {
					t.Errorf("%s not reached by ast.Inspect in %q", name, tc.sql)
				}
			}
		})
	}
}

// TestMergeSourceColumnAliasesRender checks the column alias list of a MERGE
// derived-table source survives rendering.
func TestMergeSourceColumnAliasesRender(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{keywords.DialectSQLServer,
			"MERGE dbo.Target AS t USING (VALUES (1,N'a'),(2,N'b')) AS s (Id, Val) ON t.Id = s.Id WHEN MATCHED THEN UPDATE SET Val = s.Val",
			"s (Id, Val) ON"},
		{keywords.DialectPostgreSQL,
			"MERGE INTO t USING (SELECT 1,2) AS s(c1,c2) ON t.id = s.c1 WHEN MATCHED THEN DELETE",
			"s(c1, c2) ON"},
	}
	for _, tc := range tests {
		tree, err := ParseWithDialect(tc.sql, tc.dialect)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		got := tree.SQL()
		if !strings.Contains(strings.ReplaceAll(got, " (", "("), strings.ReplaceAll(tc.want, " (", "(")) {
			t.Errorf("%s: rendered %q lacks column aliases %q", tc.dialect, got, tc.want)
		}
	}
}

// TestASTSQLFallsBackToToSQL covers statements that only implement ToSQL.
func TestASTSQLFallsBackToToSQL(t *testing.T) {
	tree, err := ParseWithDialect("CREATE SEQUENCE seq_orders START WITH 1 INCREMENT BY 1", keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := tree.SQL()
	if !strings.Contains(strings.ToUpper(got), "CREATE SEQUENCE") || !strings.Contains(got, "seq_orders") {
		t.Errorf("AST.SQL() = %q, want the CREATE SEQUENCE statement", got)
	}
}
