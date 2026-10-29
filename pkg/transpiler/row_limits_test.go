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

package transpiler_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspileTopAcrossDialects(t *testing.T) {
	for _, target := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectOracle, keywords.DialectGeneric} {
		t.Run(string(target), func(t *testing.T) {
			want := "SELECT a FROM t LIMIT 1"
			if target == keywords.DialectOracle || target == keywords.DialectGeneric {
				want = "SELECT a FROM t FETCH FIRST 1 ROW ONLY"
			}
			got, err := transpiler.Transpile("SELECT TOP (1) a FROM t", keywords.DialectSQLServer, target)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
			tree, err := parser.ParseWithDialect(got, target)
			if err != nil {
				t.Fatalf("target SQL does not parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

func TestTranspileLimitToTopAcrossDialects(t *testing.T) {
	for _, source := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectGeneric} {
		t.Run(string(source), func(t *testing.T) {
			got, err := transpiler.Transpile("SELECT a FROM t ORDER BY a LIMIT 2", source, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			if got != "SELECT TOP 2 a FROM t ORDER BY a" {
				t.Fatalf("unexpected SQL: %s", got)
			}
		})
	}
}

func TestTranspileTopRejectsUnsupportedSemantics(t *testing.T) {
	for _, target := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite, keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectOracle, keywords.DialectGeneric} {
		for _, sql := range []string{"SELECT TOP 10 PERCENT a FROM t", "SELECT TOP 1 WITH TIES a FROM t ORDER BY a", "SELECT TOP (@n) a FROM t", "SELECT a FROM (SELECT TOP 10 PERCENT a FROM t) AS q"} {
			t.Run(string(target)+"/"+sql, func(t *testing.T) {
				got, err := transpiler.Transpile(sql, keywords.DialectSQLServer, target)
				if err == nil || got != "" {
					t.Fatalf("got %q, %v; want refusal", got, err)
				}
			})
		}
	}
}

func TestTranspileNestedTop(t *testing.T) {
	got, err := transpiler.Transpile("SELECT a FROM (SELECT TOP 3 a FROM t) AS q", keywords.DialectSQLServer, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "TOP") || !strings.Contains(got, "LIMIT 3") {
		t.Fatalf("nested TOP not rewritten: %s", got)
	}
}

func TestTranspileRowLimitEdges(t *testing.T) {
	tests := []struct {
		name, sql, want string
		from, to        keywords.SQLDialect
	}{
		{"top_zero", "SELECT TOP 0 a FROM t", "SELECT a FROM t LIMIT 0", keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{"limit_zero", "SELECT a FROM t LIMIT 0", "SELECT TOP 0 a FROM t", keywords.DialectPostgreSQL, keywords.DialectSQLServer},
		{"limit_offset", "SELECT a FROM t ORDER BY a LIMIT 2 OFFSET 3", "SELECT a FROM t ORDER BY a OFFSET 3 ROWS FETCH NEXT 2 ROWS ONLY", keywords.DialectPostgreSQL, keywords.DialectSQLServer},
		{"cte", "WITH q AS (SELECT TOP 2 a FROM t) SELECT a FROM q", "WITH q AS (SELECT a FROM t LIMIT 2) SELECT a FROM q", keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{"set_operation", "SELECT TOP 2 a FROM t UNION ALL SELECT TOP 3 a FROM u", "(SELECT a FROM t LIMIT 2) UNION ALL (SELECT a FROM u LIMIT 3)", keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{"cte_set_operation", "WITH q AS (SELECT a FROM t) SELECT TOP 2 a FROM q UNION ALL SELECT a FROM q", "WITH q AS (SELECT a FROM t) (SELECT a FROM q LIMIT 2) UNION ALL SELECT a FROM q", keywords.DialectSQLServer, keywords.DialectPostgreSQL},
		{"same_dialect", "SELECT TOP 10 PERCENT a FROM t", "SELECT TOP 10 PERCENT a FROM t", keywords.DialectSQLServer, keywords.DialectSQLServer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transpiler.Transpile(tt.sql, tt.from, tt.to)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			tree, err := parser.ParseWithDialect(got, tt.to)
			if err != nil {
				t.Fatalf("target SQL does not parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

func TestTranspileTopSetOperandToSQLiteRefused(t *testing.T) {
	got, err := transpiler.Transpile("SELECT TOP 2 a FROM t UNION ALL SELECT a FROM u", keywords.DialectSQLServer, keywords.DialectSQLite)
	if err == nil || got != "" {
		t.Fatalf("got %q, %v; want refusal", got, err)
	}
}

func TestTranspileLimitWithTiesToSQLServerRefused(t *testing.T) {
	for _, sql := range []string{
		"SELECT a FROM t ORDER BY a LIMIT 2 WITH TIES",
		"SELECT a FROM t ORDER BY a LIMIT 2 WITH TIES OFFSET 1",
		"SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 2 WITH TIES",
	} {
		t.Run(sql, func(t *testing.T) {
			got, err := transpiler.Transpile(sql, keywords.DialectClickHouse, keywords.DialectSQLServer)
			if err == nil || got != "" {
				t.Fatalf("got %q, %v; want refusal", got, err)
			}
		})
	}
}

func TestTranspileDMLTopRefused(t *testing.T) {
	for _, sql := range []string{"UPDATE TOP (2) t SET a = 1", "DELETE TOP (2) FROM t"} {
		t.Run(sql, func(t *testing.T) {
			got, err := transpiler.Transpile(sql, keywords.DialectSQLServer, keywords.DialectPostgreSQL)
			if err == nil || got != "" || !strings.Contains(err.Error(), "DML TOP") {
				t.Fatalf("got %q, %v; want DML TOP refusal", got, err)
			}
		})
	}
}

func TestTranspileSetOperationRowLimits(t *testing.T) {
	pg, ms := keywords.DialectPostgreSQL, keywords.DialectSQLServer
	type testCase struct {
		name, sql, want string
		from, to        keywords.SQLDialect
	}
	tests := []testCase{
		{"union", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms},
		{"union_all_offset", "SELECT a FROM t UNION ALL SELECT b FROM u ORDER BY 1 LIMIT 5 OFFSET 2", "SELECT a FROM t UNION ALL SELECT b FROM u ORDER BY 1 OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms},
		{"mysql_nested", "SELECT a FROM t EXCEPT SELECT b FROM u UNION SELECT c FROM v ORDER BY 1 LIMIT 5", "SELECT a FROM t EXCEPT SELECT b FROM u UNION SELECT c FROM v ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY", keywords.DialectMySQL, ms},
		{"precedence_nested", "SELECT a FROM t UNION SELECT b FROM u INTERSECT SELECT c FROM v ORDER BY 1 LIMIT 5", "SELECT a FROM t UNION SELECT b FROM u INTERSECT SELECT c FROM v ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms},
		{"derived", "SELECT * FROM (SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5) x", "SELECT * FROM (SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY) x", pg, ms},
		{"cte", "WITH c AS (SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5) SELECT * FROM c", "WITH c AS (SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY) SELECT * FROM c", pg, ms},
		{"parenthesized_set", "(SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 2) UNION SELECT c FROM v", "(SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 2 ROWS ONLY) UNION SELECT c FROM v", pg, ms},
		{"tail", "SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT 5", "SELECT a FROM t UNION ALL (SELECT TOP 1 b FROM u ORDER BY b) ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms},
		{"tail_offset", "SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT 5 OFFSET 2", "SELECT a FROM t UNION ALL (SELECT TOP 1 b FROM u ORDER BY b) ORDER BY 1 OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms},
		{"tail_dynamic", "SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT $1 OFFSET $2", "SELECT a FROM t UNION ALL (SELECT TOP 1 b FROM u ORDER BY b) ORDER BY 1 OFFSET $2 ROWS FETCH NEXT $1 ROWS ONLY", pg, ms},
		{"offset_only", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 2", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 2 ROWS", pg, ms},
		{"branch_limits", "(SELECT a FROM t LIMIT 3) UNION (SELECT b FROM u LIMIT 4)", "(SELECT TOP 3 a FROM t) UNION (SELECT TOP 4 b FROM u)", pg, ms},
		{"plain_select", "SELECT a FROM t ORDER BY a LIMIT 5", "SELECT TOP 5 a FROM t ORDER BY a", pg, ms},
		{"mysql_target", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5", pg, keywords.DialectMySQL},
		{"oracle_target", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 FETCH FIRST 5 ROWS ONLY", pg, keywords.DialectOracle},
		{"reverse_branch_order", "SELECT a FROM t UNION (SELECT TOP 3 b FROM u ORDER BY b)", "SELECT a FROM t UNION (SELECT b FROM u ORDER BY b LIMIT 3)", ms, pg},
		{"reverse_left", "SELECT TOP 3 a FROM t UNION SELECT b FROM u", "(SELECT a FROM t LIMIT 3) UNION SELECT b FROM u", ms, pg},
	}
	for _, op := range []string{"UNION", "INTERSECT", "EXCEPT"} {
		tests = append(tests, testCase{
			"forward_" + op, "SELECT a FROM t " + op + " SELECT b FROM u ORDER BY 1 LIMIT 5", "SELECT a FROM t " + op + " SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY", pg, ms,
		})
		for _, target := range []keywords.SQLDialect{pg, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectGeneric} {
			limit := "LIMIT 3"
			if target == keywords.DialectOracle || target == keywords.DialectGeneric {
				limit = "FETCH FIRST 3 ROWS ONLY"
			}
			tests = append(tests, testCase{
				"reverse_" + op + "_" + string(target), "SELECT a FROM t " + op + " SELECT TOP 3 b FROM u ORDER BY 1", "SELECT a FROM t " + op + " (SELECT b FROM u " + limit + ") ORDER BY 1", ms, target,
			})
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transpiler.Transpile(tt.sql, tt.from, tt.to)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			tree, err := parser.ParseWithDialect(got, tt.to)
			if err != nil {
				t.Fatalf("target SQL does not parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}

func TestTranspileSetOperationRowLimitErrors(t *testing.T) {
	for _, sql := range []string{
		"SELECT a FROM t UNION SELECT b FROM u LIMIT 5",
		"SELECT a FROM t UNION SELECT b FROM u LIMIT 5 OFFSET 2",
		"SELECT a FROM t UNION SELECT b FROM u OFFSET 2",
		"SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) LIMIT 5",
		"SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) OFFSET 2",
	} {
		t.Run(sql, func(t *testing.T) {
			got, err := transpiler.Transpile(sql, keywords.DialectPostgreSQL, keywords.DialectSQLServer)
			if got != "" || err == nil || !strings.Contains(err.Error(), "ORDER BY") || !strings.Contains(err.Error(), "SQL Server") {
				t.Fatalf("got %q, %v; want ORDER BY/SQL Server error", got, err)
			}
		})
	}
	got, err := transpiler.Transpile("SELECT a FROM t UNION SELECT TOP 3 b FROM u ORDER BY 1", keywords.DialectSQLServer, keywords.DialectSQLite)
	if got != "" || err == nil || !strings.Contains(err.Error(), "SQLite") {
		t.Fatalf("got %q, %v; want SQLite error", got, err)
	}
}

func TestTranspileTopSetOperandConflictingTailOrder(t *testing.T) {
	tree, err := parser.ParseWithDialect("SELECT a FROM t UNION SELECT TOP 3 b FROM u ORDER BY 1", keywords.DialectSQLServer)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	set, ok := tree.Statements[0].(*ast.SetOperation)
	if !ok {
		t.Fatalf("expected SetOperation, got %T", tree.Statements[0])
	}
	// A hand-built AST may have both trailing representations populated.
	set.Tail = &ast.QueryTail{OrderBy: []ast.OrderByExpression{{Expression: &ast.LiteralValue{Value: 2, Type: "int"}}}}
	for _, rule := range transpiler.RulesFor(keywords.DialectSQLServer, keywords.DialectPostgreSQL) {
		if err = rule(set); err != nil {
			break
		}
	}
	if err == nil || !strings.Contains(err.Error(), "conflicting set-level ORDER BY") {
		t.Fatalf("got %v; want conflicting ORDER BY error", err)
	}
}

func TestTranspileSQLServerOffsetFetch(t *testing.T) {
	cases := []struct{ sql, want string }{
		{"SELECT a FROM t LIMIT 5 OFFSET 2", "SELECT a FROM t ORDER BY (SELECT NULL) OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY"},
		{"SELECT a FROM t ORDER BY a LIMIT 5 OFFSET 2", "SELECT a FROM t ORDER BY a OFFSET 2 ROWS FETCH NEXT 5 ROWS ONLY"},
		{"SELECT a FROM t LIMIT 5", "SELECT TOP 5 a FROM t"},
		{"SELECT a FROM t ORDER BY 1 FETCH FIRST 5 ROWS ONLY", "SELECT a FROM t ORDER BY 1 OFFSET 0 ROWS FETCH FIRST 5 ROWS ONLY"},
		{"SELECT a FROM t FETCH FIRST 5 ROWS ONLY", "SELECT a FROM t ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH FIRST 5 ROWS ONLY"},
		{"SELECT a FROM t OFFSET 3", "SELECT a FROM t ORDER BY (SELECT NULL) OFFSET 3 ROWS"},
		{"SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 FETCH FIRST 5 ROWS ONLY", "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 OFFSET 0 ROWS FETCH FIRST 5 ROWS ONLY"},
	}
	for _, source := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite} {
		for _, tc := range cases {
			t.Run(string(source)+"/"+tc.sql, func(t *testing.T) {
				got, err := transpiler.Transpile(tc.sql, source, keywords.DialectSQLServer)
				if err != nil {
					t.Fatal(err)
				}
				if got != tc.want {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
				tree, err := parser.ParseWithDialect(got, keywords.DialectSQLServer)
				if err != nil {
					t.Fatalf("target SQL does not parse: %v", err)
				}
				defer ast.ReleaseAST(tree)
			})
		}
	}
	for _, sql := range []string{"SELECT a FROM t UNION SELECT b FROM u FETCH FIRST 5 ROWS ONLY", "SELECT a FROM t UNION (SELECT b FROM u) FETCH FIRST 5 ROWS ONLY"} {
		if got, err := transpiler.Transpile(sql, keywords.DialectPostgreSQL, keywords.DialectSQLServer); err == nil || got != "" {
			t.Fatalf("got %q, %v; want set operation ORDER BY refusal", got, err)
		}
	}
}

func TestTranspileWithTiesNeverLost(t *testing.T) {
	for _, sql := range []string{
		"SELECT a FROM t ORDER BY 1 LIMIT 5 WITH TIES",
		"SELECT a FROM t ORDER BY 1 LIMIT 5 WITH TIES OFFSET 2",
		"SELECT a FROM t UNION ALL SELECT b FROM u ORDER BY 1 LIMIT 5 WITH TIES",
		"SELECT a FROM t UNION ALL (SELECT b FROM u) ORDER BY 1 LIMIT 5 WITH TIES",
		"SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT 5 WITH TIES",
		"SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 LIMIT 5 WITH TIES OFFSET 2",
		"SELECT a FROM t ORDER BY 1 FETCH FIRST 5 ROWS WITH TIES",
		"SELECT a FROM t UNION ALL (SELECT b FROM u) ORDER BY 1 FETCH FIRST 5 ROWS WITH TIES",
		"SELECT a FROM t UNION ALL (SELECT b FROM u ORDER BY b LIMIT 1) ORDER BY 1 FETCH FIRST 5 ROWS WITH TIES",
	} {
		for _, target := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectOracle, keywords.DialectMySQL, keywords.DialectSQLite, keywords.DialectSQLServer} {
			t.Run(string(target)+"/"+sql, func(t *testing.T) {
				got, err := transpiler.Transpile(sql, keywords.DialectClickHouse, target)
				if err != nil {
					if target == keywords.DialectPostgreSQL || target == keywords.DialectOracle {
						t.Fatalf("target supports FETCH WITH TIES: %v", err)
					}
					if got != "" {
						t.Fatalf("output on error: %q", got)
					}
					return
				}
				if target != keywords.DialectPostgreSQL && target != keywords.DialectOracle {
					t.Fatalf("target cannot express FETCH WITH TIES: got %q", got)
				}
				if !strings.Contains(got, "WITH TIES") {
					t.Fatalf("ties lost: %s", got)
				}
				tree, err := parser.ParseWithDialect(got, target)
				if err != nil {
					t.Fatalf("target SQL does not parse: %v", err)
				}
				defer ast.ReleaseAST(tree)
			})
		}
	}
}
