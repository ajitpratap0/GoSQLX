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
	for _, suffix := range []string{"", " OFFSET 1"} {
		t.Run(suffix, func(t *testing.T) {
			got, err := transpiler.Transpile("SELECT a FROM t ORDER BY a LIMIT 2 WITH TIES"+suffix, keywords.DialectClickHouse, keywords.DialectSQLServer)
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
