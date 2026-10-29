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

func TestTranspileNestedRowLimitsTargetDialect(t *testing.T) {
	tests := []struct {
		name, sql string
		from, to  keywords.SQLDialect
		want      string
	}{
		{"derived oracle", "SELECT * FROM (SELECT a FROM t ORDER BY a LIMIT 3) s", keywords.DialectPostgreSQL, keywords.DialectOracle, "FETCH FIRST 3 ROWS ONLY"},
		{"join oracle", "SELECT * FROM t JOIN (SELECT a FROM u ORDER BY a LIMIT 3) s ON t.a = s.a", keywords.DialectPostgreSQL, keywords.DialectOracle, "FETCH FIRST 3 ROWS ONLY"},
		{"scalar oracle", "SELECT (SELECT a FROM t ORDER BY a LIMIT 3) AS a", keywords.DialectPostgreSQL, keywords.DialectOracle, "FETCH FIRST 3 ROWS ONLY"},
		{"scalar expression oracle", "SELECT 1 + (SELECT a FROM t ORDER BY a LIMIT 3) AS a", keywords.DialectPostgreSQL, keywords.DialectOracle, "FETCH FIRST 3 ROWS ONLY"},
		{"nested top oracle", "SELECT * FROM (SELECT TOP 3 a FROM t) s", keywords.DialectSQLServer, keywords.DialectOracle, "FETCH FIRST 3 ROWS ONLY"},
		{"derived set oracle", "SELECT * FROM (SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5) x", keywords.DialectPostgreSQL, keywords.DialectOracle, "FETCH FIRST 5 ROWS ONLY"},
		{"derived sqlserver", "SELECT * FROM (SELECT a FROM t LIMIT 3) s", keywords.DialectPostgreSQL, keywords.DialectSQLServer, "SELECT TOP 3 a FROM t"},
		{"join sqlserver", "SELECT * FROM t JOIN (SELECT a FROM u LIMIT 3) s ON t.a = s.a", keywords.DialectPostgreSQL, keywords.DialectSQLServer, "SELECT TOP 3 a FROM u"},
		{"scalar sqlserver", "SELECT (SELECT a FROM t LIMIT 3) AS a", keywords.DialectPostgreSQL, keywords.DialectSQLServer, "SELECT TOP 3 a FROM t"},
		{"derived offset sqlserver", "SELECT * FROM (SELECT a FROM t ORDER BY a LIMIT 3 OFFSET 1) s", keywords.DialectPostgreSQL, keywords.DialectSQLServer, "ORDER BY a OFFSET 1 ROWS FETCH NEXT 3 ROWS ONLY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transpiler.Transpile(tt.sql, tt.from, tt.to)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(got, tt.want) || strings.Contains(got, "LIMIT") {
				t.Fatalf("target row limit missing: got %q; want %q", got, tt.want)
			}
			tree, err := parser.ParseWithDialect(got, tt.to)
			if err != nil {
				t.Fatalf("target SQL %q does not parse: %v", got, err)
			}
			defer ast.ReleaseAST(tree)
		})
	}
}
