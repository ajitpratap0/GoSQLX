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

// TestTranspile_DialectSpecificOperators checks that operators and literals
// whose meaning or existence depends on the dialect are rewritten for the
// target, or refused, and never emitted unchanged where they mean something
// else: ^ is exponentiation in PostgreSQL and bitwise XOR (at different
// precedence levels) in MySQL, MariaDB and SQL Server.
func TestTranspile_DialectSpecificOperators(t *testing.T) {
	const (
		pg    = keywords.DialectPostgreSQL
		my    = keywords.DialectMySQL
		maria = keywords.DialectMariaDB
		ms    = keywords.DialectSQLServer
		ora   = keywords.DialectOracle
		lite  = keywords.DialectSQLite
		snow  = keywords.DialectSnowflake
		ch    = keywords.DialectClickHouse
	)
	tests := []struct {
		name     string
		from, to keywords.SQLDialect
		sql      string
		want     string // "" when Transpile must fail
		errHas   string // substring of the error when want is ""
	}{
		// ^ as exponentiation.
		{"power kept", pg, pg, "SELECT 2 ^ 3", "SELECT 2 ^ 3", ""},
		{"power to mysql", pg, my, "SELECT 2 ^ 3", "SELECT POWER(2, 3)", ""},
		{"power to sqlserver", pg, ms, "SELECT 2 * a ^ 2 FROM t", "SELECT 2 * POWER(a, 2) FROM t", ""},
		{"power to oracle", pg, ora, "SELECT a ^ b FROM t", "SELECT POWER(a, b) FROM t", ""},
		{"nested power", pg, my, "SELECT 2 ^ 3 ^ 2", "SELECT POWER(POWER(2, 3), 2)", ""},
		// ^ as bitwise XOR.
		{"xor kept", my, my, "SELECT a ^ b FROM t", "SELECT a ^ b FROM t", ""},
		{"xor mysql to mariadb", my, maria, "SELECT a + b ^ c FROM t", "SELECT a + b ^ c FROM t", ""},
		{"xor to postgresql", my, pg, "SELECT a ^ b FROM t", "SELECT a # b FROM t", ""},
		{"xor to postgresql keeps grouping", my, pg, "SELECT a + b ^ c FROM t", "SELECT a + (b # c) FROM t", ""},
		{"xor mysql to sqlserver keeps grouping", my, ms, "SELECT a + b ^ c FROM t", "SELECT a + (b ^ c) FROM t", ""},
		{"xor sqlserver to mysql keeps grouping", ms, my, "SELECT a + b ^ c FROM t", "SELECT (a + b) ^ c FROM t", ""},
		{"xor to snowflake", my, snow, "SELECT a ^ b FROM t", "SELECT BITXOR(a, b) FROM t", ""},
		{"xor to clickhouse", ms, ch, "SELECT a ^ b FROM t", "SELECT bitXor(a, b) FROM t", ""},
		{"xor to oracle", my, ora, "SELECT a ^ b FROM t", "", "XOR"},
		{"xor to sqlite", ms, lite, "SELECT a ^ b FROM t", "", "XOR"},
		// PostgreSQL prefix and postfix operators.
		{"abs", pg, my, "SELECT @ -5", "SELECT ABS(-5)", ""},
		{"square root", pg, ms, "SELECT |/ a + 1 FROM t", "SELECT SQRT(a + 1) FROM t", ""},
		{"cube root to snowflake", pg, snow, "SELECT ||/ 27", "SELECT CBRT(27)", ""},
		{"cube root to mysql", pg, my, "SELECT ||/ 27", "", "||/"},
		{"prefix factorial", pg, my, "SELECT !! 5", "", "!!"},
		{"prefix operators kept", pg, pg, "SELECT |/ 25, @ -5", "SELECT |/25, @ -5", ""},
		// SQL Server money literals.
		{"money with fraction", ms, pg, "SELECT $5.00", "", "money"},
		{"money without fraction", ms, my, "SELECT $5 + 1", "", "money"},
		{"money kept", ms, ms, "SELECT $5.00", "SELECT $5.00", ""},
		// Snowflake object constants.
		{"object constant", snow, pg, "SELECT {'a': 1}", "", "object constant"},
		{"object constant kept", snow, snow, "SELECT {'a': 1}", "SELECT {'a': 1}", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transpiler.Transpile(tc.sql, tc.from, tc.to)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Transpile = %q, want an error", got)
				}
				if !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("error = %v, want it to mention %q", err, tc.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
			tree, err := parser.ParseWithDialect(got, tc.to)
			if err != nil {
				t.Fatalf("output %q does not parse in %s: %v", got, tc.to, err)
			}
			ast.ReleaseAST(tree)
		})
	}
}
