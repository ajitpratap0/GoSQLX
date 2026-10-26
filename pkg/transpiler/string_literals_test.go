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

package transpiler

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// stringValues parses sql in d and returns the decoded value of every string
// literal, in the order the reflective walk finds them.
func stringValues(t *testing.T, sql string, d keywords.SQLDialect) []string {
	t.Helper()
	tree, err := parser.ParseWithDialect(sql, d)
	if err != nil {
		t.Fatalf("parse %q as %s: %v", sql, d, err)
	}
	defer ast.ReleaseAST(tree)
	var out []string
	for _, stmt := range tree.Statements {
		forEachLiteral(reflect.ValueOf(stmt), make(map[seenPtr]bool), func(l *ast.LiteralValue) {
			if s, ok := l.Value.(string); ok && strings.EqualFold(l.Type, "string") {
				out = append(out, s)
			}
		})
	}
	return out
}

// TestTranspileStringLiteralsKeepValue checks that every string literal means
// the same in the target dialect as in the source: the output is re-parsed
// with the target's rules and its literal values compared with the source's.
// The literal used to be written with the source's escaping, so a PostgreSQL
// 'x\' closed early in MySQL and the rest of the statement became code.
func TestTranspileStringLiteralsKeepValue(t *testing.T) {
	pg, my, ora := keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectOracle
	tests := []struct {
		name     string
		from, to keywords.SQLDialect
		sql      string
		want     string // exact output, when pinned
	}{
		{
			name: "pg backslash before quote to mysql", from: pg, to: my,
			sql:  `SELECT * FROM t WHERE a = 'x\''' AND b = ' OR 1=1 -- '`,
			want: `SELECT * FROM t WHERE a = 'x\\''' AND b = ' OR 1=1 -- '`,
		},
		{name: "pg path to mysql", from: pg, to: my, sql: `SELECT 'C:\dir', 'x\.y' FROM t`, want: `SELECT 'C:\\dir', 'x\\.y' FROM t`},
		{name: "pg E-string to mysql", from: pg, to: my, sql: `SELECT E'a\nb\\c\'d'`, want: `SELECT 'a\nb\\c''d'`},
		{name: "pg regex in where to mysql", from: pg, to: my, sql: `SELECT a FROM t WHERE b LIKE '50\%' AND c = 'it''s'`},
		{name: "pg update to mysql", from: pg, to: my, sql: `UPDATE t SET a = 'C:\x' WHERE b IN ('p\q', 'r')`},
		{name: "pg insert to mysql", from: pg, to: my, sql: `INSERT INTO t (a) VALUES ('a\b'), ('c''d')`},

		{name: "mysql escapes to pg", from: my, to: pg, sql: `SELECT 'a\\b', 'it\'s', 'tab\there'`, want: "SELECT 'a\\b', 'it''s', 'tab\there'"},
		{name: "mysql newline to pg", from: my, to: pg, sql: `SELECT 'a\nb'`, want: "SELECT 'a\nb'"},
		{name: "mysql like escape to pg", from: my, to: pg, sql: `SELECT a FROM t WHERE b LIKE '50\%'`, want: `SELECT a FROM t WHERE b LIKE '50\%'`},
		{name: "mysql charset introducer to pg", from: my, to: pg, sql: `SELECT _utf8mb4'x\\y'`, want: `SELECT 'x\y'`},
		{name: "mysql charset introducer kept for mariadb", from: my, to: keywords.DialectMariaDB, sql: `SELECT _utf8mb4'x'`, want: `SELECT _utf8mb4'x'`},

		{name: "oracle q-quote to pg", from: ora, to: pg, sql: `SELECT q'[it's]' FROM dual`, want: `SELECT 'it''s' FROM dual`},
		{name: "oracle q-quote with backslash to pg", from: ora, to: pg, sql: `SELECT q'{a\b}' FROM dual`, want: `SELECT 'a\b' FROM dual`},
		{name: "oracle backslash to mysql", from: ora, to: my, sql: `SELECT 'a\b', q'[c\d]' FROM dual`, want: `SELECT 'a\\b', 'c\\d' FROM dual`},
		{name: "oracle q-quote kept for oracle", from: ora, to: ora, sql: `SELECT q'[it's]' FROM dual`, want: `SELECT q'[it's]' FROM dual`},
		{name: "pg E-string kept for pg", from: pg, to: pg, sql: `SELECT E'a\\b'`, want: `SELECT E'a\\b'`},

		{name: "pg to snowflake", from: pg, to: keywords.DialectSnowflake, sql: `SELECT 'x\.y'`, want: `SELECT 'x\\.y'`},
		{name: "snowflake to pg", from: keywords.DialectSnowflake, to: pg, sql: `SELECT 'x\.y', '\\d'`, want: `SELECT 'x.y', '\d'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Transpile(tt.sql, tt.from, tt.to)
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if tt.want != "" && out != tt.want {
				t.Errorf("Transpile(%q) =\n %q\nwant\n %q", tt.sql, out, tt.want)
			}
			src := stringValues(t, tt.sql, tt.from)
			dst := stringValues(t, out, tt.to)
			if !reflect.DeepEqual(src, dst) {
				t.Errorf("string values changed:\n source %q\n target %q\n output %q", src, dst, out)
			}
		})
	}
}

// TestTranspileStringLiteralsRefuseUnrepresentable checks that a control
// character the target cannot spell in a string literal is an error rather
// than being dropped or written with a different meaning.
func TestTranspileStringLiteralsRefuseUnrepresentable(t *testing.T) {
	tests := []struct {
		name     string
		from, to keywords.SQLDialect
		sql      string
	}{
		{"NUL into postgresql", keywords.DialectMySQL, keywords.DialectPostgreSQL, `SELECT 'a\0b'`},
		{"NUL into oracle", keywords.DialectMySQL, keywords.DialectOracle, `SELECT 'a\0b' FROM dual`},
		{"NUL into snowflake", keywords.DialectMySQL, keywords.DialectSnowflake, `SELECT 'a\0b'`},
		{"ctrl-z into clickhouse", keywords.DialectMySQL, keywords.DialectClickHouse, `SELECT 'a\Zb'`},
		{"ctrl-z into snowflake", keywords.DialectMySQL, keywords.DialectSnowflake, `SELECT 'a\Zb'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Transpile(tt.sql, tt.from, tt.to)
			if err == nil {
				t.Fatalf("Transpile(%q) = %q, want an error", tt.sql, out)
			}
		})
	}

	// MySQL reads \0 and \Z back, and ClickHouse reads \0.
	for _, c := range []struct {
		to   keywords.SQLDialect
		sql  string
		want string
	}{
		{keywords.DialectMariaDB, `SELECT 'a\0b\Z'`, `SELECT 'a\0b\Z'`},
		{keywords.DialectClickHouse, `SELECT 'a\0b'`, `SELECT 'a\0b'`},
	} {
		out, err := Transpile(c.sql, keywords.DialectMySQL, c.to)
		if err != nil || out != c.want {
			t.Errorf("Transpile(%q, mysql, %s) = %q, %v; want %q", c.sql, c.to, out, err, c.want)
		}
	}
}

// TestForEachLiteralReachesNestedLiterals checks the reflective walk finds
// literals in slices, nested expressions and subqueries.
func TestForEachLiteralReachesNestedLiterals(t *testing.T) {
	got := stringValues(t,
		`SELECT 'a', f('b') FROM t WHERE x IN (SELECT 'c' FROM u) AND y = CASE WHEN z THEN 'd' ELSE 'e' END`,
		keywords.DialectPostgreSQL)
	want := []string{"a", "b", "c", "d", "e"}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("literal %q not reached; got %q", w, got)
		}
	}
}
