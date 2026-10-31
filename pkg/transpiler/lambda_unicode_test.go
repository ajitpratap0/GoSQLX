// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var lambdaDialects = []keywords.SQLDialect{keywords.DialectClickHouse, keywords.DialectSnowflake}

// Lambda statements already in the formatter's canonical spelling.
var lambdaStatements = []string{
	"SELECT arrayMap(x -> x * 2, [1, 2, 3])",
	"SELECT arrayFilter(x -> x > 1 AND x < 5, arr) FROM t",
	"SELECT arrayFilter(x -> x > 1 OR x IS NULL, arr) FROM t",
	"SELECT arrayMap((x, y) -> x + y, a, b) FROM t",
	"SELECT arrayFold((acc, x) -> acc + x, [1, 2, 3], toUInt64(0))",
	"SELECT arrayExists(x -> x LIKE 'err%', tags) FROM t",
	"SELECT arrayFilter(x -> x IN (SELECT id FROM t), arr) FROM s",
	"SELECT arrayMap(x -> arrayMap(y -> y * x, [1, 2]), [1, 2])",
	"SELECT arraySort(x -> -x, arr) FROM t",
	"SELECT TRANSFORM(arr, a -> a * 2) FROM t",
	"SELECT REDUCE(arr, 0, (acc, val) -> acc + val) FROM t",
}

// Transpiling a lambda within and between ClickHouse and Snowflake must not
// change it: x -> x * 2 used to come out as (x -> x) * 2 (#897).
func TestTranspileLambdaUnchanged(t *testing.T) {
	for _, from := range lambdaDialects {
		for _, to := range lambdaDialects {
			for _, sql := range lambdaStatements {
				got, err := Transpile(sql, from, to)
				if err != nil || got != sql {
					t.Errorf("%s -> %s %q: got %q, %v", from, to, sql, got, err)
				}
			}
		}
	}
}

// noLambdaDialects read -> as JSON field access (PostgreSQL, MySQL, MariaDB,
// SQLite) or not at all (SQL Server, Oracle).
var noLambdaDialects = []keywords.SQLDialect{
	keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB,
	keywords.DialectSQLite, keywords.DialectSQLServer, keywords.DialectOracle,
}

// A lambda has no equivalent in a dialect without lambdas. Writing it as
// that dialect's -> would change its meaning (JSON extraction in MySQL) or
// its grouping (x -> x * 2 is (x -> x) * 2 in SQL Server and Oracle), so the
// transpile is refused (#897).
func TestTranspileLambdaRefusedWithoutLambdas(t *testing.T) {
	for _, from := range lambdaDialects {
		for _, to := range noLambdaDialects {
			for _, sql := range lambdaStatements {
				got, err := Transpile(sql, from, to)
				if err == nil || !strings.Contains(err.Error(), "the lambda operator -> has no equivalent in "+string(to)) {
					t.Errorf("%s -> %s %q: got %q, %v; want a lambda refusal", from, to, sql, got, err)
				}
			}
		}
	}
}

// JSON -> and ->> have no equivalent in ClickHouse or Snowflake, where ->
// is the lambda operator and ->> Snowflake's flow operator: emitting them
// unchanged would be re-read as a lambda (data -> ('a' = 'x')).
func TestTranspileJSONArrowRefusedForLambdaDialects(t *testing.T) {
	jsonDialects := []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLite}
	for _, from := range jsonDialects {
		for _, to := range lambdaDialects {
			for _, tc := range []struct{ sql, op string }{
				{"SELECT data -> 'a' = 'x' FROM t", "->"},
				{"SELECT data -> 'a' FROM t", "->"},
				{"SELECT data ->> 'a' FROM t", "->>"},
				{"SELECT id FROM t WHERE data ->> 'a' = 'x'", "->>"},
			} {
				got, err := Transpile(tc.sql, from, to)
				if err == nil || !strings.Contains(err.Error(), "the JSON operator "+tc.op+" has no equivalent in "+string(to)) {
					t.Errorf("%s -> %s %q: got %q, %v; want a JSON operator refusal", from, to, tc.sql, got, err)
				}
			}
		}
	}
	// ->> does not parse in ClickHouse or Snowflake, so a same-dialect
	// transpile fails at parse time instead of naming the source as a target.
	for _, d := range lambdaDialects {
		got, err := Transpile("SELECT a ->> 'b' FROM t", d, d)
		if err == nil || !strings.Contains(err.Error(), "the ->> operator is not supported in "+string(d)) {
			t.Errorf("%s -> %s ->>: got %q, %v; want a parse error", d, d, got, err)
		}
	}
	// Between the JSON dialects the arrow is unchanged.
	if got, err := Transpile("SELECT data -> 'a' FROM t", keywords.DialectPostgreSQL, keywords.DialectMySQL); err != nil || got != "SELECT data -> 'a' FROM t" {
		t.Errorf("postgresql -> mysql: got %q, %v", got, err)
	}
}

// Oracle, Snowflake and ClickHouse have no U& literals and no & operator:
// U&'...' is an error there instead of becoming BITAND(U, '...') (#898).
func TestTranspileUnicodeAmpersandRejected(t *testing.T) {
	for _, from := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectClickHouse} {
		for _, to := range prefilterDialects() {
			for _, sql := range []string{`SELECT U&'d\0061t'`, `SELECT u&'x' FROM t`, `SELECT U&"d\0061t" FROM t`, `SELECT U&'x' UESCAPE '!'`} {
				got, err := Transpile(sql, from, to)
				if err == nil || !strings.Contains(err.Error(), "U& Unicode escape literals in "+string(from)) {
					t.Errorf("%s -> %s %q: got %q, %v; want a U& error", from, to, sql, got, err)
				}
			}
		}
	}
}

// Where & exists, U&'x' is U & 'x' and keeps that meaning; PostgreSQL keeps
// its U& literal.
func TestTranspileUnicodeAmpersandElsewhere(t *testing.T) {
	for _, tc := range []struct {
		from, to keywords.SQLDialect
		sql      string
		want     string
	}{
		{keywords.DialectMySQL, keywords.DialectMySQL, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectMariaDB, keywords.DialectMariaDB, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectSQLServer, keywords.DialectSQLServer, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectSQLite, keywords.DialectSQLite, `SELECT U&'x'`, `SELECT U & 'x'`},
		{keywords.DialectMySQL, keywords.DialectOracle, `SELECT U&'x'`, `SELECT BITAND(U, 'x')`},
		{keywords.DialectMySQL, keywords.DialectClickHouse, `SELECT U&'x'`, `SELECT bitAnd(U, 'x')`},
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL, `SELECT U&'d\0061t'`, `SELECT U&'d\0061t'`},
		// Spaced, & stays an operator in the dialects without U& literals.
		{keywords.DialectOracle, keywords.DialectOracle, `SELECT U & 'x'`, `SELECT BITAND(U, 'x')`},
	} {
		got, err := Transpile(tc.sql, tc.from, tc.to)
		if err != nil || got != tc.want {
			t.Errorf("%s -> %s %q: got %q, %v; want %q", tc.from, tc.to, tc.sql, got, err, tc.want)
		}
	}
}
