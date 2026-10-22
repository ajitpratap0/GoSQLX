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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestOperatorsC1_RenderRoundTrip formats the operator and predicate
// constructs through every renderer: each output must re-parse to the same
// statement and keep the operator words (nothing is dropped or reworded).
func TestOperatorsC1_RenderRoundTrip(t *testing.T) {
	tests := []struct {
		d    keywords.SQLDialect
		in   string
		want string // must appear in the compact rendering
	}{
		{keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE id = ANY($1)", "id = ANY ($1)"},
		{keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE id <> ALL(ARRAY[1, 2])", "id <> ALL (ARRAY[1, 2])"},
		{keywords.DialectPostgreSQL, "SELECT 1 FROM t WHERE 'x' = SOME(tags)", "'x' = SOME (tags)"},
		{keywords.DialectPostgreSQL, "SELECT u.id FROM u WHERE u.id IS DISTINCT FROM 5", "u.id IS DISTINCT FROM 5"},
		{keywords.DialectSnowflake, "SELECT u.id FROM u WHERE u.id IS NOT DISTINCT FROM 5", "u.id IS NOT DISTINCT FROM 5"},
		{keywords.DialectPostgreSQL, "SELECT x IS NOT FALSE, y IS UNKNOWN FROM t", "x IS NOT FALSE, y IS UNKNOWN"},
		{keywords.DialectSQLite, "SELECT * FROM t WHERE a IS NOT b", "a IS NOT b"},
		{keywords.DialectPostgreSQL, "SELECT created_at AT TIME ZONE 'UTC' FROM t", "created_at AT TIME ZONE 'UTC'"},
		{keywords.DialectPostgreSQL, `SELECT col COLLATE "C" FROM t ORDER BY name COLLATE "en_US"`, `col COLLATE "C"`},
		{keywords.DialectMySQL, "SELECT x FROM t WHERE x COLLATE utf8mb4_bin = 'a'", "x COLLATE utf8mb4_bin = 'a'"},
		{keywords.DialectPostgreSQL, `SELECT a COLLATE "en_US.utf8", b COLLATE pg_catalog."C" FROM t`, `a COLLATE "en_US.utf8", b COLLATE pg_catalog."C"`},
		{keywords.DialectPostgreSQL, `CREATE INDEX i ON t (a COLLATE "C" DESC)`, `(a COLLATE "C" DESC)`},
		{keywords.DialectPostgreSQL, "SELECT x FROM t WHERE tsv @@ to_tsquery('a') AND a && b", "tsv @@ to_tsquery('a') AND a && b"},
		{keywords.DialectSQLServer, "SELECT a & b, ~c FROM t", "a & b, ~c"},
		{keywords.DialectMySQL, "SELECT a DIV 3, b MOD 2 FROM t WHERE x NOT REGEXP 'a' AND y SOUNDS LIKE z", "a DIV 3, b MOD 2"},
		{keywords.DialectMySQL, "SELECT * FROM t WHERE a <=> NULL", "a <=> NULL"},
		{keywords.DialectSQLite, "SELECT * FROM t WHERE p GLOB '*.txt' AND a MATCH 'foo' AND b == 1", "p GLOB '*.txt' AND a MATCH 'foo' AND b == 1"},
		{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE n SIMILAR TO 'x%' AND m NOT SIMILAR TO 'y%'", "n SIMILAR TO 'x%' AND m NOT SIMILAR TO 'y%'"},
		{keywords.DialectOracle, "SELECT a FROM t WHERE a LIKE 'x' ESCAPE 'y'", "a LIKE 'x' ESCAPE 'y'"},
		{keywords.DialectSQLite, "SELECT a IN (1, 2) = 1 FROM t WHERE a NOT IN () AND b IN u", "a IN (1, 2) = 1"},
		{keywords.DialectClickHouse, "SELECT a FROM t WHERE a GLOBAL IN (SELECT 1) AND b GLOBAL NOT IN (SELECT 2)", "a GLOBAL IN (SELECT 1) AND b GLOBAL NOT IN (SELECT 2)"},
		{keywords.DialectClickHouse, "SELECT a ? 1 : 2", "a ? 1 : 2"},
		{keywords.DialectPostgreSQL, "SELECT x::int[], CAST(a AS text[]), x::double precision FROM t", "CAST(x AS int[]), CAST(a AS text[]), CAST(x AS double precision)"},
		{keywords.DialectMySQL, "SELECT CAST(x AS SIGNED INTEGER), CAST(y AS CHAR CHARACTER SET utf8mb4) FROM t", "CAST(x AS SIGNED INTEGER), CAST(y AS CHAR CHARACTER SET utf8mb4)"},
	}
	for _, tc := range tests {
		t.Run(string(tc.d)+"/"+tc.in, func(t *testing.T) {
			rs := assertRoundTrip(t, tc.d, tc.in)
			for _, name := range []string{"SQL", "FmtCompact"} {
				if !strings.Contains(rs[name], tc.want) {
					t.Errorf("%s = %q, want it to contain %q", name, rs[name], tc.want)
				}
			}
		})
	}
}

// TestOperatorsC1_LogicalOperatorsUpperCase pins that the formatter writes
// AND and OR in upper case whatever their source spelling (the CLI used to
// leave them as typed).
func TestOperatorsC1_LogicalOperatorsUpperCase(t *testing.T) {
	rs := assertRoundTrip(t, keywords.DialectGeneric, "select a from t where a=1 and b=2 or c=3")
	for name, out := range rs {
		if strings.Contains(out, " and ") || strings.Contains(out, " or ") {
			t.Errorf("%s = %q, want AND / OR in upper case", name, out)
		}
		if !strings.Contains(out, " AND ") || !strings.Contains(out, " OR ") {
			t.Errorf("%s = %q, want it to contain AND and OR", name, out)
		}
	}
}
