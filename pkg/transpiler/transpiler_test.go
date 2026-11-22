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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspile_SameDialect_ReturnsEquivalent(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestTranspile_InvalidSQL_ReturnsError(t *testing.T) {
	_, err := transpiler.Transpile("NOT VALID SQL !!!", keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestTranspile_UnsupportedDialectPair_Passthrough(t *testing.T) {
	// Should either work (passthrough) or return a descriptive error — not panic.
	_, err := transpiler.Transpile("SELECT 1", keywords.DialectOracle, keywords.DialectClickHouse)
	_ = err // either outcome is acceptable as long as there is no panic
}

func TestTranspile_MySQLToPostgres_BasicSelect(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func BenchmarkTranspile(b *testing.B) {
	sql := "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY, flag TINYINT(1))"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTranspile_WideExpression(b *testing.B) {
	for _, op := range []string{"OR", "AND", "||"} {
		b.Run(op, func(b *testing.B) {
			sql := "SELECT a FROM t WHERE a" + strings.Repeat(" "+op+" a", 200)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := transpiler.Transpile(sql, keywords.DialectPostgreSQL, keywords.DialectMySQL); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTranspile_SetOpLimit(b *testing.B) {
	const sql = "SELECT a FROM t UNION SELECT b FROM u ORDER BY 1 LIMIT 5"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := transpiler.Transpile(sql, keywords.DialectPostgreSQL, keywords.DialectSQLServer); err != nil {
			b.Fatal(err)
		}
	}
}

// TestTranspile_SetOperationsForTarget checks that set operations are
// written for the target dialect: MINUS becomes EXCEPT where the target has
// no MINUS, and an Oracle chain (all operators of equal precedence, grouped
// left to right) keeps its grouping under standard precedence.
func TestTranspile_SetOperationsForTarget(t *testing.T) {
	tests := []struct {
		from, to keywords.SQLDialect
		sql      string
		want     string
	}{
		{keywords.DialectSnowflake, keywords.DialectPostgreSQL,
			"SELECT a FROM t MINUS SELECT a FROM u",
			"SELECT a FROM t EXCEPT SELECT a FROM u"},
		{keywords.DialectOracle, keywords.DialectMySQL,
			"SELECT a FROM t MINUS SELECT a FROM u",
			"SELECT a FROM t EXCEPT SELECT a FROM u"},
		{keywords.DialectOracle, keywords.DialectSnowflake,
			"SELECT a FROM t MINUS SELECT a FROM u",
			"SELECT a FROM t MINUS SELECT a FROM u"},
		{keywords.DialectOracle, keywords.DialectPostgreSQL,
			"SELECT 1 FROM dual UNION SELECT 2 FROM dual INTERSECT SELECT 3 FROM dual",
			"(SELECT 1 FROM dual UNION SELECT 2 FROM dual) INTERSECT SELECT 3 FROM dual"},
	}
	for _, tc := range tests {
		t.Run(string(tc.from)+"_to_"+string(tc.to), func(t *testing.T) {
			got, err := transpiler.Transpile(tc.sql, tc.from, tc.to)
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

// TestTranspile_NestedParenthesizedWith checks that a WITH clause written
// before nested parenthesized set operands stays in front of the whole
// operation in every target.
func TestTranspile_NestedParenthesizedWith(t *testing.T) {
	const with = "WITH c AS (SELECT a FROM t) "
	const body = "((SELECT a FROM c UNION SELECT a FROM c) INTERSECT SELECT a FROM c) EXCEPT SELECT a FROM c"
	pairs := [][2]keywords.SQLDialect{
		{keywords.DialectPostgreSQL, keywords.DialectPostgreSQL},
		{keywords.DialectPostgreSQL, keywords.DialectOracle},
		{keywords.DialectPostgreSQL, keywords.DialectSQLite},
		{keywords.DialectOracle, keywords.DialectPostgreSQL},
		{keywords.DialectSQLite, keywords.DialectPostgreSQL},
	}
	for _, pr := range pairs {
		t.Run(string(pr[0])+"_to_"+string(pr[1]), func(t *testing.T) {
			got, err := transpiler.Transpile(with+body, pr[0], pr[1])
			if err != nil {
				t.Fatalf("Transpile: %v", err)
			}
			if !strings.HasPrefix(got, with) {
				t.Errorf("WITH clause is not in front of the set operation: %s", got)
			}
		})
	}
}

func BenchmarkTranspile_SelectOps(b *testing.B) {
	const sql = "SELECT u.id, u.name || 'x', COUNT(*) AS c, a ^ b, CASE WHEN u.age > 18 AND u.flag = 1 THEN 'adult' ELSE 'minor' END FROM users u JOIN orders o ON o.uid = u.id AND o.total > 10 WHERE u.status IN ('a','b') OR (u.score * 2 + 1) >= 5 GROUP BY u.id, u.name HAVING COUNT(*) > 1 ORDER BY c DESC LIMIT 10"
	for _, p := range []struct {
		name     string
		from, to keywords.SQLDialect
	}{
		{"mysql2pg", keywords.DialectMySQL, keywords.DialectPostgreSQL},
		{"pg2mysql", keywords.DialectPostgreSQL, keywords.DialectMySQL},
	} {
		b.Run(p.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := transpiler.Transpile(sql, p.from, p.to); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A large tree must not leave stale seen pointers or AST references in scratch
// retained for the next, small call.
func TestTranspileDeepChainFollowedBySmall(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("near-ceiling chain skipped under -short and -race")
	}
	checkDeepChain(t, "OR", 490000, keywords.DialectPostgreSQL, keywords.DialectMySQL)
	got, err := transpiler.Transpile("SELECT a || b FROM t", keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("small transpile after large tree: %v", err)
	}
	if want := "SELECT CONCAT(a, b) FROM t"; got != want {
		t.Fatalf("small transpile after large tree = %q, want %q", got, want)
	}
}
