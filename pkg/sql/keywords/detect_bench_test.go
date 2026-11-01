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

package keywords_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type detectCase struct {
	name string
	sql  string
	want keywords.SQLDialect
}

// detectCases are small hand-written inputs, one per detection route: no
// input, no hint (the full scan finds nothing), one clear hint per dialect, a
// quoting-style hint, and a statement carrying hints for two dialects.
var detectCases = []detectCase{
	{"empty", "", keywords.DialectGeneric},
	{"generic", "SELECT id, name FROM users WHERE id = 1 ORDER BY name", keywords.DialectGeneric},
	{"postgresql", "SELECT DISTINCT ON (dept) name::text FROM emp WHERE name ILIKE 'a%'", keywords.DialectPostgreSQL},
	{"mysql", "SELECT `id` FROM `users` FORCE INDEX (idx_id) WHERE id > 5", keywords.DialectMySQL},
	{"sqlserver", "SELECT TOP 10 [id] FROM [users] WITH (NOLOCK) WHERE d < GETDATE()", keywords.DialectSQLServer},
	{"oracle", "SELECT * FROM orders WHERE ROWNUM <= 10 AND created < SYSDATE", keywords.DialectOracle},
	{"snowflake", "SELECT * FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1 AND PARSE_JSON(x) IS NOT NULL", keywords.DialectSnowflake},
	{"mariadb", "SELECT NEXTVAL(seq_orders), LASTVAL(seq_orders)", keywords.DialectMariaDB},
	{"mixed", "SELECT TOP 5 id, NVL(x, 0), DECODE(y, 1, 'a', 'b') FROM t WHERE ROWNUM < 3", keywords.DialectOracle},
}

// largeDetectInput is a script of at least 64 KB built from real-world
// PostgreSQL statements: it is the worst case for a scan whose cost grows with
// input length and with the number of hints checked.
func largeDetectInput(tb testing.TB) string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("load benchmark corpus: %v", err)
	}
	stmts := set.RealWorld("postgresql")
	if len(stmts) == 0 {
		tb.Fatal("no postgresql real-world statements")
	}
	return benchcorpus.Script(stmts, benchcorpus.LargeMin).SQL
}

var detectSink keywords.SQLDialect

// BenchmarkDetectDialect measures keywords.DetectDialect on short inputs for
// each detection route plus one 64 KB script.
func BenchmarkDetectDialect(b *testing.B) {
	cases := append(append([]detectCase(nil), detectCases...), detectCase{name: "large_64KB", sql: largeDetectInput(b)})
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.sql)))
			for i := 0; i < b.N; i++ {
				detectSink = keywords.DetectDialect(c.sql)
			}
		})
	}
}

// TestDetectDialectBenchCases pins the answer each benchmark case produces, so
// the benchmark cannot drift onto a different code path unnoticed.
func TestDetectDialectBenchCases(t *testing.T) {
	for _, c := range detectCases {
		if got := keywords.DetectDialect(c.sql); got != c.want {
			t.Errorf("%s: DetectDialect = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestDetectDialectLargeInput checks the large case is large and is detected
// deterministically as a real dialect, not left on the no-hint fast path.
func TestDetectDialectLargeInput(t *testing.T) {
	sql := largeDetectInput(t)
	if len(sql) < benchcorpus.LargeMin {
		t.Fatalf("large input is %d B, want >= %d", len(sql), benchcorpus.LargeMin)
	}
	first := keywords.DetectDialect(sql)
	if first != keywords.DialectPostgreSQL {
		t.Errorf("DetectDialect(large postgresql script) = %q, want %q", first, keywords.DialectPostgreSQL)
	}
	if again := keywords.DetectDialect(sql); again != first {
		t.Errorf("DetectDialect is not deterministic: %q then %q", first, again)
	}
}
