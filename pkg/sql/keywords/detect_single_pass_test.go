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

package keywords

import (
	"math/rand"
	"strings"
	"sync"
	"testing"
)

var frozenHints = []dialectHint{
	// Snowflake-specific (high confidence)
	{pattern: "QUALIFY", dialect: DialectSnowflake, weight: 3},
	{pattern: "FLATTEN", dialect: DialectSnowflake, weight: 5},
	{pattern: "VARIANT", dialect: DialectSnowflake, weight: 5},
	{pattern: "WAREHOUSE", dialect: DialectSnowflake, weight: 5},
	{pattern: "CLONE", dialect: DialectSnowflake, weight: 4},
	{pattern: "UNDROP", dialect: DialectSnowflake, weight: 5},
	{pattern: "RESULT_SCAN", dialect: DialectSnowflake, weight: 5},
	{pattern: "IFF", dialect: DialectSnowflake, weight: 4},
	{pattern: "STREAM", dialect: DialectSnowflake, weight: 3},
	{pattern: "TASK", dialect: DialectSnowflake, weight: 2},
	{pattern: "PIPE", dialect: DialectSnowflake, weight: 2},
	{pattern: "STAGE", dialect: DialectSnowflake, weight: 2},
	{pattern: "FILE_FORMAT", dialect: DialectSnowflake, weight: 5},
	{pattern: "PARSE_JSON", dialect: DialectSnowflake, weight: 5},
	{pattern: "TRY_CAST", dialect: DialectSnowflake, weight: 3},
	{pattern: "ZEROIFNULL", dialect: DialectSnowflake, weight: 5},
	{pattern: "RECLUSTER", dialect: DialectSnowflake, weight: 5},
	{pattern: "LAST_QUERY_ID", dialect: DialectSnowflake, weight: 5},
	{pattern: "GENERATOR", dialect: DialectSnowflake, weight: 3},

	// PostgreSQL-specific (high confidence)
	{pattern: "ILIKE", dialect: DialectPostgreSQL, weight: 5},
	{pattern: "RETURNING", dialect: DialectPostgreSQL, weight: 3},
	{pattern: "DISTINCT ON", dialect: DialectPostgreSQL, weight: 5},
	{pattern: "MATERIALIZED", dialect: DialectPostgreSQL, weight: 3},
	{pattern: "REINDEX", dialect: DialectPostgreSQL, weight: 5},

	// MySQL-specific (high confidence)
	{pattern: "ZEROFILL", dialect: DialectMySQL, weight: 5},
	{pattern: "UNSIGNED", dialect: DialectMySQL, weight: 4},
	{pattern: "AUTO_INCREMENT", dialect: DialectMySQL, weight: 5},
	{pattern: "FORCE INDEX", dialect: DialectMySQL, weight: 5},

	// SQL Server-specific (high confidence)
	{pattern: "NOLOCK", dialect: DialectSQLServer, weight: 5},
	{pattern: "TOP", dialect: DialectSQLServer, weight: 3},
	{pattern: "NVARCHAR", dialect: DialectSQLServer, weight: 4},
	{pattern: "GETDATE", dialect: DialectSQLServer, weight: 5},

	// Oracle-specific (high confidence)
	{pattern: "ROWNUM", dialect: DialectOracle, weight: 5},
	{pattern: "CONNECT BY", dialect: DialectOracle, weight: 3},
	{pattern: "SYSDATE", dialect: DialectOracle, weight: 5},
	{pattern: "DECODE", dialect: DialectOracle, weight: 3},

	// MariaDB-specific (high confidence — these features don't appear in MySQL or Oracle)
	{pattern: "NEXTVAL", dialect: DialectMariaDB, weight: 5},
	{pattern: "LASTVAL", dialect: DialectMariaDB, weight: 5},
	{pattern: "SETVAL", dialect: DialectMariaDB, weight: 5},
	{pattern: "NEXT VALUE FOR", dialect: DialectMariaDB, weight: 5},
	{pattern: "SYSTEM VERSIONING", dialect: DialectMariaDB, weight: 5},
	{pattern: "FOR SYSTEM_TIME", dialect: DialectMariaDB, weight: 5},
	{pattern: "VERSIONING", dialect: DialectMariaDB, weight: 4},
	{pattern: "CONNECT BY", dialect: DialectMariaDB, weight: 2},
	{pattern: "CREATE SEQUENCE", dialect: DialectMariaDB, weight: 5},
	{pattern: "DROP SEQUENCE", dialect: DialectMariaDB, weight: 5},

	// SQLite-specific (high confidence)
	{pattern: "AUTOINCREMENT", dialect: DialectSQLite, weight: 5},
	{pattern: "GLOB", dialect: DialectSQLite, weight: 4},
	{pattern: "VACUUM", dialect: DialectSQLite, weight: 4},
}

var frozenPriority = [7]SQLDialect{DialectOracle, DialectSnowflake, DialectPostgreSQL, DialectMySQL, DialectSQLServer, DialectMariaDB, DialectSQLite}

func referenceScores(sql string) (scores [7]int) {
	upper := strings.ToUpper(sql)
	add := func(d SQLDialect, n int) {
		for i, v := range frozenPriority {
			if v == d {
				scores[i] += n
				return
			}
		}
	}
	for _, h := range frozenHints {
		if containsWord(upper, h.pattern) {
			add(h.dialect, h.weight)
		}
	}
	if strings.Contains(sql, "`") {
		add(DialectMySQL, 3)
	}
	if strings.Contains(sql, "[") && strings.Contains(sql, "]") {
		add(DialectSQLServer, 3)
	}
	if strings.Contains(sql, "::") {
		add(DialectPostgreSQL, 3)
	}
	if containsWord(upper, "NVL") {
		add(DialectOracle, 1)
		add(DialectSnowflake, 1)
	}
	return
}

// containsWord checks if the uppercase SQL string contains the given pattern
// as a whole word (not as a substring of another word). The pattern is expected
// to already be uppercase.
//
// A word boundary is defined as either:
//   - The start or end of the string
//   - A non-alphanumeric, non-underscore character
func containsWord(upper string, pattern string) bool {
	idx := 0
	patLen := len(pattern)
	for {
		pos := strings.Index(upper[idx:], pattern)
		if pos == -1 {
			return false
		}
		absPos := idx + pos

		// Check word boundary before the pattern
		beforeOK := absPos == 0 || !isWordChar(upper[absPos-1])

		// Check word boundary after the pattern
		endPos := absPos + patLen
		afterOK := endPos >= len(upper) || !isWordChar(upper[endPos])

		if beforeOK && afterOK {
			return true
		}

		// Move past this occurrence and continue searching
		idx = absPos + 1
		if idx >= len(upper) {
			return false
		}
	}
}

var dialectCorpus = []string{"", "SELECT 1", "NVL", "TOP `", "TOP ` NVL", "CONNECT BY", "SYSTEM VERSIONING", "FOR SYSTEM_TIME", "NEXT VALUE FOR", "NEXT\tVALUE FOR", "connect\nby", "ılike", "ſysdate", "xılike", "ß ILIKE K", "\xffILIKE\xff", "[ ]", "] [", "-- ILIKE", "'SYSDATE'", "ILIKE_ ILIKE0 xILIKE", "ILIKE ILIKE"}

func checkScores(t *testing.T, s string) {
	t.Helper()
	got, want := dialectScores(s), referenceScores(s)
	if got != want {
		t.Errorf("scores %q: got %v want %v", s, got, want)
	}
}
func TestDetectDialectConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if got := DetectDialect("SELECT NEXTVAL(seq_orders)"); got != DialectMariaDB {
					t.Errorf("DetectDialect: got %s, want %s", got, DialectMariaDB)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDetectorHintBitsetCapacity(t *testing.T) {
	detectorOnce.Do(buildDetector)
	if got := len(dialectHints) + 2; got > 64 {
		t.Fatalf("dialect hints including NVL: %d exceed 64-bit capacity", got)
	}
	if got, want := len(detectorHints), len(dialectHints)+2; got != want {
		t.Fatalf("detector hints: got %d, want %d", got, want)
	}
}

func TestSinglePassDifferential(t *testing.T) {
	for _, h := range frozenHints {
		checkScores(t, h.pattern)
		checkScores(t, "!"+h.pattern+"! "+h.pattern)
	}
	for _, s := range dialectCorpus {
		checkScores(t, s)
	}
	r := rand.New(rand.NewSource(709))
	alphabet := []byte("abcXYZ09_ ![]:`\xff\xc4\xb1\xc5\xbf")
	for i := 0; i < 3000; i++ {
		b := make([]byte, r.Intn(100))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		checkScores(t, string(b))
		h := frozenHints[r.Intn(len(frozenHints))].pattern
		checkScores(t, string(b)+h+string(b))
	}
}
func TestSinglePassBehavior(t *testing.T) {
	cases := []struct {
		input string
		want  SQLDialect
	}{
		{"ılike", DialectPostgreSQL}, {"ſysdate", DialectOracle}, {"xılike", DialectGeneric},
		{"ß", DialectGeneric}, {"K", DialectGeneric}, {"\xffILIKE\xff", DialectPostgreSQL},
		{"ILIKE", DialectPostgreSQL}, {"x ILIKE", DialectPostgreSQL}, {"ILIKE_", DialectGeneric},
		{"ILIKE0", DialectGeneric}, {"NEXT VALUE FOR", DialectMariaDB}, {"NEXT\tVALUE FOR", DialectGeneric},
		{"CONNECT BY", DialectOracle}, {"CONNECT\nBY", DialectGeneric}, {"SYSTEM VERSIONING", DialectMariaDB},
		{"FOR SYSTEM_TIME", DialectMariaDB}, {"[ ]", DialectSQLServer}, {"] [", DialectSQLServer},
		{"-- ILIKE", DialectPostgreSQL}, {"'SYSDATE'", DialectOracle},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := DetectDialect(tc.input); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestDeterministicPriority(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want SQLDialect
	}{{"NVL", DialectOracle}, {"TOP `", DialectMySQL}, {"", DialectGeneric}, {"SYSDATE FLATTEN ILIKE ZEROFILL NOLOCK NEXTVAL AUTOINCREMENT", DialectOracle}, {"FLATTEN", DialectSnowflake}} {
		for i := 0; i < 1000; i++ {
			if got := DetectDialect(tc.s); got != tc.want {
				t.Fatalf("%q got %v want %v", tc.s, got, tc.want)
			}
		}
	}
}
func TestDetectZeroAllocs(t *testing.T) {
	for _, s := range []string{"SELECT 1", "TOP ` NVL", "ılike ſysdate", strings.Repeat("SELECT words ", 6000)} {
		if n := testing.AllocsPerRun(100, func() { DetectDialect(s) }); n != 0 {
			t.Errorf("allocations %v", n)
		}
	}
}
func FuzzDetectDialect(f *testing.F) {
	for _, s := range dialectCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkScores(t, s) })
}
