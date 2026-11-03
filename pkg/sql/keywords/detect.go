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
	"math/bits"
	"strings"
	"unicode"
	"unicode/utf8"
)

// dialectHint represents a keyword or pattern that suggests a specific SQL dialect,
// along with a weight indicating how strongly it suggests that dialect.
type dialectHint struct {
	pattern string
	dialect SQLDialect
	weight  int
}

// dialectHints contains patterns used for dialect detection.
// Each hint has a weight indicating how strongly it suggests a specific dialect.
// Higher weights indicate more dialect-specific patterns.
//
// Patterns are matched case-insensitively against the SQL text using word boundary
// awareness (preceded and followed by non-alphanumeric characters or string boundaries).
var dialectHints = []dialectHint{
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

// DetectDialect attempts to identify the SQL dialect from SQL text.
// It analyzes the SQL string for dialect-specific keywords and patterns,
// returning the most likely dialect based on weighted keyword analysis.
//
// The detection uses a scoring system where each dialect-specific keyword
// contributes a weight to its dialect's score. The dialect with the highest
// total score wins. Each hint contributes at most once. Ties are resolved in
// the order Oracle, Snowflake, PostgreSQL, MySQL, SQL Server, MariaDB, SQLite.
// If no dialect-specific patterns are found, DialectGeneric
// is returned.
//
// Detection heuristics include:
//   - Snowflake: QUALIFY, FLATTEN, VARIANT, WAREHOUSE, CLONE, UNDROP, RESULT_SCAN, IFF
//   - PostgreSQL: ILIKE, RETURNING, DISTINCT ON, MATERIALIZED
//   - MySQL: ZEROFILL, UNSIGNED, AUTO_INCREMENT, FORCE INDEX
//   - SQL Server: NOLOCK, TOP, NVARCHAR, GETDATE
//   - Oracle: ROWNUM, CONNECT BY, SYSDATE, DECODE
//   - MariaDB: NEXTVAL, LASTVAL, SETVAL, NEXT VALUE FOR, SYSTEM VERSIONING, FOR SYSTEM_TIME, VERSIONING, CONNECT BY, CREATE SEQUENCE, DROP SEQUENCE
//   - SQLite: AUTOINCREMENT, GLOB, VACUUM
//
// The function also performs syntactic checks for identifier quoting styles:
//   - Backtick identifiers (`) suggest MySQL
//   - Square bracket identifiers ([]) suggest SQL Server
//   - Double-colon type casting (::) suggests PostgreSQL
//
// Example:
//
//	dialect := keywords.DetectDialect("SELECT * FROM users QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1")
//	// dialect == DialectSnowflake
//
//	dialect = keywords.DetectDialect("SELECT DISTINCT ON (dept) * FROM emp")
//	// dialect == DialectPostgreSQL
//
//	dialect = keywords.DetectDialect("SELECT NEXTVAL(seq_orders)")
//	// dialect == DialectMariaDB
//
//	dialect = keywords.DetectDialect("SELECT * FROM users")
//	// dialect == DialectGeneric
var dialectPriority = [7]SQLDialect{DialectOracle, DialectSnowflake, DialectPostgreSQL, DialectMySQL, DialectSQLServer, DialectMariaDB, DialectSQLite}

// The automaton is built once from the hint table; each output bit identifies
// one weighted hint, including duplicate patterns with different dialects.
type matcherNode struct {
	next    [128]int
	fail    int
	outputs uint64
}
type matcherHint struct {
	length  int
	dialect int
	weight  int
}

var detectorNodes []matcherNode
var detectorHints []matcherHint

func init() {
	detectorNodes = append(detectorNodes, matcherNode{})
	add := func(pattern string, dialect, weight int) {
		id := len(detectorHints)
		detectorHints = append(detectorHints, matcherHint{len(pattern), dialect, weight})
		node := 0
		for i := 0; i < len(pattern); i++ {
			c := pattern[i]
			next := detectorNodes[node].next[c]
			if next == 0 {
				next = len(detectorNodes)
				detectorNodes = append(detectorNodes, matcherNode{})
				detectorNodes[node].next[c] = next
			}
			node = next
		}
		detectorNodes[node].outputs |= uint64(1) << id
	}
	for _, h := range dialectHints {
		for i, d := range dialectPriority {
			if h.dialect == d {
				add(h.pattern, i, h.weight)
				break
			}
		}
	}
	add("NVL", 0, 1)
	add("NVL", 1, 1)
	queue := make([]int, 0, len(detectorNodes))
	for c := 0; c < 128; c++ {
		if n := detectorNodes[0].next[c]; n != 0 {
			queue = append(queue, n)
		}
	}
	for head := 0; head < len(queue); head++ {
		n := queue[head]
		fail := detectorNodes[n].fail
		detectorNodes[n].outputs |= detectorNodes[fail].outputs
		for c := 0; c < 128; c++ {
			child := detectorNodes[n].next[c]
			if child != 0 {
				detectorNodes[child].fail = detectorNodes[fail].next[c]
				queue = append(queue, child)
			} else {
				detectorNodes[n].next[c] = detectorNodes[fail].next[c]
			}
		}
	}
}

func DetectDialect(sql string) SQLDialect {
	if sql == "" {
		return DialectGeneric
	}
	scores := dialectScores(sql)
	best := 0
	result := DialectGeneric
	for i, score := range scores {
		if score > best {
			best = score
			result = dialectPriority[i]
		}
	}
	return result
}

// dialectScores streams uppercase characters through the matcher. Non-ASCII
// uppercase runes cannot occur in an ASCII hint and all their UTF-8 bytes are
// non-word bytes, so one sentinel preserves both matching and byte boundaries.
func dialectScores(sql string) (scores [7]int) {
	var seen, pending, history uint64
	node := 0
	backtick, left, right, colon, previousColon := false, false, false, false, false
	// A match remains pending until the following byte establishes its end
	// boundary. History supplies the byte before each possible match.
	feed := func(c byte) {
		if !isWordChar(c) {
			for pending != 0 {
				id := bits.TrailingZeros64(pending)
				bit := uint64(1) << id
				if seen&bit == 0 {
					h := detectorHints[id]
					scores[h.dialect] += h.weight
					seen |= bit
				}
				pending &^= bit
			}
		} else {
			pending = 0
		}
		if c >= 128 {
			c = 0
		}
		node = detectorNodes[node].next[c]
		out := detectorNodes[node].outputs &^ seen
		for out != 0 {
			id := bits.TrailingZeros64(out)
			bit := uint64(1) << id
			if history&(uint64(1)<<(detectorHints[id].length-1)) == 0 {
				pending |= bit
			}
			out &^= bit
		}
		history <<= 1
		if isWordChar(c) {
			history |= 1
		}
	}
	for i := 0; i < len(sql); {
		c := sql[i]
		i++
		if c >= utf8.RuneSelf {
			r, n := utf8.DecodeRuneInString(sql[i-1:])
			i += n - 1
			r = unicode.ToUpper(r)
			if r < utf8.RuneSelf {
				c = byte(r)
			} else {
				c = 128
			}
		} else if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case '`':
			backtick = true
		case '[':
			left = true
		case ']':
			right = true
		}
		if c == ':' && previousColon {
			colon = true
		}
		previousColon = c == ':'
		feed(c)
	}
	feed(0)
	if backtick {
		scores[3] += 3
	}
	if left && right {
		scores[4] += 3
	}
	if colon {
		scores[2] += 3
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
//
//nolint:unused // Retained for the existing package helper contract.
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

// isWordChar returns true if the byte is an alphanumeric character or underscore.
func isWordChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}
