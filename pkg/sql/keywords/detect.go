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
	"sync"
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

const (
	dialectOracleIndex = iota
	dialectSnowflakeIndex
	dialectPostgreSQLIndex
	dialectMySQLIndex
	dialectSQLServerIndex
	dialectMariaDBIndex
	dialectSQLiteIndex
	dialectCount
)

// dialectPriority defines score indices and tie-breaking order.
var dialectPriority = [dialectCount]SQLDialect{
	dialectOracleIndex:     DialectOracle,
	dialectSnowflakeIndex:  DialectSnowflake,
	dialectPostgreSQLIndex: DialectPostgreSQL,
	dialectMySQLIndex:      DialectMySQL,
	dialectSQLServerIndex:  DialectSQLServer,
	dialectMariaDBIndex:    DialectMariaDB,
	dialectSQLiteIndex:     DialectSQLite,
}

// The automaton is built lazily from the hint table. Each output bit identifies
// one weighted hint, including duplicate patterns with different dialects.
const matcherClasses = 30

const (
	classOther      = 0
	classDigit      = 27
	classUnderscore = 28
	classSpace      = 29
)

type matcherHint struct {
	length  int
	dialect int
	weight  int
}

var detectorOnce sync.Once
var detectorClasses [256]uint8
var detectorTransitions []uint16
var detectorOutputs []uint64
var detectorHints []matcherHint

func buildDetector() {
	if len(dialectHints)+2 > 64 {
		panic("dialect detector hints exceed 64-bit bitset capacity")
	}
	for c := byte('A'); c <= 'Z'; c++ {
		detectorClasses[c] = c - 'A' + 1
	}
	for c := byte('0'); c <= '9'; c++ {
		detectorClasses[c] = classDigit
	}
	detectorClasses['_'] = classUnderscore
	detectorClasses[' '] = classSpace

	// An upper bound on trie nodes allows building without growing the scratch table.
	maxNodes := 1 + 2*len("NVL")
	for _, h := range dialectHints {
		maxNodes += len(h.pattern)
	}
	if maxNodes > 1<<16 {
		panic("dialect detector exceeds uint16 node capacity")
	}
	transitions := make([]uint16, maxNodes*matcherClasses)
	outputs := make([]uint64, maxNodes)
	fail := make([]uint16, maxNodes)
	detectorHints = make([]matcherHint, 0, len(dialectHints)+2)
	nodes := 1
	add := func(pattern string, dialect, weight int) {
		id := len(detectorHints)
		if id >= 64 {
			panic("dialect detector hints exceed 64-bit bitset capacity")
		}
		if len(pattern) > 64 {
			panic("dialect detector hint exceeds 64-bit history capacity")
		}
		detectorHints = append(detectorHints, matcherHint{len(pattern), dialect, weight})
		node := 0
		for i := 0; i < len(pattern); i++ {
			class := detectorClasses[pattern[i]]
			if class == classOther || class == classDigit {
				panic("unsupported dialect hint byte")
			}
			index := node*matcherClasses + int(class)
			next := transitions[index]
			if next == 0 {
				next = uint16(nodes)
				nodes++
				transitions[index] = next
			}
			node = int(next)
		}
		outputs[node] |= uint64(1) << id
	}
	for _, h := range dialectHints {
		for i, d := range dialectPriority {
			if h.dialect == d {
				add(h.pattern, i, h.weight)
				break
			}
		}
	}
	add("NVL", dialectOracleIndex, 1)
	add("NVL", dialectSnowflakeIndex, 1)
	queue := make([]uint16, 0, nodes)
	for c := 0; c < matcherClasses; c++ {
		if n := transitions[c]; n != 0 {
			queue = append(queue, n)
		}
	}
	for head := 0; head < len(queue); head++ {
		n := int(queue[head])
		f := int(fail[n])
		outputs[n] |= outputs[f]
		for c := 0; c < matcherClasses; c++ {
			index := n*matcherClasses + c
			child := transitions[index]
			if child != 0 {
				fail[child] = transitions[f*matcherClasses+c]
				queue = append(queue, child)
			} else {
				transitions[index] = transitions[f*matcherClasses+c]
			}
		}
	}
	detectorTransitions = make([]uint16, nodes*matcherClasses)
	copy(detectorTransitions, transitions)
	detectorOutputs = make([]uint64, nodes)
	copy(detectorOutputs, outputs)
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
func dialectScores(sql string) (scores [dialectCount]int) {
	detectorOnce.Do(buildDetector)
	var seen, pending, history uint64
	node := 0
	backtick, left, right, colon, previousColon := false, false, false, false, false
	// A match remains pending until the following byte establishes its end boundary.
	for i := 0; i <= len(sql); {
		var c byte
		if i < len(sql) {
			c = sql[i]
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
		} else {
			i++ // Feed a non-word sentinel to flush the final pending match.
		}
		word := isWordChar(c)
		if !word {
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
		node = int(detectorTransitions[node*matcherClasses+int(detectorClasses[c])])
		out := detectorOutputs[node] &^ seen
		for out != 0 {
			id := bits.TrailingZeros64(out)
			bit := uint64(1) << id
			if history&(uint64(1)<<(detectorHints[id].length-1)) == 0 {
				pending |= bit
			}
			out &^= bit
		}
		history <<= 1
		if word {
			history |= 1
		}
	}
	if backtick {
		scores[dialectMySQLIndex] += 3
	}
	if left && right {
		scores[dialectSQLServerIndex] += 3
	}
	if colon {
		scores[dialectPostgreSQLIndex] += 3
	}
	return
}

// isWordChar returns true if the byte is an alphanumeric character or underscore.
func isWordChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}
