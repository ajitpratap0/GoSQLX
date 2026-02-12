package keywords

import "strings"

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
	{pattern: "CONNECT BY", dialect: DialectOracle, weight: 5},
	{pattern: "SYSDATE", dialect: DialectOracle, weight: 5},
	{pattern: "DECODE", dialect: DialectOracle, weight: 3},

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
// total score wins. If no dialect-specific patterns are found, DialectGeneric
// is returned.
//
// Detection heuristics include:
//   - Snowflake: QUALIFY, FLATTEN, VARIANT, WAREHOUSE, CLONE, UNDROP, RESULT_SCAN, IFF
//   - PostgreSQL: ILIKE, RETURNING, DISTINCT ON, MATERIALIZED
//   - MySQL: ZEROFILL, UNSIGNED, AUTO_INCREMENT, FORCE INDEX
//   - SQL Server: NOLOCK, TOP, NVARCHAR, GETDATE
//   - Oracle: ROWNUM, CONNECT BY, SYSDATE, DECODE
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
//	dialect = keywords.DetectDialect("SELECT * FROM users")
//	// dialect == DialectGeneric
func DetectDialect(sql string) SQLDialect {
	if sql == "" {
		return DialectGeneric
	}

	upper := strings.ToUpper(sql)
	scores := make(map[SQLDialect]int)

	// Check keyword-based hints
	for _, hint := range dialectHints {
		if containsWord(upper, hint.pattern) {
			scores[hint.dialect] += hint.weight
		}
	}

	// Syntactic checks for identifier quoting styles
	if strings.Contains(sql, "`") {
		scores[DialectMySQL] += 3
	}
	if strings.Contains(sql, "[") && strings.Contains(sql, "]") {
		scores[DialectSQLServer] += 3
	}
	if strings.Contains(sql, "::") {
		scores[DialectPostgreSQL] += 3
	}

	// NVL is shared between Oracle and Snowflake, so only add a small weight
	if containsWord(upper, "NVL") {
		scores[DialectOracle] += 1
		scores[DialectSnowflake] += 1
	}

	// Find the dialect with the highest score
	var bestDialect SQLDialect = DialectGeneric
	bestScore := 0
	for dialect, score := range scores {
		if score > bestScore {
			bestScore = score
			bestDialect = dialect
		}
	}

	return bestDialect
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

// isWordChar returns true if the byte is an alphanumeric character or underscore.
func isWordChar(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_'
}
