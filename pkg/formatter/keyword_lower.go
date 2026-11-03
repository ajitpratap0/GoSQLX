// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import "strings"

// lowerKeywordTable maps the upper-case keyword spellings the renderers pass
// to nodeFormatter.kw to their lower-case form. strings.ToLower allocates a
// new string for every upper-case input, so lower-case rendering paid one
// allocation per keyword; the table returns a constant instead.
//
// The table is only a fast path. lowerKeyword falls back to strings.ToLower
// for any spelling not listed (dynamic text from the AST, hand-built nodes),
// so a missing entry costs an allocation, never a wrong result.
// TestLowerKeywordTable checks every entry against strings.ToLower and every
// kw("literal") call site against the table.
var lowerKeywordTable = buildLowerKeywordTable(
	" DO NOTHING",
	" DO UPDATE SET ",
	" FOR ",
	" LOCK IN SHARE MODE",
	" NOWAIT",
	" OF ",
	" ON CONFLICT",
	" ON CONSTRAINT ",
	" SKIP LOCKED",
	" WAIT ",
	" WHERE ",
	"ALL",
	"ALTER SEQUENCE",
	"ALTER TABLE",
	"AND",
	"ARRAY JOIN",
	"AS",
	"BEFORE SYSTEM_TIME",
	"BETWEEN",
	"BY",
	"CACHE",
	"CASE",
	"CHARACTER SET",
	"CONCURRENTLY",
	"CONNECT BY",
	"CREATE",
	"CYCLE",
	"DEFAULT VALUES",
	"DELETE",
	"DELETE WHERE",
	"DISTINCT",
	"DISTINCT ON",
	"DROP SEQUENCE",
	"ELSE",
	"END",
	"EXISTS",
	"FETCH",
	"FOR",
	"FORMAT",
	"FROM",
	"FUNCTION",
	"GLOBAL",
	"GROUP BY",
	"HAVING",
	"IF EXISTS",
	"IF NOT EXISTS",
	"IN",
	"INCREMENT BY",
	"INSERT",
	"INTERPOLATE",
	"INTO",
	"LATERAL",
	"LEFT ARRAY JOIN",
	"LIMIT",
	"LOG ERRORS",
	"MATCH_CONDITION",
	"MATCHED",
	"MATERIALIZED",
	"MAXVALUE",
	"MERGE INTO",
	"MINVALUE",
	"NOCACHE",
	"NOCYCLE",
	"NOT",
	"NOT MATCHED",
	"NOT MATCHED BY SOURCE",
	"NOT MATCHED BY TARGET",
	"OFFSET",
	"ON",
	"ON DUPLICATE KEY UPDATE",
	"ONLY",
	"OPTION",
	"OR REPLACE",
	"ORDER BY",
	"ORDER SIBLINGS BY",
	"OUTPUT",
	"PARTITION",
	"PERCENT",
	"PERIOD FOR",
	"PREWHERE",
	"QUALIFY",
	"RECURSIVE",
	"REFRESH MATERIALIZED VIEW",
	"REJECT LIMIT",
	"RESTART",
	"RESTART WITH",
	"RETURNING",
	"ROWS",
	"ROWS EXAMINED",
	"SELECT",
	"SEQUENCE",
	"SET",
	"SETTINGS",
	"SHOW",
	"START WITH",
	"TABLE",
	"THEN",
	"TOP",
	"UNKNOWN",
	"UPDATE",
	"USING",
	"VALUES",
	"WHEN",
	"WHERE",
	"WINDOW",
	"WITH",
	"WITH CUBE",
	"WITH DATA",
	"WITH NO DATA",
	"WITH ORDINALITY",
	"WITH ROLLUP",
	"WITH TIES",
	"WITH TOTALS",
	// Spellings that reach kw through ast helpers rather than literals.
	"ROW", "ROWS", "ASC", "DESC",
	"UNION", "UNION ALL", "UNION DISTINCT", "EXCEPT", "EXCEPT ALL", "EXCEPT DISTINCT",
	"INTERSECT", "INTERSECT ALL", "INTERSECT DISTINCT", "MINUS",
	"JOIN", "INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN", "CROSS JOIN",
	"NATURAL JOIN", "LEFT OUTER JOIN", "RIGHT OUTER JOIN", "FULL OUTER JOIN",
	"CROSS APPLY", "OUTER APPLY", "STRAIGHT_JOIN", "LATERAL JOIN",
	"FOR UPDATE", "FOR SHARE", "FOR NO KEY UPDATE", "FOR KEY SHARE",
	"MATCHED", "NOT MATCHED", "NOT MATCHED BY SOURCE", "NOT MATCHED BY TARGET",
	"DELETE", "DO NOTHING", "ADD COLUMN", "DROP COLUMN", "ALTER COLUMN",
	"RENAME TO", "ADD CONSTRAINT", "DROP CONSTRAINT",
)

func buildLowerKeywordTable(upper ...string) map[string]string {
	m := make(map[string]string, len(upper))
	for _, u := range upper {
		m[u] = strings.ToLower(u)
	}
	return m
}

// lowerKeyword returns keyword in lower case, matching strings.ToLower
// byte for byte. Input with no upper-case ASCII or non-ASCII byte is returned
// as is; known upper-case keywords come from lowerKeywordTable without
// allocating.
func lowerKeyword(keyword string) string {
	needs := false
	for i := 0; i < len(keyword); i++ {
		c := keyword[i]
		if c >= 'A' && c <= 'Z' || c >= 0x80 {
			needs = true
			break
		}
	}
	if !needs {
		return keyword
	}
	if lower, ok := lowerKeywordTable[keyword]; ok {
		return lower
	}
	return strings.ToLower(keyword)
}
