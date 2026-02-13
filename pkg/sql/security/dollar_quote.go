package security

import (
	"regexp"
	"strings"
)

// dollarQuotePattern matches PostgreSQL dollar-quoted strings: $$...$$ or $tag$...$tag$
// Tags must be valid identifiers (letters, digits, underscore; cannot start with digit).
var dollarQuotePattern = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)?\$`)

// stripDollarQuotedStrings replaces the content of dollar-quoted strings with empty
// strings (preserving the delimiters) so that injection patterns inside string literals
// don't cause false positives, and injection patterns that use dollar-quoting to evade
// detection are neutralized.
func stripDollarQuotedStrings(sql string) string {
	// Find all potential opening dollar-quote tags
	matches := dollarQuotePattern.FindAllStringIndex(sql, -1)
	if len(matches) == 0 {
		return sql
	}

	var result strings.Builder
	result.Grow(len(sql))
	pos := 0

	for pos < len(sql) {
		// Find next dollar-quote opening from current position
		loc := dollarQuotePattern.FindStringIndex(sql[pos:])
		if loc == nil {
			result.WriteString(sql[pos:])
			break
		}

		// Write everything before this match
		openStart := pos + loc[0]
		openEnd := pos + loc[1]
		result.WriteString(sql[pos:openStart])

		openTag := sql[openStart:openEnd]

		// Find the matching closing tag
		closeIdx := strings.Index(sql[openEnd:], openTag)
		if closeIdx == -1 {
			// No closing tag — write the rest as-is (unterminated)
			result.WriteString(sql[openStart:])
			break
		}

		// Write opening tag, skip content, write closing tag
		result.WriteString(openTag)
		result.WriteString(openTag)
		pos = openEnd + closeIdx + len(openTag)
	}

	return result.String()
}
