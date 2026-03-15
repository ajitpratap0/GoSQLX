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
			// No closing tag - write the rest as-is (unterminated)
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
