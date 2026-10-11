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

package gosqlx

import "strings"

// SplitStatements splits a SQL source string into top-level statements on
// unquoted semicolons. It is dialect-aware: depending on the supplied dialect
// it understands features that the conservative ANSI-compatible path cannot,
// notably PostgreSQL dollar-quoting, MySQL/ClickHouse backtick identifiers,
// SQL Server bracketed identifiers, PostgreSQL E-string backslash escapes,
// and PostgreSQL nested block comments.
//
// Recognised dialect strings (case-insensitive) — unknown values fall back to
// the conservative ANSI profile:
//
//	"postgresql", "postgres", "pg" — dollar-quotes, E-strings, nested /*…*/
//	"mysql", "mariadb"            — backtick identifiers
//	"clickhouse"                  — backtick identifiers
//	"sqlserver", "mssql", "tsql"  — [bracketed identifiers]
//	""                            — ANSI only (single/double quotes, line/block comments)
//
// The returned slice preserves the original byte ranges between semicolons
// (the terminating ';' itself is stripped). Empty or whitespace-only segments
// are NOT filtered out here; callers such as ParseReaderMultiple trim and
// skip them. This mirrors the long-standing behaviour of the splitter that
// this function replaces.
//
// The returned segments are substrings of sql: no bytes are copied, so
// retaining any one segment keeps the whole input string reachable. Callers
// that keep a single small statement from a very large script and want the
// script to be garbage collected should strings.Clone that segment.
//
// The splitter is intentionally a hand-written state machine rather than a
// full tokenizer: it only needs to know what it is inside of, not what the
// tokens mean. That keeps it fast, robust against partial or syntactically
// invalid SQL (the parser still gets a chance to report those problems
// downstream), and its only allocation is the result slice.
func SplitStatements(sql, dialect string) []string {
	p := profileForDialect(dialect)
	return splitWithProfile(sql, p)
}

// dialectProfile collects the per-dialect feature flags the splitter needs.
// Profiles are immutable and shared; one is resolved per call and passed to
// the state machine by value-ish (read-only) pointer.
type dialectProfile struct {
	supportsDollarQuoting       bool
	supportsBackticks           bool
	supportsBrackets            bool
	supportsEStrings            bool
	supportsNestedBlockComments bool
}

// profileForDialect returns the feature flags for the named dialect. The
// lookup is case-insensitive and tolerant of the common aliases users pass
// through WithDialect.
func profileForDialect(dialect string) dialectProfile {
	switch strings.ToLower(strings.TrimSpace(dialect)) {
	case "postgresql", "postgres", "pg":
		return dialectProfile{
			supportsDollarQuoting:       true,
			supportsEStrings:            true,
			supportsNestedBlockComments: true,
		}
	case "mysql", "mariadb":
		return dialectProfile{supportsBackticks: true}
	case "clickhouse":
		return dialectProfile{supportsBackticks: true}
	case "sqlserver", "mssql", "tsql":
		return dialectProfile{supportsBrackets: true}
	default:
		return dialectProfile{}
	}
}

// splitWithProfile is the state machine. It walks src byte-by-byte, tracking
// which lexical context the cursor is inside (quoted string, comment,
// dollar-quote, etc.) and only emits a split when it sees a top-level ';'.
//
// Segments are emitted as src[start:i] slices of the input rather than being
// copied into a builder, and the result slice is presized from the number of
// ';' bytes in src (an upper bound on the segment count), so the function
// performs a single allocation. Empty input returns nil.
//
// The function is deliberately monolithic — extracting helpers would require
// sharing a lot of index state and would obscure the invariants. Each branch
// documents the transitions it performs so future readers do not have to
// reconstruct the logic from a stack trace.
func splitWithProfile(src string, p dialectProfile) []string {
	if len(src) == 0 {
		return nil
	}
	// Every ';' that terminates a segment is a literal ';' in src, so the
	// count is an upper bound on the number of emitted segments (semicolons
	// inside strings/comments are counted too). Presizing means the result
	// slice is the only allocation and never regrows.
	out := make([]string, 0, strings.Count(src, ";")+1)
	// start is the index in src where the current segment begins. Every
	// segment is the contiguous substring src[start:i], so no bytes are copied.
	start := 0

	// Mutually-exclusive context flags. At most one of (inSingle, inDouble,
	// inBacktick, inBracket, inLine, dollarTag != "") is ever true at a time.
	// blockCommentDepth uses a depth counter instead of a bool because
	// PostgreSQL permits /* /* nested */ */.
	inSingle := false
	inDouble := false
	inBacktick := false
	inBracket := false
	inLine := false
	blockCommentDepth := 0
	dollarTag := "" // non-empty while inside a $tag$...$tag$ or $$...$$ block

	// eStringActive tracks whether the current single-quoted literal was
	// opened with an E-prefix (PostgreSQL): inside such strings a backslash
	// escapes the following byte, including '\''.
	eStringActive := false

	i := 0
	for i < len(src) {
		c := src[i]

		// ─── Inside a context: consume until we exit ──────────────────────
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
			}
			i++
			continue

		case blockCommentDepth > 0:
			if p.supportsNestedBlockComments &&
				c == '/' && i+1 < len(src) && src[i+1] == '*' {
				blockCommentDepth++
				i += 2
				continue
			}
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				blockCommentDepth--
				i += 2
				continue
			}
			i++
			continue

		case dollarTag != "":
			// Closing tag must match exactly, including the surrounding '$'.
			if c == '$' && matchDollarTag(src, i, dollarTag) {
				i += len(dollarTag)
				dollarTag = ""
				continue
			}
			i++
			continue

		case inSingle:
			// PG E-strings: `\` escapes the next byte (commonly \' for a
			// literal apostrophe). The quote we are escaping must not close
			// the string.
			if eStringActive && c == '\\' && i+1 < len(src) {
				i += 2
				continue
			}
			if c == '\'' {
				// Standard SQL doubled-quote escape `''` (works in every
				// dialect, including PG E-strings).
				if i+1 < len(src) && src[i+1] == '\'' {
					i += 2
					continue
				}
				inSingle = false
				eStringActive = false
			}
			i++
			continue

		case inDouble:
			if c == '"' {
				inDouble = false
			}
			i++
			continue

		case inBacktick:
			if c == '`' {
				inBacktick = false
			}
			i++
			continue

		case inBracket:
			if c == ']' {
				inBracket = false
			}
			i++
			continue
		}

		// ─── Top-level: look for openers and semicolons ───────────────────
		switch {
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			inLine = true
			i += 2

		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			blockCommentDepth = 1
			i += 2

		case p.supportsEStrings && (c == 'E' || c == 'e') &&
			i+1 < len(src) && src[i+1] == '\'':
			// PG E'...'
			inSingle = true
			eStringActive = true
			i += 2

		case c == '\'':
			inSingle = true
			eStringActive = false
			i++

		case c == '"':
			inDouble = true
			i++

		case p.supportsBackticks && c == '`':
			inBacktick = true
			i++

		case p.supportsBrackets && c == '[':
			// T-SQL treats [] as identifier quoting. ANSI-land uses [] only
			// inside string literals, which we never reach here, so the guard
			// above is sufficient.
			inBracket = true
			i++

		case p.supportsDollarQuoting && c == '$':
			if tag, ok := readDollarTag(src, i); ok {
				dollarTag = tag
				i += len(tag)
				continue
			}
			i++

		case c == ';':
			out = append(out, src[start:i])
			i++
			start = i

		default:
			i++
		}
	}

	if start < len(src) {
		out = append(out, src[start:])
	}
	return out
}

// readDollarTag attempts to read a PostgreSQL dollar-quote opener starting at
// src[i] (which must be '$'). If the run is a valid opener it returns the
// full tag string (e.g. "$$" or "$outer$") and ok=true. Otherwise it returns
// ("", false) so the caller can treat the '$' as a literal character.
//
// A dollar-quote tag body may contain ASCII letters, digits, and underscores,
// but must NOT start with a digit — matching PostgreSQL's own lexer
// (src/backend/parser/scan.l). A bare "$$" is always valid.
func readDollarTag(src string, i int) (string, bool) {
	// src[i] == '$' by contract.
	if i+1 >= len(src) {
		return "", false
	}
	if src[i+1] == '$' {
		return "$$", true
	}
	// Scan body.
	j := i + 1
	if !isDollarTagStart(src[j]) {
		return "", false
	}
	j++
	for j < len(src) && isDollarTagCont(src[j]) {
		j++
	}
	if j >= len(src) || src[j] != '$' {
		return "", false
	}
	return src[i : j+1], true
}

// matchDollarTag reports whether src[i:] begins with the exact tag string.
// Tag matching is byte-exact; PG preserves case and treats $A$ and $a$ as
// distinct. Used to detect the closing tag while inside a dollar-quote.
func matchDollarTag(src string, i int, tag string) bool {
	if i+len(tag) > len(src) {
		return false
	}
	return src[i:i+len(tag)] == tag
}

// isDollarTagStart reports whether c may be the first byte of a dollar-quote
// tag body (the part between the two '$' delimiters). PG rules: ASCII letter
// or underscore; digits are NOT allowed at the start.
func isDollarTagStart(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
}

// isDollarTagCont reports whether c may appear in the body of a dollar-quote
// tag after the first byte. Letters, digits, and underscores are permitted.
func isDollarTagCont(c byte) bool {
	return isDollarTagStart(c) || (c >= '0' && c <= '9')
}
