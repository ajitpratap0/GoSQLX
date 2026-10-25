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

package ast

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

// stringLiteralNeedsEscapeRaw is the RawBackslash counterpart of
// stringLiteralNeedsEscape: a quote, NUL or non-ASCII byte is rewritten, but
// backslashes, line breaks and Ctrl-Z are plain characters.
func stringLiteralNeedsEscapeRaw(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= utf8.RuneSelf || c == '\'' || c == 0 {
			return true
		}
	}
	return false
}

// writeRawStringLiteral escapes s for a single-quoted literal in a dialect
// where a backslash is an ordinary character: only the quote is doubled and
// invalid UTF-8 is replaced with U+FFFD. Such a dialect has no way to write a
// NUL, and a raw NUL byte would truncate the statement in C-string APIs, so
// NUL bytes are dropped. Parsed input cannot reach this (the tokenizer
// rejects a NUL inside a string in these dialects, and the transpiler
// refuses to target them with one); only a hand-built AST can.
func writeRawStringLiteral(buf *bytes.Buffer, s string) {
	if !stringLiteralNeedsEscapeRaw(s) {
		buf.WriteString(s)
		return
	}
	for _, r := range s {
		switch r {
		case '\'':
			buf.WriteString("''")
		case '\x00':
		default:
			buf.WriteRune(r)
		}
	}
}

// safeStringPrefix returns the literal's introducer, or "" when it is not a
// plain word (letters, digits, underscore). A hand-built AST could otherwise
// smuggle arbitrary text in front of the opening quote.
func (l *LiteralValue) safeStringPrefix() string {
	for i := 0; i < len(l.DialectExtras().Prefix); i++ {
		c := l.DialectExtras().Prefix[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return ""
		}
	}
	return l.DialectExtras().Prefix
}

// stringSQL renders a STRING literal.
func (l *LiteralValue) stringSQL() string {
	text := literalText(l.Value)
	if l.DialectExtras().Prefix == "" {
		if !l.DialectExtras().RawBackslash && !stringLiteralNeedsEscape(text) {
			return "'" + text + "'"
		}
		if l.DialectExtras().RawBackslash && !stringLiteralNeedsEscapeRaw(text) {
			return "'" + text + "'"
		}
	}
	buf := getBuf()
	defer putBuf(buf)
	l.writeStringSQL(buf)
	return buf.String()
}

// writeStringSQL writes a STRING literal: the introducer (if any), the opening
// quote, the text escaped with the literal's own rules, and the closing quote.
func (l *LiteralValue) writeStringSQL(buf *bytes.Buffer) {
	text := literalText(l.Value)
	switch l.DialectExtras().Prefix {
	case "E", "e":
		// PostgreSQL escape string: backslash sequences are decoded, so the
		// text is escaped like a MySQL string, except that Ctrl-Z has no \Z.
		buf.WriteString("E'")
		writeEscapedEStringLiteral(buf, text)
		buf.WriteByte('\'')
		return
	case "q", "Q":
		// Oracle alternative quoting: no escaping at all, so pick a delimiter
		// that does not close early. If none works, fall back to a plain
		// string, which means the same.
		if open, closer, ok := altQuoteDelimiters(text); ok {
			buf.WriteString("q'")
			buf.WriteByte(open)
			buf.WriteString(text)
			buf.WriteByte(closer)
			buf.WriteByte('\'')
			return
		}
		buf.WriteByte('\'')
		writeRawStringLiteral(buf, text)
		buf.WriteByte('\'')
		return
	}
	buf.WriteString(l.safeStringPrefix())
	buf.WriteByte('\'')
	if l.DialectExtras().RawBackslash {
		writeRawStringLiteral(buf, text)
	} else {
		writeEscapedStringLiteral(buf, text)
	}
	buf.WriteByte('\'')
}

// altQuoteDelimiters picks the delimiters of an Oracle q'..' literal for text:
// the first of [], {}, (), <>, !!, # # whose closing delimiter followed by a
// quote does not occur in text. ok is false when text has a NUL or invalid
// UTF-8 (which a plain literal normalises) or no delimiter fits.
func altQuoteDelimiters(text string) (open, closer byte, ok bool) {
	if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return 0, 0, false
	}
	for _, d := range [...][2]byte{{'[', ']'}, {'{', '}'}, {'(', ')'}, {'<', '>'}, {'!', '!'}, {'#', '#'}} {
		if !strings.Contains(text, string(d[1])+"'") {
			return d[0], d[1], true
		}
	}
	return 0, 0, false
}

// writeEscapedEStringLiteral escapes s for a PostgreSQL E'..' literal.
func writeEscapedEStringLiteral(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '\'':
			buf.WriteString("''")
		case '\\':
			buf.WriteString(`\\`)
		case 0:
			// Three octal digits, so a following digit is not read as part
			// of the escape.
			buf.WriteString(`\000`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			buf.WriteRune(r)
		}
	}
}
