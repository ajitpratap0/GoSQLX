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

package tokenizer

import (
	"bytes"
	"fmt"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	sqldialect "github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// handleEscapeSequence decodes one backslash escape in a string literal whose
// dialect treats '\' as an escape character (see backslashEscapes). On entry
// t.pos is at the backslash; on success it is just past the sequence.
//
// The rules follow t.strEscape (see sqldialect.StringEscape):
//
//   - every mode decodes \\ \' \" \n \r \t;
//   - Strict (no dialect configured) also decodes \` and rejects anything
//     else, since its meaning depends on the dialect;
//   - MySQL decodes \0 \b \Z, keeps the backslash of \% and \_ and drops it
//     before any other character;
//   - Lenient (ClickHouse, BigQuery) decodes \` \0 \a \b \f \v and ASCII
//     \xHH and keeps the backslash before any other character;
//   - DropUnknown (Snowflake, Redshift) decodes \b \f, three-digit octal,
//     \xhh and \uhhhh and drops the backslash before any other character.
//
// A sequence whose value the formatter could not write back unchanged (a
// NUL in DropUnknown mode, a byte above 0x7F, a dialect-dependent digit
// form) is an error rather than a silently different literal.
func (t *Tokenizer) handleEscapeSequence(buf *bytes.Buffer) error {
	t.pos.Index++
	t.pos.Column++

	if t.pos.Index >= len(t.input) {
		return errors.IncompleteStatementError(t.getCurrentPosition(), t.src)
	}

	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	switch r {
	case '\\', '"', '\'':
		buf.WriteRune(r)
		t.pos.AdvanceRune(r, size)
		return nil
	case 'n':
		buf.WriteByte('\n')
		t.pos.AdvanceRune(r, size)
		return nil
	case 'r':
		buf.WriteByte('\r')
		t.pos.AdvanceRune(r, size)
		return nil
	case 't':
		buf.WriteByte('\t')
		t.pos.AdvanceRune(r, size)
		return nil
	}

	switch t.strEscape {
	case sqldialect.StringEscapeStrict:
		if r != '`' {
			return t.invalidEscape(r)
		}
		buf.WriteRune(r)
	case sqldialect.StringEscapeMySQL:
		switch r {
		case '0':
			buf.WriteByte(0)
		case 'b':
			buf.WriteByte('\b')
		case 'Z':
			buf.WriteByte(0x1a)
		case '%', '_':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		default:
			buf.WriteRune(r)
		}
	case sqldialect.StringEscapeDropUnknown:
		return t.decodeDropUnknownEscape(buf, r, size)
	default: // StringEscapeLenient
		switch r {
		case '`':
			buf.WriteRune(r)
		case '0':
			buf.WriteByte(0)
		case 'a':
			buf.WriteByte('\a')
		case 'b':
			buf.WriteByte('\b')
		case 'f':
			buf.WriteByte('\f')
		case 'v':
			buf.WriteByte('\v')
		case 'x':
			v, ok := t.escapeHexDigits(2)
			if !ok {
				// Not a hex escape: like any unknown sequence, kept.
				buf.WriteString(`\x`)
				break
			}
			if v > 0x7f || t.controlUnrepresentable(v) {
				return t.invalidEscape(r)
			}
			buf.WriteByte(byte(v))
			t.pos.Index += 3
			t.pos.Column += 3
			return nil
		default:
			buf.WriteByte('\\')
			buf.WriteRune(r)
		}
	}

	t.pos.AdvanceRune(r, size)
	return nil
}

// decodeDropUnknownEscape decodes the escape after a backslash in the
// Snowflake/Redshift mode; t.pos is on r. Octal, hex and Unicode escapes
// must be complete and name a non-NUL character (ASCII for octal and hex);
// the forms on which Snowflake and PostgreSQL-style Redshift disagree (short
// octal or hex runs, \U) are rejected.
func (t *Tokenizer) decodeDropUnknownEscape(buf *bytes.Buffer, r rune, size int) error {
	switch {
	case r == 'b':
		buf.WriteByte('\b')
	case r == 'f':
		buf.WriteByte('\f')
	case r >= '0' && r <= '7':
		in := t.input
		i := t.pos.Index
		if i+2 >= len(in) || !isOctalDigit(in[i+1]) || !isOctalDigit(in[i+2]) {
			return t.invalidEscape(r)
		}
		v := (in[i]-'0')<<6 | (in[i+1]-'0')<<3 | (in[i+2] - '0')
		if v > 0x7f || in[i] > '1' || t.controlUnrepresentable(rune(v)) {
			return t.invalidEscape(r)
		}
		buf.WriteByte(v)
		t.pos.Index += 3
		t.pos.Column += 3
		return nil
	case r == 'x':
		v, ok := t.escapeHexDigits(2)
		if !ok || v > 0x7f || t.controlUnrepresentable(v) {
			return t.invalidEscape(r)
		}
		buf.WriteByte(byte(v))
		t.pos.Index += 3
		t.pos.Column += 3
		return nil
	case r == 'u':
		v, ok := t.escapeHexDigits(4)
		if !ok || !utf8.ValidRune(v) || t.controlUnrepresentable(v) {
			return t.invalidEscape(r)
		}
		buf.WriteRune(v)
		t.pos.Index += 5
		t.pos.Column += 5
		return nil
	case r == 'U':
		return t.invalidEscape(r)
	default:
		buf.WriteRune(r)
	}
	t.pos.AdvanceRune(r, size)
	return nil
}

// escapeHexDigits reads exactly n hex digits after the escape letter at
// t.pos.Index without consuming them.
func (t *Tokenizer) escapeHexDigits(n int) (rune, bool) {
	in := t.input
	start := t.pos.Index + 1
	if start+n > len(in) {
		return 0, false
	}
	var v rune
	for _, d := range in[start : start+n] {
		switch {
		case d >= '0' && d <= '9':
			v = v<<4 | rune(d-'0')
		case d >= 'a' && d <= 'f':
			v = v<<4 | rune(d-'a'+10)
		case d >= 'A' && d <= 'F':
			v = v<<4 | rune(d-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}

func isOctalDigit(c byte) bool { return c >= '0' && c <= '7' }

// invalidEscape reports an escape sequence the configured dialect does not
// decode to a value the formatter can write back. t.pos is on r.
func (t *Tokenizer) invalidEscape(r rune) error {
	return errors.InvalidSyntaxError(
		fmt.Sprintf("invalid escape sequence '\\%c'", r),
		t.getCurrentPosition(),
		t.src,
	)
}

// controlUnrepresentable reports whether the formatter cannot write c (a NUL
// or Ctrl-Z, whether raw in the source or decoded from an escape) back into a
// string literal of the configured dialect so that it reads as the same
// value; such a literal is rejected rather than formatted with a different
// value. The writer spells NUL as \0 and Ctrl-Z as \Z in a backslash-escaping
// literal and has no spelling for NUL where backslashes do not escape:
//
//   - None (PostgreSQL, Oracle, SQLite, SQL Server, generic): NUL;
//   - Strict (no dialect), which accepts neither \0 nor \Z: both;
//   - Lenient (ClickHouse keeps \Z as two characters): Ctrl-Z;
//   - DropUnknown (Snowflake reads \0 before digits as octal, \Z as Z): both;
//   - MySQL reads both back.
func (t *Tokenizer) controlUnrepresentable(c rune) bool {
	switch t.strEscape {
	case sqldialect.StringEscapeMySQL:
		return false
	case sqldialect.StringEscapeNone:
		return c == 0
	case sqldialect.StringEscapeLenient:
		return c == 0x1a
	default:
		return c == 0 || c == 0x1a
	}
}
