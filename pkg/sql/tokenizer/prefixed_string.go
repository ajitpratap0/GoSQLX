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
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// This file lexes string literals with a one-letter introducer written
// directly before the opening quote:
//
//	N'text'   national string          (TokenTypeNationalStringLiteral)
//	X'4D'     hexadecimal string       (TokenTypeHexStringLiteral)
//	B'101'    bit string               (TokenTypeByteStringLiteral)
//	E'a\tb'   PostgreSQL escape string (TokenTypeEscapedStringLiteral)
//	q'[it's]' Oracle alternative quote (TokenTypeSingleQuotedString, Quote 'q')
//
// Each token's Value is the decoded text. The introducer decides the token
// type, so the parser can keep it for the round trip (N, X, B) or discard it
// when the decoded text is all the literal means (E, q).

// prefixedStringAllowed reports whether the introducer letter (upper-cased)
// starts a prefixed literal in the tokenizer's dialect. An unconfigured
// tokenizer behaves as PostgreSQL.
func (t *Tokenizer) prefixedStringAllowed(letter byte) bool {
	d := t.dialect
	switch letter {
	case 'N':
		return d == keywords.DialectSQLServer || d == keywords.DialectOracle ||
			d == keywords.DialectMySQL || d == keywords.DialectMariaDB || d == keywords.DialectPostgreSQL
	case 'X':
		return d == keywords.DialectMySQL || d == keywords.DialectMariaDB ||
			d == keywords.DialectSQLite || d == keywords.DialectPostgreSQL || d == keywords.DialectSnowflake
	case 'B':
		return d == keywords.DialectMySQL || d == keywords.DialectMariaDB || d == keywords.DialectPostgreSQL
	case 'E':
		return d == keywords.DialectPostgreSQL
	case 'Q':
		return d == keywords.DialectOracle
	}
	return false
}

// readPrefixedString lexes a prefixed literal whose one-letter introducer has
// just been consumed, leaving t.pos on the opening quote. ok is false, with
// nothing consumed, when the letter is not an introducer in this dialect, so
// the caller reads an ordinary identifier.
func (t *Tokenizer) readPrefixedString(letter byte) (tok models.Token, ok bool, err error) {
	if letter >= 'a' && letter <= 'z' {
		letter -= 'a' - 'A'
	}
	if !t.prefixedStringAllowed(letter) {
		return models.Token{}, false, nil
	}
	switch letter {
	case 'N', 'X', 'B':
		inner, err := t.readQuotedString('\'')
		if err != nil {
			return models.Token{}, true, err
		}
		typ := models.TokenTypeNationalStringLiteral
		switch letter {
		case 'X':
			typ = models.TokenTypeHexStringLiteral
		case 'B':
			typ = models.TokenTypeByteStringLiteral
		}
		return models.Token{Type: typ, Value: inner.Value, Quote: rune(letter)}, true, nil
	case 'E':
		tok, err := t.readEscapedString()
		return tok, true, err
	default: // 'Q'
		return t.readAltQuotedString()
	}
}

// readEscapedString reads the body of a PostgreSQL E'...' string. t.pos is on
// the opening quote. Backslash sequences are decoded (\b \f \n \r \t, octal
// \ooo, \xhh, \uXXXX, \UXXXXXXXX); any other escaped character stands for
// itself, so \\ and \' work. A doubled quote is a quote.
func (t *Tokenizer) readEscapedString() (models.Token, error) {
	startPos := t.pos
	t.pos.Index++ // opening quote (ASCII)
	t.pos.Column++
	buf := &t.litBuf
	buf.Reset()
	in := t.input
	for t.pos.Index < len(in) {
		c := in[t.pos.Index]
		switch {
		case c == '\'':
			if t.pos.Index+1 < len(in) && in[t.pos.Index+1] == '\'' {
				buf.WriteByte('\'')
				t.pos.Index += 2
				t.pos.Column += 2
				continue
			}
			t.pos.Index++
			t.pos.Column++
			return models.Token{Type: models.TokenTypeEscapedStringLiteral, Value: buf.String(), Quote: 'E'}, nil
		case c == '\\':
			t.pos.Index++
			t.pos.Column++
			if t.pos.Index >= len(in) {
				return models.Token{}, errors.UnterminatedStringError(t.toSQLPosition(startPos), t.src)
			}
			t.decodePGEscape(buf)
		default:
			r, size := utf8.DecodeRune(in[t.pos.Index:])
			if r == utf8.RuneError && size == 1 {
				buf.WriteRune(utf8.RuneError)
			} else {
				buf.Write(in[t.pos.Index : t.pos.Index+size])
			}
			t.pos.AdvanceRune(r, size)
		}
	}
	return models.Token{}, errors.UnterminatedStringError(t.toSQLPosition(startPos), t.src)
}

// decodePGEscape decodes the escape that follows a backslash in an E-string;
// t.pos is on the character after the backslash.
func (t *Tokenizer) decodePGEscape(buf *bytes.Buffer) {
	in := t.input
	c := in[t.pos.Index]
	hexRun := func(max int) (v rune, n int) {
		for n < max && t.pos.Index+1+n < len(in) {
			d := in[t.pos.Index+1+n]
			switch {
			case d >= '0' && d <= '9':
				v = v<<4 | rune(d-'0')
			case d >= 'a' && d <= 'f':
				v = v<<4 | rune(d-'a'+10)
			case d >= 'A' && d <= 'F':
				v = v<<4 | rune(d-'A'+10)
			default:
				return v, n
			}
			n++
		}
		return v, n
	}
	switch {
	case c >= '0' && c <= '7':
		v, n := rune(0), 0
		for n < 3 && t.pos.Index+n < len(in) && in[t.pos.Index+n] >= '0' && in[t.pos.Index+n] <= '7' {
			v = v<<3 | rune(in[t.pos.Index+n]-'0')
			n++
		}
		buf.WriteByte(byte(v))
		t.pos.Index += n
		t.pos.Column += n
	case c == 'x':
		if v, n := hexRun(2); n > 0 {
			buf.WriteByte(byte(v))
			t.pos.Index += 1 + n
			t.pos.Column += 1 + n
			return
		}
		buf.WriteByte('x')
		t.pos.Index++
		t.pos.Column++
	case c == 'u' || c == 'U':
		want := 4
		if c == 'U' {
			want = 8
		}
		if v, n := hexRun(want); n == want && utf8.ValidRune(v) {
			buf.WriteRune(v)
			t.pos.Index += 1 + n
			t.pos.Column += 1 + n
			return
		}
		buf.WriteByte(c)
		t.pos.Index++
		t.pos.Column++
	default:
		switch c {
		case 'b':
			buf.WriteByte('\b')
		case 'f':
			buf.WriteByte('\f')
		case 'n':
			buf.WriteByte('\n')
		case 'r':
			buf.WriteByte('\r')
		case 't':
			buf.WriteByte('\t')
		default:
			r, size := utf8.DecodeRune(in[t.pos.Index:])
			buf.WriteRune(r)
			t.pos.AdvanceRune(r, size)
			return
		}
		t.pos.Index++
		t.pos.Column++
	}
}

// readAltQuotedString reads an Oracle alternative-quoting literal q'<d>...<d>'
// where <d> is any non-blank character: [ { ( < close with the matching
// bracket, any other character closes with itself. t.pos is on the opening
// quote. ok is false, with nothing consumed, when no delimiter follows the
// quote (q is then an ordinary word).
func (t *Tokenizer) readAltQuotedString() (models.Token, bool, error) {
	in := t.input
	d := t.pos.Index + 1
	if d >= len(in) {
		return models.Token{}, false, nil
	}
	open, dsize := utf8.DecodeRune(in[d:])
	if open == ' ' || open == '\t' || open == '\n' || open == '\r' || open == '\'' {
		return models.Token{}, false, nil
	}
	closer := open
	switch open {
	case '[':
		closer = ']'
	case '{':
		closer = '}'
	case '(':
		closer = ')'
	case '<':
		closer = '>'
	}
	startPos := t.pos
	contentStart := d + dsize
	for i := contentStart; i < len(in); {
		r, size := utf8.DecodeRune(in[i:])
		if r == closer && i+size < len(in) && in[i+size] == '\'' {
			value := t.src[contentStart:i]
			end := i + size + 1
			for t.pos.Index < end {
				cr, cs := utf8.DecodeRune(in[t.pos.Index:])
				t.pos.AdvanceRune(cr, cs)
			}
			return models.Token{Type: models.TokenTypeSingleQuotedString, Value: value, Quote: 'q'}, true, nil
		}
		i += size
	}
	return models.Token{}, true, errors.UnterminatedStringError(t.toSQLPosition(startPos), t.src)
}
