// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// readUnicodeEscape lexes a PostgreSQL U&'...' string or U&"..." name with
// its optional UESCAPE clause. A string keeps its validated spelling in one
// TokenTypeUnicodeStringLiteral token; a name keeps its decoded Value and
// double-quote delimiter so it works wherever a name does. Only Unicode names
// allocate optional Word metadata, whose Value holds their source spelling and
// whose QuoteStyle is 'U'; ordinary identifier tokens retain their usual shape.
func (t *Tokenizer) readUnicodeEscape() (models.Token, error) {
	start := t.pos
	quote := t.input[t.pos.Index+2]
	t.pos.Index += 3
	t.pos.Column += 3
	body := t.pos.Index
	end, err := t.scanUnicodeQuote(quote)
	if err != nil {
		return models.Token{}, err
	}
	escape := rune('\\')
	literalEnd := t.pos.Index
	after := t.pos
	comments := len(t.Comments)
	commented, err := t.skipSpaceAndComments()
	i := t.pos.Index
	if err == nil && i+7 <= len(t.input) && strings.EqualFold(t.src[i:i+7], "UESCAPE") &&
		(i+7 == len(t.input) || !nextIsWordStart(t.input[i+7:])) {
		t.pos.Index += 7
		t.pos.Column += 7
		more, err := t.skipSpaceAndComments()
		if err != nil {
			return models.Token{}, err
		}
		commented = commented || more
		if t.pos.Index >= len(t.input) || t.input[t.pos.Index] != '\'' {
			return models.Token{}, errors.UnexpectedCharError('U', t.toSQLPosition(start), t.src)
		}
		t.pos.Index++
		t.pos.Column++
		char := t.pos.Index
		_, err = t.scanUnicodeQuote('\'')
		if err != nil {
			return models.Token{}, err
		}
		value := t.src[char : t.pos.Index-1]
		r, n := utf8.DecodeRuneInString(value)
		if n != len(value) || r == utf8.RuneError || unicode.IsSpace(r) || strings.ContainsRune("0123456789abcdefABCDEF+'\"", r) {
			return models.Token{}, errors.UnexpectedCharError(r, t.toSQLPosition(start), t.src)
		}
		escape = r
	} else {
		// Not followed by UESCAPE: give back the whitespace and any
		// comments so the main loop records them as usual.
		t.pos = after
		t.Comments = t.Comments[:comments]
		commented = false
	}
	content := t.src[body:end]
	if quote == '"' {
		content = strings.ReplaceAll(content, `""`, `"`)
	}
	name, ok := decodeUnicodeEscapes(content, escape)
	if !ok {
		return models.Token{}, errors.UnexpectedCharError(escape, t.toSQLPosition(start), t.src)
	}
	raw := t.src[start.Index:t.pos.Index]
	if commented {
		// Comments between the literal and UESCAPE are recorded in
		// t.Comments; keep them out of the literal's spelling.
		raw = t.src[start.Index:literalEnd] + " UESCAPE '" + string(escape) + "'"
	}
	if quote == '"' {
		return models.Token{Type: models.TokenTypeIdentifier, Value: name, Quote: '"',
			Word: &models.Word{Value: raw, QuoteStyle: 'U'}}, nil
	}
	return models.Token{Type: models.TokenTypeUnicodeStringLiteral, Value: raw, Quote: 'U'}, nil
}

// skipSpaceAndComments skips whitespace and comments, recording the
// comments, and reports whether any comment was skipped.
func (t *Tokenizer) skipSpaceAndComments() (bool, error) {
	commented := false
	for {
		t.skipWhitespace()
		if t.pos.Index+1 >= len(t.input) {
			return commented, nil
		}
		switch {
		case t.input[t.pos.Index] == '-' && t.input[t.pos.Index+1] == '-':
			if err := t.skipLineComment(2); err != nil {
				return commented, err
			}
		case t.input[t.pos.Index] == '/' && t.input[t.pos.Index+1] == '*':
			if err := t.skipBlockComment(); err != nil {
				return commented, err
			}
		default:
			return commented, nil
		}
		commented = true
	}
}

func (t *Tokenizer) scanUnicodeQuote(quote byte) (int, error) {
	for t.pos.Index < len(t.input) {
		if t.input[t.pos.Index] == quote {
			end := t.pos.Index
			t.pos.Index++
			t.pos.Column++
			if t.pos.Index < len(t.input) && t.input[t.pos.Index] == quote {
				t.pos.Index++
				t.pos.Column++
				continue
			}
			return end, nil
		}
		r, n := utf8.DecodeRune(t.input[t.pos.Index:])
		t.pos.AdvanceRune(r, n)
	}
	return 0, errors.UnterminatedStringError(t.getCurrentPosition(), t.src)
}

// decodeUnicodeEscapes validates the escapes in s (\XXXX, \+XXXXXX, a
// doubled escape character, UTF-16 surrogate pairs) and returns the decoded
// text.
func decodeUnicodeEscapes(s string, escape rune) (string, bool) {
	if !utf8.ValidString(s) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(s))
	high := rune(0)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if r != escape {
			if high != 0 {
				return "", false
			}
			b.WriteRune(r)
			continue
		}
		if i >= len(s) {
			return "", false
		}
		r, n = utf8.DecodeRuneInString(s[i:])
		if r == escape {
			if high != 0 {
				return "", false
			}
			b.WriteRune(r)
			i += n
			continue
		}
		count := 4
		if s[i] == '+' {
			count = 6
			i++
		}
		if len(s)-i < count {
			return "", false
		}
		var value rune
		for j := 0; j < count; j++ {
			c := s[i+j]
			if !isHexDigit(c) {
				return "", false
			}
			value *= 16
			switch {
			case c <= '9':
				value += rune(c - '0')
			case c <= 'F':
				value += rune(c - 'A' + 10)
			default:
				value += rune(c - 'a' + 10)
			}
		}
		switch {
		case value >= 0xD800 && value <= 0xDBFF:
			if high != 0 {
				return "", false
			}
			high = value
		case value >= 0xDC00 && value <= 0xDFFF:
			if high == 0 {
				return "", false
			}
			b.WriteRune(utf16.DecodeRune(high, value))
			high = 0
		case high != 0 || value == 0 || !utf8.ValidRune(value):
			return "", false
		default:
			b.WriteRune(value)
		}
		i += count
	}
	if high != 0 {
		return "", false
	}
	return b.String(), true
}
