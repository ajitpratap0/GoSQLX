// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/ajitpratap0/GoSQLX/internal/namequote"
	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

type normalBuffer struct{ data []byte }

var normalBuffers = sync.Pool{New: func() any { return &normalBuffer{data: make([]byte, 0, 1024)} }}

func putNormalBuffer(b *normalBuffer) {
	if cap(b.data) <= 64<<10 {
		b.data = b.data[:0]
		normalBuffers.Put(b)
	}
}

func normalizeTokens(sql string, opts Options, hash bool) (string, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if opts.Dialect != "" {
		tkz.SetDialect(opts.Dialect)
	}
	toks, err := tokscratch.String(tkz, sql)
	if err != nil {
		return "", fmt.Errorf("fingerprint: tokenization failed: %w", err)
	}
	b, ok := normalBuffers.Get().(*normalBuffer)
	if !ok || b == nil {
		b = &normalBuffer{}
	}
	defer putNormalBuffer(b)
	b.data = appendNormalV2(b.data[:0], toks, sql, opts)
	if len(b.data) == 0 {
		return "", ErrEmpty
	}
	if !hash {
		return string(b.data), nil
	}
	digest := sha256.Sum256(b.data)
	var encoded [67]byte
	copy(encoded[:], VersionPrefix)
	hex.Encode(encoded[3:], digest[:])
	return string(encoded[:]), nil
}

type frame struct {
	cast, modifier, in, row                      bool
	start, element, comma, previous, previousEnd int
	rowPrevious, rowEnd, rowComma                int
}

// delimited mirrors normalizeTokenInPlace in parser/preprocess.go and
// isQuotedIdentifierToken in parser/parser.go, including multiline backticks.
func delimited(t models.TokenWithSpan) bool {
	if t.Token.Type == models.TokenTypeDoubleQuotedString {
		return true
	}
	if t.Token.Type != models.TokenTypeIdentifier {
		return false
	}
	q := t.Token.Quote
	return q == '"' || q == '[' || q == '`' || (q == 0 && (t.Start.Line != t.End.Line || (t.Start.Line != 0 && t.End.Column-t.Start.Column > len(t.Token.Value))))
}
func nameToken(t models.TokenWithSpan) bool {
	return t.Token.Type == models.TokenTypeIdentifier || delimited(t)
}
func literalString(t models.TokenType) bool {
	return t >= models.TokenRangeStringStart && t < models.TokenRangeStringEnd && t != models.TokenTypeDoubleQuotedString
}
func upperEqual(s, up string) bool {
	if len(s) != len(up) {
		return false
	}
	for i := range s {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		if c != up[i] {
			return false
		}
	}
	return true
}
func appendUpper(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		b = append(b, c)
	}
	return b
}
func castName(t models.TokenWithSpan) bool {
	return !delimited(t) && (upperEqual(t.Token.Value, "CAST") || upperEqual(t.Token.Value, "TRY_CAST") || upperEqual(t.Token.Value, "SAFE_CAST"))
}

// unaryAfter excludes value-ending punctuation and QUESTION placeholders from
// IsOperator's broad range. Redacting a number to '?' must not turn the next
// binary sign into a unary one on a second normalization (N6/N15).
func unaryAfter(t models.TokenType) bool {
	switch t {
	case models.TokenTypeEOF, models.TokenTypeLParen, models.TokenTypeLBracket, models.TokenTypeComma:
		return true
	case models.TokenTypeQuestion, models.TokenTypeRParen, models.TokenTypeRBracket,
		models.TokenTypeLBrace, models.TokenTypeRBrace, models.TokenTypePeriod,
		models.TokenTypeColon, models.TokenTypeSemicolon:
		return false
	}
	return t.IsOperator() || (t.IsKeyword() && t != models.TokenTypeEnd &&
		t != models.TokenTypeNull && t != models.TokenTypeTrue && t != models.TokenTypeFalse)
}

func unaryTarget(t, next models.TokenWithSpan) bool {
	k := t.Token.Type
	return k == models.TokenTypeNumber || k == models.TokenTypeTrue ||
		k == models.TokenTypeFalse || k == models.TokenTypeNull || literalString(k) ||
		k == models.TokenTypePlaceholder || k == models.TokenTypeQuestion ||
		nameToken(t) || k == models.TokenTypeLParen ||
		(k == models.TokenTypeColon && next.Token.Type == models.TokenTypeIdentifier)
}

// Keep AS pending until its next emitted token is known. This composes alias
// removal with discarded ASC/AS tokens without rescanning or extra lookahead.
func flushAliases(b []byte, written models.TokenWithSpan, count int) ([]byte, models.TokenWithSpan) {
	for ; count > 0; count-- {
		p := written.Token.Type
		if len(b) > 0 && p != models.TokenTypeEOF && p != models.TokenTypeLParen &&
			p != models.TokenTypeLBracket && p != models.TokenTypePeriod && p != models.TokenTypeDoubleColon {
			b = append(b, ' ')
		}
		b = append(b, 'A', 'S')
		written = models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeAs, Value: "AS"}}
	}
	return b, written
}

func finishElement(b []byte, f *frame) []byte {
	start := f.element
	if start < len(b) && b[start] == ' ' {
		start++
	}
	if f.previous >= 0 && bytes.Equal(b[f.previous:f.previousEnd], b[start:]) {
		return b[:f.comma]
	}
	f.previous = start
	f.previousEnd = len(b)
	return b
}

// A tentative modifier contains only numbers and commas. If another token
// disqualifies it, compact that numeric prefix in place before continuing.
// This avoids a second traversal of tokens or unbounded token lookahead.
func redactModifierPrefix(b []byte, start int) []byte {
	end := len(b)
	w := start
	for r := start; r < end; {
		if b[r] == ' ' || b[r] == ',' {
			b[w] = b[r]
			w++
			r++
			continue
		}
		b[w] = '?'
		w++
		for r < end && b[r] != ' ' && b[r] != ',' {
			r++
		}
	}
	return b[:w]
}

func appendNormalV2(b []byte, ts []models.TokenWithSpan, sql string, opts Options) []byte {
	var stack [32]frame
	root := frame{rowPrevious: -1}
	depth := 0
	var prev, before models.TokenWithSpan
	var written models.TokenWithSpan
	var unary bool
	pendingInto := false
	pendingAS := 0
	unaryColon := false
	ddl, selected, with, main, statement, pending := false, false, false, false, false, false
	line, lineStart := 1, 0
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		typ := t.Token.Type
		if typ == models.TokenTypeEOF || typ == models.TokenTypeWhitespace {
			continue
		}
		var next models.TokenWithSpan
		if i+1 < len(ts) {
			next = ts[i+1]
		}
		// A statement consisting only of discarded ASC tokens must not
		// introduce an empty statement or a leading separator (N10/N16).
		if !statement && typ == models.TokenTypeAsc && next.Token.Type != models.TokenTypePeriod {
			continue
		}
		if typ == models.TokenTypeSemicolon {
			b, written = flushAliases(b, written, pendingAS)
			pendingAS = 0
			if statement {
				pending = true
			}
			statement = false
			depth = 0
			root = frame{rowPrevious: -1}
			prev = models.TokenWithSpan{}
			before = prev
			written = prev
			unary = false
			pendingInto = false
			unaryColon = false
			continue
		}
		if !statement {
			if pending {
				b = append(b, ';', ' ')
				pending = false
			}
			ddl = typ == models.TokenTypeCreate || typ == models.TokenTypeAlter
			selected = false
			with = typ == models.TokenTypeWith
			main = false
			statement = true
		}
		if typ == models.TokenTypeSelect {
			selected = true
		}
		if with && depth == 0 && (typ == models.TokenTypeSelect || typ == models.TokenTypeInsert || typ == models.TokenTypeUpdate || typ == models.TokenTypeDelete || typ == models.TokenTypeMerge) {
			main = true
		}
		var f *frame
		if depth > 0 && depth <= len(stack) {
			f = &stack[depth-1]
		}
		parentRows := &root
		if f != nil {
			parentRows = f
		}
		if depth <= len(stack) && !(typ == models.TokenTypeComma && prev.Token.Type == models.TokenTypeRParen) && !(typ == models.TokenTypeLParen && prev.Token.Type == models.TokenTypeComma) {
			parentRows.rowPrevious = -1
		}
		if f != nil && f.modifier && typ != models.TokenTypeNumber && typ != models.TokenTypeComma && typ != models.TokenTypeRParen {
			b = redactModifierPrefix(b, f.start)
			f.modifier = false
		}
		skip := false
		value := t.Token.Value
		up := false
		quote := rune(0)
		// N2 name parts retain their spelling, including ASC (the N10 exception).
		dotted := typ.IsKeyword() && (prev.Token.Type == models.TokenTypePeriod || next.Token.Type == models.TokenTypePeriod)
		if !dotted {
			switch typ {
			case models.TokenTypeAsc:
				skip = true
			case models.TokenTypeAll:
				// N10 may have removed tokens between SELECT and ALL.
				// Apply N11 to the emitted stream so normalizing twice is stable.
				skip = pendingAS == 0 && written.Token.Type == models.TokenTypeSelect
				up = true
			case models.TokenTypeInner, models.TokenTypeOuter:
				skip = next.Token.Type == models.TokenTypeJoin
				up = true
			case models.TokenTypeInnerJoin, models.TokenTypeOuterJoin:
				value = "JOIN"
			case models.TokenTypeAs:
				if !(f != nil && f.cast) && !(ddl && !selected) && !(with && depth == 0 && !main) {
					pendingAS++
					skip = true
				}
				up = true
			case models.TokenTypeNumber:
				if f == nil || !f.modifier {
					value = "?"
				}
			case models.TokenTypeNull:
				if prev.Token.Type == models.TokenTypeIs || prev.Token.Type == models.TokenTypeNot || (ddl && prev.Token.Type != models.TokenTypeDefault) {
					up = true
				} else {
					value = "?"
				}
			case models.TokenTypeTrue, models.TokenTypeFalse:
				if prev.Token.Type == models.TokenTypeIs || (prev.Token.Type == models.TokenTypeNot && before.Token.Type == models.TokenTypeIs) || upperEqual(prev.Token.Value, "IS NOT") {
					up = true
				} else {
					value = "?"
				}
			case models.TokenTypeNeq:
				value = "<>"
			case models.TokenTypeEq, models.TokenTypeDoubleEq:
				value = "="
			default:
				if delimited(t) {
					if namequote.MustStayQuoted(value, opts.Dialect) {
						quote = t.Token.Quote
						if quote == 0 {
							if typ == models.TokenTypeDoubleQuotedString {
								quote = '"'
							} else {
								quote = '`'
							}
						}
					}
				} else if literalString(typ) {
					if prev.Token.Type == models.TokenTypeAs && !(f != nil && f.cast) {
						// Only kept aliases need source bytes rather than decoded token content.
						for line < t.Start.Line && lineStart < len(sql) {
							if sql[lineStart] == '\n' {
								line++
							}
							lineStart++
						}
						start := lineStart + t.Start.Column - 1
						endLine, endStart := line, lineStart
						for endLine < t.End.Line && endStart < len(sql) {
							if sql[endStart] == '\n' {
								endLine++
							}
							endStart++
						}
						end := endStart + t.End.Column - 1
						if start >= 0 && end >= start && end <= len(sql) {
							value = sql[start:end]
						}
					} else {
						value = "?"
					}
				} else if typ.IsKeyword() {
					up = prev.Token.Type != models.TokenTypePeriod && next.Token.Type != models.TokenTypePeriod
				} else if typ == models.TokenTypeIdentifier && literalString(next.Token.Type) {
					up = true
				}
			}
		}
		if !skip {
			if pendingAS > 0 {
				if !nameToken(t) {
					b, written = flushAliases(b, written, pendingAS)
					unary = false
					unaryColon = false
					pendingInto = false
				}
				pendingAS = 0
			}
			// A discarded token can reveal the identifier of :name after
			// a unary sign. Remove only the provisional space before the
			// trailing colon; the usual colon/name rule supplies the rest.
			if unaryColon && typ == models.TokenTypeIdentifier && len(b) >= 3 && b[len(b)-2] == ' ' && b[len(b)-1] == ':' {
				b[len(b)-2] = ':'
				b = b[:len(b)-1]
			}
			unaryColon = unary && typ == models.TokenTypeColon
			// Delay N12 until the next emitted token. Discarded ASC tokens
			// cannot hide an INSERT/MERGE target from the canonical form.
			if pendingInto && nameToken(t) {
				b = append(b, " INTO"...)
				written = models.TokenWithSpan{Token: models.Token{Type: models.TokenTypeInto, Value: "INTO"}}
			}
			pendingInto = !dotted && (typ == models.TokenTypeInsert || typ == models.TokenTypeMerge)
			if typ == models.TokenTypeComma && f != nil && f.in {
				b = finishElement(b, f)
				f.comma = len(b)
			}
			if typ == models.TokenTypeRParen && f != nil && f.in {
				b = finishElement(b, f)
			}
			noSpace := len(b) == 0 || written.Token.Type == models.TokenTypeEOF
			switch typ {
			case models.TokenTypeComma, models.TokenTypeRParen, models.TokenTypeRBracket, models.TokenTypePeriod, models.TokenTypeDoubleColon:
				noSpace = true
			case models.TokenTypeLParen:
				p := written.Token.Type
				noSpace = noSpace || nameToken(written) || p.IsAggregateFunction() || p.IsDataType() || p == models.TokenTypeCast
			}
			p := written.Token.Type
			if p == models.TokenTypeLParen || p == models.TokenTypeLBracket || p == models.TokenTypePeriod || p == models.TokenTypeDoubleColon || (p == models.TokenTypeColon && typ == models.TokenTypeIdentifier) || (unary && unaryTarget(t, next)) {
				noSpace = true
			}
			first := byte(0)
			if len(value) > 0 {
				first = value[0]
			}
			if quote != 0 {
				first = byte(quote)
			}
			if noSpace && len(b) > 0 {
				last := b[len(b)-1]
				if (last == '-' && first == '-') || (last == '/' && first == '*') || (last == '*' && first == '/') || (last == ':' && first == ':') {
					noSpace = false
				}
			}
			if !noSpace {
				b = append(b, ' ')
			}
			start := len(b)
			if quote != 0 {
				end := byte(quote)
				if quote == '[' {
					end = ']'
				}
				b = append(b, byte(quote))
				for j := 0; j < len(value); j++ {
					c := value[j]
					b = append(b, c)
					if c == end {
						b = append(b, c)
					}
				}
				b = append(b, end)
			} else if up {
				b = appendUpper(b, value)
			} else {
				b = append(b, value...)
			}
			if typ == models.TokenTypeLParen {
				parent := &root
				if f != nil {
					parent = f
				}
				isRow := prev.Token.Type == models.TokenTypeValues || (prev.Token.Type == models.TokenTypeComma && parent.rowPrevious >= 0)
				depth++
				if depth <= len(stack) {
					m := (nameToken(prev) || prev.Token.Type.IsDataType()) && (ddl || before.Token.Type == models.TokenTypeDoubleColon || (before.Token.Type == models.TokenTypeAs && f != nil && f.cast))
					in := prev.Token.Type == models.TokenTypeIn && next.Token.Type != models.TokenTypeSelect && next.Token.Type != models.TokenTypeWith && next.Token.Type != models.TokenTypeValues && next.Token.Type != models.TokenTypeTable
					stack[depth-1] = frame{cast: castName(prev), modifier: m, in: in, row: isRow, start: len(b), element: len(b), previous: -1, rowPrevious: -1, comma: start}
				}
			} else if typ == models.TokenTypeRParen && depth > 0 {
				row := f != nil && f.row
				rowStart := 0
				if row {
					rowStart = f.start - 1
				}
				depth--
				parent := &root
				if depth > 0 && depth <= len(stack) {
					parent = &stack[depth-1]
				}
				if row {
					if parent.rowPrevious >= 0 && bytes.Equal(b[parent.rowPrevious:parent.rowEnd], b[rowStart:]) {
						b = b[:parent.rowComma]
					} else {
						parent.rowPrevious = rowStart
						parent.rowEnd = len(b)
					}
				}
			} else if typ == models.TokenTypeComma && depth <= len(stack) {
				if f != nil && f.in {
					f.element = len(b)
				}
				parent := &root
				if f != nil {
					parent = f
				}
				parent.rowComma = start
			}
			unary = false
			if typ == models.TokenTypePlus || typ == models.TokenTypeMinus {
				unary = unaryAfter(written.Token.Type)
			}
			written = t
		}
		before = prev
		prev = t
	}
	b, _ = flushAliases(b, written, pendingAS)
	return b
}
