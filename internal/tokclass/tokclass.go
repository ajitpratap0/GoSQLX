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

// Package tokclass holds the parser-facing token classification rules: the
// compound-keyword split tables, the IDENT/KEYWORD to specific-type remap,
// the COUNT..MAX to IDENT rule and the backtick-width rule.
//
// It is the single source of truth for turning a tokenizer token into the
// form the parser consumes. The parser's preprocess pass
// (pkg/sql/parser/preprocess.go) is a loop over these functions; a tokenizer
// mode that emits parser-ready tokens directly must use the same functions so
// that both paths agree token for token.
//
// The package imports only pkg/models and strings and holds no per-call
// state: every table is read-only package data, so all functions are safe for
// concurrent use.
package tokclass

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Gate reports whether preprocessing may change a token of this type:
// identifiers, generic keywords, the COUNT..MAX aggregate keywords, the typed
// compound keywords (GroupBy..CrossJoin) and GroupingSets. For every other
// type the parser-ready token is the input token unchanged
// (TestGateIsHoleFree checks this for every type).
func Gate(typ models.TokenType) bool {
	return typ == models.TokenTypeIdentifier || typ == models.TokenTypeKeyword ||
		(typ >= models.TokenTypeCount && typ <= models.TokenTypeMax) ||
		(typ >= models.TokenTypeGroupBy && typ <= models.TokenTypeCrossJoin) ||
		typ == models.TokenTypeGroupingSets
}

// NormalizeInPlace remaps one non-compound token's type (and records a
// backtick quote) in place:
//
//   - COUNT, SUM, AVG, MIN and MAX become identifiers, so they can be used as
//     function-call names.
//   - An identifier with no recorded quote whose single-line span is wider
//     than its value was delimited (`key`, [Group]); it gets Quote '`' and
//     keeps its type, so it stays a name.
//   - Any other identifier or generic keyword whose value is a keyword the
//     parser dispatches on by type gets that type (IdentifierKeywordType,
//     KeywordType).
func NormalizeInPlace(t *models.TokenWithSpan) {
	switch t.Token.Type {
	case models.TokenTypeCount, models.TokenTypeSum, models.TokenTypeAvg,
		models.TokenTypeMin, models.TokenTypeMax:
		t.Token.Type = models.TokenTypeIdentifier
		return
	case models.TokenTypeIdentifier:
		if t.Token.Quote != 0 {
			return
		}
		if t.Start.Line != 0 && t.Start.Line == t.End.Line && t.End.Column-t.Start.Column > len(t.Token.Value) {
			t.Token.Quote = '`'
			return
		}
		if remapped := IdentifierKeywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
	case models.TokenTypeKeyword:
		if remapped := KeywordType(t.Token.Value); remapped != models.TokenTypeUnknown {
			t.Token.Type = remapped
		}
	}
}

// ParserType is the type NormalizeInPlace gives a bare word: a token of type
// lexType with this value, no quote, and a span exactly as wide as the value
// (so the backtick-width rule cannot fire). A keyword table can pre-compute
// it per word. Compound tokens are out of its domain; see CompoundParts.
//
// The remaps upper-case ASCII only, so for a non-ASCII value the result is
// lexType, except that COUNT..MAX still become Identifier.
func ParserType(lexType models.TokenType, value string) models.TokenType {
	switch {
	case lexType >= models.TokenTypeCount && lexType <= models.TokenTypeMax:
		return models.TokenTypeIdentifier
	case lexType == models.TokenTypeKeyword:
		if remapped := KeywordType(value); remapped != models.TokenTypeUnknown {
			return remapped
		}
	case lexType == models.TokenTypeIdentifier:
		if remapped := IdentifierKeywordType(value); remapped != models.TokenTypeUnknown {
			return remapped
		}
	}
	return lexType
}

// AppendCompound appends the expansion of compound token t to dst, copying
// t's span onto every sub-token. It reports false (leaving dst unchanged) if t
// is not a compound token. It performs no allocation beyond growing dst.
func AppendCompound(dst []models.TokenWithSpan, t *models.TokenWithSpan) ([]models.TokenWithSpan, bool) {
	parts := CompoundParts(t)
	if parts == nil {
		return dst, false
	}
	for i := range parts {
		dst = append(dst, models.TokenWithSpan{Token: parts[i], Start: t.Start, End: t.End})
	}
	return dst, true
}

// AppendReady appends the parser-ready form of one tokenizer token to dst:
// its compound parts, or the token with NormalizeInPlace applied, or the
// token unchanged when Gate rejects its type. *t is not modified. This is the
// body of the parser's preprocess loop.
func AppendReady(dst []models.TokenWithSpan, t *models.TokenWithSpan) []models.TokenWithSpan {
	if !Gate(t.Token.Type) {
		return append(dst, *t)
	}
	if d, ok := AppendCompound(dst, t); ok {
		return d
	}
	dst = append(dst, *t)
	NormalizeInPlace(&dst[len(dst)-1])
	return dst
}
