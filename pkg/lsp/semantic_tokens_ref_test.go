// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// The reference builder and closure encoder preserve origin/main independently
// of the production encoding lookup table.
var semanticEncodingsReference = buildSemanticEncodingsReference()

func TestSemanticEncodingsTable(t *testing.T) {
	reference := buildSemanticEncodingsReference()
	for i := 0; i < 256; i++ {
		cat := highlight.Category(i)
		got := semanticEncodings[cat]
		if got != reference[cat] {
			t.Errorf("category %d: got %+v want %+v", i, got, reference[cat])
		}
		if got.ok && (int(got.tokenType) >= len(semanticLegend.TokenTypes) || semanticLegend.TokenTypes[got.tokenType] != semanticTokenSpecs[cat].tokenType) {
			t.Errorf("category %d: invalid legend entry", i)
		}
	}
}

func TestEncodeSemanticTokensMatchesReference(t *testing.T) {
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	corpusCases := 0
	for _, st := range set.All() {
		for _, dialect := range goldens.Dialects() {
			for _, cut := range []int{len(st.SQL), len(st.SQL) / 2} {
				content := st.SQL[:cut]
				spans := highlight.Spans(content, highlight.WithDialect(keywords.SQLDialect(dialect)))
				got := encodeSemanticTokens(content, spans)
				want := encodeSemanticTokensReference(content, spans)
				if !slices.Equal(got, want) {
					t.Fatalf("corpus dialect %s cut %d content %q spans %+v: got %v, want %v", dialect, cut, content, spans, got, want)
				}
				corpusCases++
			}
		}
	}
	t.Logf("corpus differential: %d cases", corpusCases)

	const randomCases = 200_000
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "b", " ", "\t", "\n", "\r", "\r\n", "é", "名", "😀", "\xff", "\xe2\x82"}
	categories := append(highlight.Categories(), highlight.Plain, highlight.Category(200))
	for i := 0; i < randomCases; i++ {
		var b strings.Builder
		for n := rng.Intn(30); n > 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		content := b.String()
		spans := make([]highlight.Span, rng.Intn(9))
		for j := range spans {
			// Independent endpoints include inversions, overlap and split runes or CRLF.
			spans[j] = highlight.Span{
				Start:    rng.Intn(len(content)+5) - 2,
				End:      rng.Intn(len(content)+5) - 2,
				Category: categories[rng.Intn(len(categories))],
			}
		}
		if i%2 == 0 {
			slices.SortStableFunc(spans, func(a, b highlight.Span) int { return a.Start - b.Start })
		}
		got := encodeSemanticTokens(content, spans)
		want := encodeSemanticTokensReference(content, spans)
		if !slices.Equal(got, want) {
			t.Fatalf("random case %d content %q spans %+v: got %v, want %v", i, content, spans, got, want)
		}
	}
	t.Logf("seeded random differential: %d cases", randomCases)
}

func buildSemanticEncodingsReference() map[highlight.Category]semanticTokenEncoding {
	legend := SemanticTokensLegend{TokenTypes: []string{}, TokenModifiers: []string{}}
	encodings := make(map[highlight.Category]semanticTokenEncoding, len(semanticTokenSpecs))
	typeIndex := make(map[string]uint32)
	modIndex := make(map[string]uint32)

	for _, cat := range highlight.Categories() {
		spec, ok := semanticTokenSpecs[cat]
		if !ok {
			continue
		}
		ti, seen := typeIndex[spec.tokenType]
		if !seen {
			ti = uint32(len(legend.TokenTypes))
			typeIndex[spec.tokenType] = ti
			legend.TokenTypes = append(legend.TokenTypes, spec.tokenType)
		}
		var mods uint32
		for _, m := range spec.modifiers {
			mi, seen := modIndex[m]
			if !seen {
				mi = uint32(len(legend.TokenModifiers))
				modIndex[m] = mi
				legend.TokenModifiers = append(legend.TokenModifiers, m)
			}
			mods |= 1 << mi
		}
		encodings[cat] = semanticTokenEncoding{tokenType: ti, modifiers: mods, ok: true}
	}
	return encodings
}

func encodeSemanticTokensReference(content string, spans []highlight.Span) []uint32 {
	data := make([]uint32, 0, len(spans)*5)

	// Cursor state: byte offset into content and its LSP position.
	pos, line, char := 0, uint32(0), uint32(0)
	prevLine, prevChar := uint32(0), uint32(0)

	emit := func(l, c, length uint32, enc semanticTokenEncoding) {
		if length == 0 {
			return
		}
		deltaLine := l - prevLine
		deltaChar := c
		if deltaLine == 0 {
			deltaChar = c - prevChar
		}
		data = append(data, deltaLine, deltaChar, length, enc.tokenType, enc.modifiers)
		prevLine, prevChar = l, c
	}

	// step consumes one rune or line break at pos, reporting whether it was
	// a line break.
	step := func() bool {
		switch content[pos] {
		case '\n':
			pos++
		case '\r':
			pos++
			if pos < len(content) && content[pos] == '\n' {
				pos++
			}
		default:
			r, size := utf8.DecodeRuneInString(content[pos:])
			pos += size
			char += uint32(utf16.RuneLen(r)) // RuneError (invalid UTF-8) counts as 1
			return false
		}
		line++
		char = 0
		return true
	}

	for _, sp := range spans {
		enc := semanticEncodingsReference[sp.Category]
		if !enc.ok || sp.Start < 0 || sp.End > len(content) || sp.Start >= sp.End {
			continue
		}
		for pos < sp.Start {
			step()
		}
		// A preceding "\r\n" consumed as a unit can leave pos past Start;
		// emit only the remainder of the span.
		segLine, segChar := line, char
		for pos < sp.End {
			before := char
			if step() {
				emit(segLine, segChar, before-segChar, enc)
				segLine, segChar = line, char
			}
		}
		emit(segLine, segChar, char-segChar, enc)
	}
	return data
}
