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

package bridge

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
)

// jsSlice returns the text JavaScript's s.slice(start, end) yields for a Go
// string holding s, by indexing its UTF-16 encoding.
func jsSlice(s string, start, end int) string {
	u := utf16.Encode([]rune(s))
	if start < 0 || end > len(u) || start > end {
		return "<out of range>"
	}
	return string(utf16.Decode(u[start:end]))
}

func TestUTF16Spans_ConvertsByteOffsets(t *testing.T) {
	// é is 2 bytes / 1 unit, 😀 is 4 bytes / 2 units (a surrogate pair).
	src := "SELECT 'é😀' AS x -- 😀\nFROM t"
	spans := highlight.Spans(src)
	got := UTF16Spans(src, spans)
	if len(got) != len(spans) {
		t.Fatalf("got %d spans, want %d", len(got), len(spans))
	}
	for i, s := range got {
		want := spans[i].Text(src)
		if text := jsSlice(src, s.Start, s.End); text != want {
			t.Errorf("span %d (%s): JS slice [%d,%d) = %q, want %q", i, s.Category, s.Start, s.End, text, want)
		}
		if s.Category != spans[i].Category.String() {
			t.Errorf("span %d: category %q, want %q", i, s.Category, spans[i].Category)
		}
	}
}

func TestUTF16Spans_Table(t *testing.T) {
	tests := []struct {
		name  string
		src   string
		spans []highlight.Span
		want  []HighlightSpan
	}{
		{
			name:  "ascii is unchanged",
			src:   "SELECT 1",
			spans: []highlight.Span{{Start: 0, End: 6, Category: highlight.Keyword}, {Start: 7, End: 8, Category: highlight.Number}},
			want:  []HighlightSpan{{0, 6, "keyword"}, {7, 8, "number"}},
		},
		{
			name:  "astral rune counts two units",
			src:   "'😀' x",
			spans: []highlight.Span{{Start: 0, End: 6, Category: highlight.String}, {Start: 7, End: 8, Category: highlight.Identifier}},
			want:  []HighlightSpan{{0, 4, "string"}, {5, 6, "identifier"}},
		},
		{
			name:  "offsets are clamped to the source",
			src:   "ab",
			spans: []highlight.Span{{Start: -3, End: 99, Category: highlight.Error}},
			want:  []HighlightSpan{{0, 2, "error"}},
		},
		{
			name:  "span left empty by snapping into a rune is dropped",
			src:   "é",
			spans: []highlight.Span{{Start: 0, End: 1, Category: highlight.Identifier}},
			want:  []HighlightSpan{},
		},
		{
			name:  "offset inside a rune snaps to its start",
			src:   "é",
			spans: []highlight.Span{{Start: 1, End: 2, Category: highlight.Identifier}},
			want:  []HighlightSpan{{0, 1, "identifier"}},
		},
		{
			name:  "invalid UTF-8 byte counts one unit",
			src:   "\xff x",
			spans: []highlight.Span{{Start: 2, End: 3, Category: highlight.Identifier}},
			want:  []HighlightSpan{{2, 3, "identifier"}},
		},
		{
			name:  "out-of-order spans are still converted",
			src:   "é x é",
			spans: []highlight.Span{{Start: 6, End: 8, Category: highlight.Identifier}, {Start: 0, End: 2, Category: highlight.Identifier}},
			want:  []HighlightSpan{{4, 5, "identifier"}, {0, 1, "identifier"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UTF16Spans(tt.src, tt.spans)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("UTF16Spans(%q) = %v, want %v", tt.src, got, tt.want)
			}
		})
	}
}

func TestHighlight_JSONShape(t *testing.T) {
	b, err := json.Marshal(Highlight("SELECT id FROM t", "postgresql"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"spans":[{"start":0,"end":6,"category":"keyword"},{"start":7,"end":9,"category":"identifier"},` +
		`{"start":10,"end":14,"category":"keyword"},{"start":15,"end":16,"category":"identifier"}]}`
	if string(b) != want {
		t.Fatalf("got %s\nwant %s", b, want)
	}
}

func TestHighlight_EmptyAndInvalidInput(t *testing.T) {
	if got := Highlight("", "generic"); got.Spans == nil || len(got.Spans) != 0 {
		t.Fatalf("empty SQL: got %#v, want an empty non-nil slice", got.Spans)
	}
	b, err := json.Marshal(Highlight("", ""))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"spans":[]}` {
		t.Fatalf("empty SQL JSON = %s, want {\"spans\":[]}", b)
	}

	src := "SELECT 'é unterminated"
	got := Highlight(src, "no-such-dialect")
	if len(got.Spans) == 0 {
		t.Fatal("expected spans for invalid SQL")
	}
	last := got.Spans[len(got.Spans)-1]
	if last.Category != "error" || last.End != len(utf16.Encode([]rune(src))) {
		t.Fatalf("last span = %+v, want an error span to the end of the input", last)
	}
}

func TestHighlight_HonoursDialect(t *testing.T) {
	// Backticks quote identifiers in MySQL.
	got := Highlight("SELECT `a` FROM t", "mysql")
	var cats []string
	for _, s := range got.Spans {
		cats = append(cats, s.Category)
	}
	if !strings.Contains(strings.Join(cats, ","), "quoted-identifier") {
		t.Fatalf("mysql backtick identifier not classified as quoted-identifier: %v", cats)
	}
}
