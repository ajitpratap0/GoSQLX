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
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
)

// HighlightSpan is one classified range of the submitted SQL.
//
// Start and End are 0-based offsets counted in UTF-16 code units, the unit
// JavaScript string indices and CodeMirror document positions use, so the
// editor can decorate the text without re-reading it. The range is
// end-exclusive. Category is a highlight.Category name such as "keyword".
type HighlightSpan struct {
	Start    int    `json:"start"`
	End      int    `json:"end"`
	Category string `json:"category"`
}

// HighlightResponse is the result of Highlight. Spans are sorted, never
// overlap and always form a JSON array; text between spans is plain.
type HighlightResponse struct {
	Spans []HighlightSpan `json:"spans"`
}

// Highlight classifies sql for syntax highlighting with the given playground
// dialect. It never fails: SQL the tokenizer rejects is highlighted up to the
// error and the rest is a single "error" span.
func Highlight(sql, dialect string) HighlightResponse {
	var opts []highlight.Option
	if d := Dialect(dialect); d != "" {
		opts = append(opts, highlight.WithDialect(d))
	}
	return HighlightResponse{Spans: UTF16Spans(sql, highlight.Spans(sql, opts...))}
}

// UTF16Spans converts spans with byte offsets into src to spans with UTF-16
// offsets. Offsets are clamped to src and moved back to the start of the rune
// they fall inside; spans left empty by that are dropped. Sorted input is
// converted in a single pass.
func UTF16Spans(src string, spans []highlight.Span) []HighlightSpan {
	out := make([]HighlightSpan, 0, len(spans))
	var c utf16Cursor
	for _, s := range spans {
		start := c.offset(src, s.Start)
		end := c.offset(src, s.End)
		if end <= start {
			continue
		}
		out = append(out, HighlightSpan{Start: start, End: end, Category: s.Category.String()})
	}
	return out
}

// utf16Cursor maps byte offsets to UTF-16 offsets, resuming from the last
// position so that a non-decreasing sequence of offsets costs O(len(src)).
type utf16Cursor struct {
	byteOff, utf16Off int
}

// offset returns the UTF-16 offset of byte offset b in src.
func (c *utf16Cursor) offset(src string, b int) int {
	b = min(max(b, 0), len(src))
	if b < c.byteOff {
		c.byteOff, c.utf16Off = 0, 0 // out-of-order input: rescan
	}
	for c.byteOff < b {
		r, size := utf8.DecodeRuneInString(src[c.byteOff:])
		if c.byteOff+size > b {
			break // b falls inside this rune
		}
		c.byteOff += size
		if r == utf8.RuneError && size == 1 {
			c.utf16Off++ // an invalid byte becomes one U+FFFD in JavaScript
		} else {
			c.utf16Off += utf16.RuneLen(r)
		}
	}
	return c.utf16Off
}
