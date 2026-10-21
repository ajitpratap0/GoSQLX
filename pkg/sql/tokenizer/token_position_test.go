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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Behaviour of token positions (issue #797): a tab is one column, like in
// editors and LSP clients, and a token's Start addresses the token itself, not
// the whitespace or comments skipped before it. Columns stay byte-based.

func loc(line, col int) models.Location { return models.Location{Line: line, Column: col} }

func TestTokenPositions_TabIsOneColumn(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []wantSpan
	}{
		{
			name: "tab between identifiers",
			sql:  "a\tb",
			want: []wantSpan{
				{"a", loc(1, 1), loc(1, 2)},
				{"b", loc(1, 3), loc(1, 4)},
			},
		},
		{
			name: "several tabs",
			sql:  "a\t\t\tb",
			want: []wantSpan{
				{"a", loc(1, 1), loc(1, 2)},
				{"b", loc(1, 5), loc(1, 6)},
			},
		},
		{
			name: "tab inside a string literal counts as one column",
			sql:  "SELECT 'x\ty' AS v",
			want: []wantSpan{
				{"AS", loc(1, 14), loc(1, 16)},
				{"v", loc(1, 17), loc(1, 18)},
			},
		},
		{
			name: "tab indentation on later lines",
			sql:  "SELECT 1\n\tFROM t\n\t\tWHERE x",
			want: []wantSpan{
				{"FROM", loc(2, 2), loc(2, 6)},
				{"WHERE", loc(3, 3), loc(3, 8)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSpans(t, tt.sql, tt.want)
		})
	}
}

func TestTokenPositions_StartIsAfterTrivia(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []wantSpan
	}{
		{
			name: "block comment between tokens after a tab",
			sql:  "a\tb /* x */ c",
			want: []wantSpan{
				{"b", loc(1, 3), loc(1, 4)},
				{"c", loc(1, 13), loc(1, 14)},
			},
		},
		{
			name: "several comments in a row",
			sql:  "a /* 1 */ /* 2 */ -- 3\n  /* 4 */ b",
			want: []wantSpan{
				{"a", loc(1, 1), loc(1, 2)},
				{"b", loc(2, 11), loc(2, 12)},
			},
		},
		{
			name: "line comment then next line",
			sql:  "SELECT a -- note\n\tFROM t",
			want: []wantSpan{
				{"FROM", loc(2, 2), loc(2, 6)},
			},
		},
		{
			name: "block comment spanning lines",
			sql:  "SELECT a /* one\n\ttwo */ FROM t",
			want: []wantSpan{
				{"FROM", loc(2, 9), loc(2, 13)},
			},
		},
		{
			name: "comment directly before token without whitespace",
			sql:  "SELECT 1/* c */+2",
			want: []wantSpan{
				{"+", loc(1, 16), loc(1, 17)},
			},
		},
		{
			name: "multi-byte characters in comment and code, columns are bytes",
			sql:  "SELECT 'é' /* ü */ , x",
			want: []wantSpan{
				// 'é' is 2 bytes and ü is 2 bytes.
				{",", loc(1, 22), loc(1, 23)},
				{"x", loc(1, 24), loc(1, 25)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertSpans(t, tt.sql, tt.want)
		})
	}
}

// A comment before a token must not move the token's Start, and the comment is
// still collected with its own position.
func TestTokenPositions_CommentsKeepOwnPositions(t *testing.T) {
	tests := []struct {
		name         string
		sql          string
		commentStart models.Location
		commentEnd   models.Location
		afterStart   models.Location // Start of the token right after the comment ("c")
	}{
		{"single-line block comment", "a\tb /* x */ c", loc(1, 5), loc(1, 12), loc(1, 13)},
		{"multi-line block comment", "a\tb /* x\n y */ c", loc(1, 5), loc(2, 6), loc(2, 7)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := pooledTokenizer(t)
			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("Tokenize: %v", err)
			}
			if len(tkz.Comments) != 1 {
				t.Fatalf("got %d comments, want 1", len(tkz.Comments))
			}
			c := tkz.Comments[0]
			if c.Start != tt.commentStart || c.End != tt.commentEnd {
				t.Errorf("comment span = %+v-%+v, want %+v-%+v", c.Start, c.End, tt.commentStart, tt.commentEnd)
			}
			if len(tokens) < 3 {
				t.Fatalf("got %d tokens, want at least 3", len(tokens))
			}
			// The token after the comment must not overlap the comment span:
			// tokens[2].Start >= Comments[0].End, comparing line then column.
			after := tokens[2]
			if after.Token.Value != "c" {
				t.Fatalf("tokens[2] = %q, want %q", after.Token.Value, "c")
			}
			if locBefore(after.Start, c.End) {
				t.Errorf("tokens[2] (%q) Start %+v overlaps comment ending at %+v", after.Token.Value, after.Start, c.End)
			}
			if after.Start != tt.afterStart {
				t.Errorf("tokens[2] (%q) Start = %+v, want %+v", after.Token.Value, after.Start, tt.afterStart)
			}
			// Every token lies wholly before or wholly after the comment, and
			// has a non-empty span.
			for i, tok := range tokens {
				if tok.Token.Type == models.TokenTypeEOF {
					continue
				}
				if tok.End.Line == tok.Start.Line && tok.End.Column <= tok.Start.Column {
					t.Errorf("token %d (%q): empty span %+v-%+v", i, tok.Token.Value, tok.Start, tok.End)
				}
				// Half-open spans [Start, End) overlap iff each starts before the other ends.
				if locBefore(tok.Start, c.End) && locBefore(c.Start, tok.End) {
					t.Errorf("token %d (%q) span %+v-%+v overlaps comment %+v-%+v",
						i, tok.Token.Value, tok.Start, tok.End, c.Start, c.End)
				}
			}
		})
	}
}

// locBefore reports whether a precedes b, comparing line then column.
func locBefore(a, b models.Location) bool {
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Column < b.Column
}

// A trailing comment leaves no token after it; the EOF token sits at the end.
func TestTokenPositions_TrailingComment(t *testing.T) {
	tkz := pooledTokenizer(t)
	tokens, err := tkz.Tokenize([]byte("a /* end */"))
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	eof := tokens[len(tokens)-1]
	if eof.Token.Type != models.TokenTypeEOF || eof.Start != loc(1, 12) || eof.End != loc(1, 12) {
		t.Errorf("EOF = %v %+v-%+v, want EOF at %+v", eof.Token.Type, eof.Start, eof.End, loc(1, 12))
	}
}
