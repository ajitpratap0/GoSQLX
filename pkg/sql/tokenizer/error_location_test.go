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
	"errors"
	"strings"
	"testing"

	gerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// refLocation is an independent reference for the public location rule:
// 1-based line, 1-based byte column, every byte (a tab included) one column.
func refLocation(input string, idx int) models.Location {
	line, lineStart := 1, 0
	for i := 0; i < idx; i++ {
		if input[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	return models.Location{Line: line, Column: 1 + idx - lineStart}
}

// TestTokenizer_ErrorLocations checks that tokenizer errors report the byte
// that starts the offending construct (the opening delimiter of an
// unterminated literal) under the same
// byte-based rule as token spans.
func TestTokenizer_ErrorLocations(t *testing.T) {
	cases := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		// at is the substring whose first byte is the reported location.
		at   string
		want models.Location
	}{
		// Double-quoted identifier broken by a newline.
		{"dquote newline first column", keywords.DialectPostgreSQL, "\n\"\n", "\"", models.Location{Line: 2, Column: 1}},
		{"dquote newline after tabs", keywords.DialectPostgreSQL, "SELECT\t\t\"a\nb\"", "\"", models.Location{Line: 1, Column: 9}},
		{"dquote newline after multibyte", keywords.DialectPostgreSQL, "SELECT 'é€𝄞', \"x\ny\"", "\"", models.Location{Line: 1, Column: 21}},
		{"dquote newline multi-line", keywords.DialectPostgreSQL, "SELECT 1\nFROM t\nWHERE\t\"a\nb\"", "\"", models.Location{Line: 3, Column: 7}},

		// Unterminated dollar-quoted string: the tag's leading '$'.
		{"dollar after tab", keywords.DialectPostgreSQL, "SELECT\t$$abc", "$$", models.Location{Line: 1, Column: 8}},
		{"dollar tag multi-line", keywords.DialectPostgreSQL, "SELECT 'é€',\n\t$tag$body\nmore", "$tag$", models.Location{Line: 2, Column: 2}},
		{"dollar after multibyte", keywords.DialectPostgreSQL, "SELECT 'é€𝄞' || $$abc", "$$", models.Location{Line: 1, Column: 23}},

		// Unterminated SQL Server bracket identifier: the '['.
		{"bracket after tab", keywords.DialectSQLServer, "SELECT\t[col", "[", models.Location{Line: 1, Column: 8}},
		{"bracket multi-line multibyte", keywords.DialectSQLServer, "SELECT N'é€',\n\t\t[abc def", "[", models.Location{Line: 2, Column: 3}},

		// A backslash-escaped closing quote leaves the literal unterminated:
		// the opening quote is reported.
		{"escaped quote after tab and multibyte", keywords.DialectMySQL, "SELECT\t'é\\'", "'é", models.Location{Line: 1, Column: 8}},
		{"escaped quote multi-line", keywords.DialectMySQL, "SELECT 'a\nb€',\n\t'x\\'", "'x", models.Location{Line: 3, Column: 2}},

		// Regression guards for paths that already used the opener.
		{"single quote multi-line", keywords.DialectPostgreSQL, "SELECT\t'é',\n\t'abc", "'abc", models.Location{Line: 2, Column: 2}},
		{"block comment after multibyte", keywords.DialectPostgreSQL, "SELECT 'é€'\t/* never closed", "/*", models.Location{Line: 1, Column: 16}},
		{"backtick after tab", keywords.DialectMySQL, "SELECT\t`a", "`", models.Location{Line: 1, Column: 8}},
		{"triple quote after tab", keywords.DialectBigQuery, "SELECT\t'''abc", "'''", models.Location{Line: 1, Column: 8}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := strings.Index(tc.sql, tc.at)
			if idx < 0 {
				t.Fatalf("marker %q not in %q", tc.at, tc.sql)
			}
			if ref := refLocation(tc.sql, idx); ref != tc.want {
				t.Fatalf("case is inconsistent: byte %d maps to %+v, want %+v", idx, ref, tc.want)
			}

			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(tc.dialect)

			check := func(api string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s(%q): expected an error", api, tc.sql)
				}
				var se *gerrors.Error
				if !errors.As(err, &se) {
					t.Fatalf("%s: got %T, want *errors.Error", api, err)
				}
				if se.Location != tc.want {
					t.Errorf("%s(%q): location %+v, want %+v", api, tc.sql, se.Location, tc.want)
				}
			}
			_, err := tkz.Tokenize([]byte(tc.sql))
			check("Tokenize", err)
			_, err = tkz.TokenizeString(tc.sql)
			check("TokenizeString", err)
		})
	}
}

// TestStringLiteralReader_ErrorLocations covers the standalone reader, which
// has no line index and derives locations from the byte offset directly.
func TestStringLiteralReader_ErrorLocations(t *testing.T) {
	cases := []struct {
		name  string
		input string
		start int // byte offset of the opening quote
		want  models.Location
	}{
		{"unterminated after tab and multibyte", "é\t'abc", 3, models.Location{Line: 1, Column: 4}},
		{"newline on second line", "x\n\t'ab\ncd'", 3, models.Location{Line: 2, Column: 2}},
		{"bad escape", "\t'é\\q'", 1, models.Location{Line: 1, Column: 6}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos := NewPosition(1, tc.start)
			_, err := NewStringLiteralReader([]byte(tc.input), &pos, '\'').ReadStringLiteral()
			if err == nil {
				t.Fatalf("expected an error for %q", tc.input)
			}
			var se *gerrors.Error
			if !errors.As(err, &se) {
				t.Fatalf("got %T, want *errors.Error", err)
			}
			if se.Location != tc.want {
				t.Errorf("location %+v, want %+v", se.Location, tc.want)
			}
		})
	}
}

// TestPosition_LocationMatchesTokenSpans checks that Position.Location applies
// the same rule as token spans.
func TestPosition_LocationMatchesTokenSpans(t *testing.T) {
	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	input := "SELECT 1\n\téü\tx"
	tokens, err := tkz.TokenizeString(input)
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	idx := strings.Index(input, "x")
	got := NewPosition(1, idx).Location(tkz)
	if want := (models.Location{Line: 2, Column: 7}); got != want {
		t.Fatalf("Location() = %+v, want %+v", got, want)
	}
	last := tokens[len(tokens)-2] // the final token before EOF
	if last.Token.Value != "x" || last.Start != got {
		t.Fatalf("token %q starts at %+v, Location() = %+v", last.Token.Value, last.Start, got)
	}
}
