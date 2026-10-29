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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestTokenizerHashComments(t *testing.T) {
	for _, dialect := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, tc := range []struct {
			name, input, comment string
			inline               bool
			lastValue            string
		}{
			{"where", "SELECT a FROM t WHERE x = 1 # c\nAND y = 2", "# c", true, "2"},
			{"no space", "SELECT 1#c", "#c", true, "1"},
			{"identifier adjacency", "SELECT a#c", "#c", true, "a"},
			{"EOF", "#", "#", false, ""},
			{"leading", "  # c\nSELECT 1", "# c", false, "1"},
			{"unicode", "SELECT 1 # café\nSELECT 2", "# café", true, "2"},
		} {
			t.Run(string(dialect)+"/"+tc.name, func(t *testing.T) {
				tkz := GetTokenizer()
				defer PutTokenizer(tkz)
				tkz.SetDialect(dialect)
				tokens, err := tkz.TokenizeString(tc.input)
				if err != nil {
					t.Fatalf("TokenizeString: %v", err)
				}
				lastValue := ""
				for _, token := range tokens {
					if token.Token.Type == models.TokenTypeSharp {
						t.Fatal("hash comment emitted a SHARP token")
					}
					if token.Token.Type != models.TokenTypeEOF {
						lastValue = token.Token.Value
					}
				}
				if len(tkz.Comments) != 1 {
					t.Fatalf("comments = %v, want one", tkz.Comments)
				}
				comment := tkz.Comments[0]
				if comment.Text != tc.comment || comment.Style != models.LineComment || comment.Inline != tc.inline {
					t.Errorf("comment = %+v, want text %q, line style, inline %v", comment, tc.comment, tc.inline)
				}
				if lastValue != tc.lastValue {
					t.Errorf("last token value = %q, want %q", lastValue, tc.lastValue)
				}
			})
		}
		t.Run(string(dialect)+"/quoted hashes", func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(dialect)
			tokens, err := tkz.TokenizeString("'#' `a#b` \"#\"")
			if err != nil {
				t.Fatalf("TokenizeString: %v", err)
			}
			if len(tkz.Comments) != 0 || len(tokens) != 4 {
				t.Fatalf("tokens = %v, comments = %v", tokens, tkz.Comments)
			}
			for i, want := range []string{"#", "a#b", "#"} {
				if tokens[i].Token.Value != want {
					t.Errorf("token %d = %q, want %q", i, tokens[i].Token.Value, want)
				}
			}
		})
	}
}

func TestTokenizerOtherDialectHashes(t *testing.T) {
	for _, tc := range []struct {
		name, input, value string
		dialect            keywords.SQLDialect
		kind               models.TokenType
	}{
		{"postgres XOR", "a # b", "#", keywords.DialectPostgreSQL, models.TokenTypeSharp},
		{"postgres path", "j #> '{a}'", "#>", keywords.DialectPostgreSQL, models.TokenTypeHashArrow},
		{"postgres text path", "j #>> '{a}'", "#>>", keywords.DialectPostgreSQL, models.TokenTypeHashLongArrow},
		{"postgres deletion", "j #- '{a}'", "#-", keywords.DialectPostgreSQL, models.TokenTypeHashMinus},
		{"sqlserver local", "SELECT * FROM #tmp", "#tmp", keywords.DialectSQLServer, models.TokenTypeIdentifier},
		{"sqlserver global", "SELECT * FROM ##g", "##g", keywords.DialectSQLServer, models.TokenTypeIdentifier},
		{"oracle name", "SELECT emp# FROM t", "emp#", keywords.DialectOracle, models.TokenTypeIdentifier},
		{"generic", "a # b", "#", keywords.DialectGeneric, models.TokenTypeSharp},
		{"unknown", "a # b", "#", keywords.SQLDialect("unknown"), models.TokenTypeSharp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(tc.dialect)
			tokens, err := tkz.TokenizeString(tc.input)
			if err != nil {
				t.Fatalf("TokenizeString: %v", err)
			}
			if len(tkz.Comments) != 0 {
				t.Fatalf("unexpected comments: %v", tkz.Comments)
			}
			for _, token := range tokens {
				if token.Token.Value == tc.value && token.Token.Type == tc.kind {
					return
				}
			}
			t.Errorf("tokens = %v, want %v %q", tokens, tc.kind, tc.value)
		})
	}
}
