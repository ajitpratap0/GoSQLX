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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestTokenizer_DollarNameKeepsText checks that a '$' followed by a name that
// does not open a dollar-quoted string ($name, not $name$) is emitted as one
// placeholder token carrying the full "$name" text, in every dialect.
func TestTokenizer_DollarNameKeepsText(t *testing.T) {
	names := []string{"v", "abc", "my_var", "action", "UNION", "Select", "x1", "é"}
	// Each suffix ends the name without a closing '$'.
	suffixes := []string{"", " SELECT 1", "+1", ")", ",b", "\nFROM t", ";", "-- c"}
	dialects := []keywords.SQLDialect{
		keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSnowflake,
		keywords.DialectClickHouse, keywords.DialectSQLite, keywords.DialectMariaDB,
	}

	for _, d := range dialects {
		for _, name := range names {
			for _, suffix := range suffixes {
				input := "SELECT a FROM t WHERE b = $" + name + suffix

				tkz := GetTokenizer()
				tkz.SetDialect(d)
				tokens, err := tkz.TokenizeString(input)
				PutTokenizer(tkz)
				if err != nil {
					t.Fatalf("%s %q: %v", d, input, err)
				}

				found := false
				for _, tok := range tokens {
					if tok.Token.Value == "$"+name {
						if tok.Token.Type != models.TokenTypePlaceholder {
							t.Fatalf("%s %q: $%s has type %v, want placeholder", d, input, name, tok.Token.Type)
						}
						found = true
					}
					if tok.Token.Value == "$" {
						t.Fatalf("%s %q: got a bare \"$\" token", d, input)
					}
				}
				if !found {
					t.Fatalf("%s %q: no placeholder token %q in %v", d, input, "$"+name, tokenValues(tokens))
				}
				if suffix == " SELECT 1" {
					vals := tokenValues(tokens)
					if got := strings.Join(vals[len(vals)-4:len(vals)-1], " "); got != "$"+name+" SELECT 1" {
						t.Fatalf("%s %q: trailing tokens %q", d, input, got)
					}
				}
			}
		}
	}
}

// TestTokenizer_DollarFormsUnchanged pins the other '$' forms next to the
// $name placeholder: positional $N, $$...$$, $tag$...$tag$ and a bare '$'.
func TestTokenizer_DollarFormsUnchanged(t *testing.T) {
	input := "SELECT $1, $$x$$, $tag$y $z$tag$, $w, $"

	tkz := GetTokenizer()
	defer PutTokenizer(tkz)

	tokens, err := tkz.TokenizeString(input)
	if err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	want := []struct {
		typ models.TokenType
		val string
	}{
		{models.TokenTypeSelect, "SELECT"},
		{models.TokenTypePlaceholder, "$1"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeDollarQuotedString, "x"},
		{models.TokenTypeComma, ","},
		{models.TokenTypeDollarQuotedString, "y $z"},
		{models.TokenTypeComma, ","},
		{models.TokenTypePlaceholder, "$w"},
		{models.TokenTypeComma, ","},
		{models.TokenTypePlaceholder, "$"},
		{models.TokenTypeEOF, ""},
	}
	if len(tokens) != len(want) {
		t.Fatalf("got %d tokens %v, want %d", len(tokens), tokenValues(tokens), len(want))
	}
	for i, w := range want {
		if tokens[i].Token.Type != w.typ || tokens[i].Token.Value != w.val {
			t.Errorf("token %d = (%v, %q), want (%v, %q)", i, tokens[i].Token.Type, tokens[i].Token.Value, w.typ, w.val)
		}
	}
	// The $w placeholder spans exactly "$w".
	if s, e := tokens[7].Start, tokens[7].End; e.Column-s.Column != 2 {
		t.Errorf("$w spans columns %d-%d, want width 2", s.Column, e.Column)
	}
}

func tokenValues(tokens []models.TokenWithSpan) []string {
	vals := make([]string, len(tokens))
	for i, tok := range tokens {
		vals[i] = tok.Token.Value
	}
	return vals
}
