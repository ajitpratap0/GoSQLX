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

// Package tokenizer - oracle_bind_param_test.go
// Tests for Oracle bind variable (:1, :name) tokenization (issue #520) and the
// guards that every other dialect keeps emitting a plain COLON token.

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type wantTok struct {
	typ models.TokenType
	val string
}

func tokenizeNoEOF(t *testing.T, dialect keywords.SQLDialect, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz, err := NewWithDialect(dialect)
	if err != nil {
		t.Fatalf("NewWithDialect(%q) error = %v", dialect, err)
	}
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q) error = %v", sql, err)
	}
	if len(tokens) == 0 {
		t.Fatalf("Tokenize(%q) returned no tokens", sql)
	}
	return tokens[:len(tokens)-1] // drop EOF
}

func TestTokenizer_OracleBindVariables(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []wantTok
	}{
		{
			name:  "issue 520 SQL",
			input: "SELECT a, b FROM virtual_fund WHERE virtual_fund_id = :1",
			want: []wantTok{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeComma, ","},
				{models.TokenTypeIdentifier, "b"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "virtual_fund"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "virtual_fund_id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":1"},
			},
		},
		{
			name:  "positional :1 and :2",
			input: "SELECT * FROM t WHERE a = :1 AND b = :2",
			want: []wantTok{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "t"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":1"},
				{models.TokenTypeAnd, "AND"},
				{models.TokenTypeIdentifier, "b"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":2"},
			},
		},
		{
			name:  "named :name",
			input: "SELECT * FROM t WHERE name = :name",
			want: []wantTok{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeMul, "*"},
				{models.TokenTypeFrom, "FROM"},
				{models.TokenTypeIdentifier, "t"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "name"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":name"},
			},
		},
		{
			name:  "INSERT VALUES",
			input: "INSERT INTO t (a, b) VALUES (:1, :b)",
			want: []wantTok{
				{models.TokenTypeInsert, "INSERT"},
				{models.TokenTypeInto, "INTO"},
				{models.TokenTypeIdentifier, "t"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeComma, ","},
				{models.TokenTypeIdentifier, "b"},
				{models.TokenTypeRParen, ")"},
				{models.TokenTypeValues, "VALUES"},
				{models.TokenTypeLParen, "("},
				{models.TokenTypePlaceholder, ":1"},
				{models.TokenTypeComma, ","},
				{models.TokenTypePlaceholder, ":b"},
				{models.TokenTypeRParen, ")"},
			},
		},
		{
			name:  "UPDATE SET with underscore name",
			input: "UPDATE t SET a = :new_a WHERE id = :id",
			want: []wantTok{
				{models.TokenTypeUpdate, "UPDATE"},
				{models.TokenTypeIdentifier, "t"},
				{models.TokenTypeSet, "SET"},
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":new_a"},
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "id"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":id"},
			},
		},
		{
			name:  "no space around operator",
			input: "WHERE a=:1",
			want: []wantTok{
				{models.TokenTypeWhere, "WHERE"},
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":1"},
			},
		},
		{
			name:  "multi-digit :10",
			input: "a = :10",
			want: []wantTok{
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeEq, "="},
				{models.TokenTypePlaceholder, ":10"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeNoEOF(t, keywords.DialectOracle, tt.input)
			if len(tokens) != len(tt.want) {
				t.Fatalf("expected %d tokens, got %d: %v", len(tt.want), len(tokens), tokens)
			}
			for i, w := range tt.want {
				if tokens[i].Token.Type != w.typ || tokens[i].Token.Value != w.val {
					t.Errorf("token %d: want %s %q, got %s %q", i,
						w.typ.String(), w.val, tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}
}

// Keyword-named binds must be placeholders, not keyword tokens.
func TestTokenizer_OracleBindKeywordNamed(t *testing.T) {
	tokens := tokenizeNoEOF(t, keywords.DialectOracle, "WHERE lvl = :level AND d = :date")
	var got []string
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypePlaceholder {
			got = append(got, tok.Token.Value)
		}
		if tok.Token.Type == models.TokenTypeColon {
			t.Errorf("unexpected COLON token in %v", tokens)
		}
	}
	if len(got) != 2 || got[0] != ":level" || got[1] != ":date" {
		t.Errorf("expected placeholders [:level :date], got %v", got)
	}
}

func TestTokenizer_OracleColonNonBind(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []wantTok
	}{
		{
			name:  "assignment :=",
			input: "x := 1",
			want: []wantTok{
				{models.TokenTypeIdentifier, "x"},
				{models.TokenTypeColon, ":"},
				{models.TokenTypeEq, "="},
				{models.TokenTypeNumber, "1"},
			},
		},
		{
			name:  "space breaks the bind",
			input: "a = : 1",
			want: []wantTok{
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeEq, "="},
				{models.TokenTypeColon, ":"},
				{models.TokenTypeNumber, "1"},
			},
		},
		{
			name:  "double colon cast",
			input: "a::int",
			want: []wantTok{
				{models.TokenTypeIdentifier, "a"},
				{models.TokenTypeDoubleColon, "::"},
				{models.TokenTypeIdentifier, "int"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := tokenizeNoEOF(t, keywords.DialectOracle, tt.input)
			if len(tokens) != len(tt.want) {
				t.Fatalf("expected %d tokens, got %d: %v", len(tt.want), len(tokens), tokens)
			}
			for i, w := range tt.want {
				if tokens[i].Token.Type != w.typ || tokens[i].Token.Value != w.val {
					t.Errorf("token %d: want %s %q, got %s %q", i,
						w.typ.String(), w.val, tokens[i].Token.Type.String(), tokens[i].Token.Value)
				}
			}
		})
	}

	t.Run("colons inside string literals", func(t *testing.T) {
		tokens := tokenizeNoEOF(t, keywords.DialectOracle, "SELECT TO_DATE('12:30', 'HH24:MI') FROM dual")
		for _, tok := range tokens {
			if tok.Token.Type == models.TokenTypePlaceholder {
				t.Errorf("unexpected PLACEHOLDER %q", tok.Token.Value)
			}
		}
	})
}

func TestTokenizer_ColonBindIsOracleOnly(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectMariaDB,
		keywords.DialectSQLServer,
		keywords.DialectSQLite,
		keywords.DialectSnowflake,
		keywords.DialectClickHouse,
		keywords.DialectGeneric,
	}
	for _, d := range dialects {
		t.Run(string(d), func(t *testing.T) {
			tokens := tokenizeNoEOF(t, d, "WHERE a = :1 AND b = :name")
			colons := 0
			for _, tok := range tokens {
				switch tok.Token.Type {
				case models.TokenTypePlaceholder:
					t.Errorf("dialect %q emitted PLACEHOLDER %q", d, tok.Token.Value)
				case models.TokenTypeColon:
					colons++
				}
			}
			if colons != 2 {
				t.Errorf("dialect %q: expected 2 COLON tokens, got %d", d, colons)
			}
		})
	}
}

func TestTokenizer_OracleBindVariableSpans(t *testing.T) {
	tokens := tokenizeNoEOF(t, keywords.DialectOracle, "SELECT * FROM t WHERE a = :1 AND b = :name")
	var phs []models.TokenWithSpan
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypePlaceholder {
			phs = append(phs, tok)
		}
	}
	if len(phs) != 2 {
		t.Fatalf("expected 2 placeholders, got %d", len(phs))
	}
	want := []struct {
		val        string
		start, end models.Location
	}{
		{":1", models.Location{Line: 1, Column: 27}, models.Location{Line: 1, Column: 29}},
		{":name", models.Location{Line: 1, Column: 38}, models.Location{Line: 1, Column: 43}},
	}
	for i, w := range want {
		if phs[i].Token.Value != w.val || phs[i].Start != w.start || phs[i].End != w.end {
			t.Errorf("placeholder %d: got %q %v-%v, want %q %v-%v", i,
				phs[i].Token.Value, phs[i].Start, phs[i].End, w.val, w.start, w.end)
		}
	}
}

// A pooled tokenizer switched to Oracle must not leak bind handling to the next
// borrower, which gets the default dialect back.
func TestPool_OracleBindNoLeak(t *testing.T) {
	tkz := GetTokenizer()
	tkz.SetDialect(keywords.DialectOracle)
	tokens, err := tkz.Tokenize([]byte("a = :1"))
	if err != nil {
		PutTokenizer(tkz)
		t.Fatalf("Tokenize() error = %v", err)
	}
	found := false
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypePlaceholder && tok.Token.Value == ":1" {
			found = true
		}
	}
	PutTokenizer(tkz)
	if !found {
		t.Fatal("Oracle tokenizer did not emit PLACEHOLDER for :1")
	}

	tkz2 := GetTokenizer()
	defer PutTokenizer(tkz2)
	tokens, err = tkz2.Tokenize([]byte("SELECT arr[1:n] FROM t"))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}
	colon := false
	for _, tok := range tokens {
		if tok.Token.Type == models.TokenTypePlaceholder {
			t.Errorf("pooled tokenizer leaked Oracle bind: PLACEHOLDER %q", tok.Token.Value)
		}
		if tok.Token.Type == models.TokenTypeColon {
			colon = true
		}
	}
	if !colon {
		t.Error("expected COLON token under default dialect")
	}
}
