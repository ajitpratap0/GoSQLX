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
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type lexTok struct {
	typ models.TokenType
	val string
}

func lexAll(t *testing.T, d keywords.SQLDialect, sql string) []lexTok {
	t.Helper()
	tkz, _ := NewWithDialect(d)
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		t.Fatalf("%s %q: %v", d, sql, err)
	}
	var out []lexTok
	for _, tw := range tokens {
		if tw.Token.Type == models.TokenTypeEOF {
			continue
		}
		out = append(out, lexTok{tw.Token.Type, tw.Token.Value})
	}
	return out
}

func TestLexNumbers(t *testing.T) {
	num := models.TokenTypeNumber
	tests := []struct {
		name string
		sql  string
		want []lexTok
	}{
		{"hex", "0x1F", []lexTok{{num, "0x1F"}}},
		{"hex upper prefix and lower digits", "0XaB09", []lexTok{{num, "0XaB09"}}},
		{"hex in expression", "a = 0xFF AND b", []lexTok{
			{models.TokenTypeIdentifier, "a"}, {models.TokenTypeEq, "="}, {num, "0xFF"},
			{models.TokenTypeAnd, "AND"}, {models.TokenTypeIdentifier, "b"}}},
		{"0x without digits is an identifier", "0x", []lexTok{{models.TokenTypeIdentifier, "0x"}}},
		{"leading dot", ".5", []lexTok{{num, ".5"}}},
		{"leading dot after operator", "a+.5", []lexTok{{models.TokenTypeIdentifier, "a"}, {models.TokenTypePlus, "+"}, {num, ".5"}}},
		{"leading dot after comma", "(1,.25)", []lexTok{
			{models.TokenTypeLeftParen, "("}, {num, "1"}, {models.TokenTypeComma, ","}, {num, ".25"}, {models.TokenTypeRightParen, ")"}}},
		{"leading dot with exponent", ".5e-3", []lexTok{{num, ".5e-3"}}},
		{"qualifier dot is not a number", "t.5", []lexTok{{models.TokenTypeIdentifier, "t"}, {models.TokenTypeDot, "."}, {num, "5"}}},
		{"trailing dot", "5.", []lexTok{{num, "5."}}},
		{"trailing dot before comma", "5., 6", []lexTok{{num, "5."}, {models.TokenTypeComma, ","}, {num, "6"}}},
		{"trailing dot before keyword", "5. FROM", []lexTok{{num, "5."}, {models.TokenTypeFrom, "FROM"}}},
		{"trailing dot with exponent", "1.e5", []lexTok{{num, "1.e5"}}},
		{"dot then word stays separate", "1.foo", []lexTok{{num, "1"}, {models.TokenTypeDot, "."}, {models.TokenTypeIdentifier, "foo"}}},
		{"double dot stays separate", "1..2", []lexTok{{num, "1"}, {models.TokenTypeDot, "."}, {num, ".2"}}},
		{"plain decimal unchanged", "1.5", []lexTok{{num, "1.5"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lexAll(t, keywords.DialectMySQL, tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%q\n got %v\nwant %v", tt.sql, got, tt.want)
			}
		})
	}
}

func TestLexOperators(t *testing.T) {
	tests := []struct {
		sql  string
		want lexTok
	}{
		{"^", lexTok{models.TokenTypeCaret, "^"}},
		{"^@", lexTok{models.TokenTypeCaretAt, "^@"}},
		{"<=>", lexTok{models.TokenTypeSpaceship, "<=>"}},
		{"<->", lexTok{models.TokenTypeCustomBinaryOperator, "<->"}},
		{"<<", lexTok{models.TokenTypeShiftLeft, "<<"}},
		{">>", lexTok{models.TokenTypeShiftRight, ">>"}},
		{"==", lexTok{models.TokenTypeDoubleEq, "=="}},
		{":=", lexTok{models.TokenTypeAssignment, ":="}},
		{"{", lexTok{models.TokenTypeLBrace, "{"}},
		{"}", lexTok{models.TokenTypeRBrace, "}"}},
	}
	for _, tt := range tests {
		for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite, keywords.DialectOracle} {
			got := lexAll(t, d, "a "+tt.sql+" b")
			want := []lexTok{{models.TokenTypeIdentifier, "a"}, tt.want, {models.TokenTypeIdentifier, "b"}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %q\n got %v\nwant %v", d, tt.sql, got, want)
			}
		}
	}
}

// TestLexOperatorsKeepNeighbours guards the tokens that share a prefix with
// the new operators.
func TestLexOperatorsKeepNeighbours(t *testing.T) {
	tests := []struct {
		sql  string
		want []models.TokenType
	}{
		{"a<=b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeLtEq, models.TokenTypeIdentifier}},
		{"a<>b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeNeq, models.TokenTypeIdentifier}},
		{"a<-1", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeLt, models.TokenTypeMinus, models.TokenTypeNumber}},
		{"a->b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeArrow, models.TokenTypeIdentifier}},
		{"a>=b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeGtEq, models.TokenTypeIdentifier}},
		{"a=>b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeRArrow, models.TokenTypeIdentifier}},
		{"a::b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeDoubleColon, models.TokenTypeIdentifier}},
		{"a<@b", []models.TokenType{models.TokenTypeIdentifier, models.TokenTypeArrowAt, models.TokenTypeIdentifier}},
	}
	for _, tt := range tests {
		var got []models.TokenType
		for _, tok := range lexAll(t, keywords.DialectPostgreSQL, tt.sql) {
			got = append(got, tok.typ)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: got %v, want %v", tt.sql, got, tt.want)
		}
	}
}

func TestLexIdentifierDollarAndHash(t *testing.T) {
	id := models.TokenTypeIdentifier
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []lexTok
	}{
		{"oracle v$session", keywords.DialectOracle, "v$session", []lexTok{{id, "v$session"}}},
		{"oracle gv$ view after dot", keywords.DialectOracle, "sys.gv$sql", []lexTok{{id, "sys"}, {models.TokenTypeDot, "."}, {id, "gv$sql"}}},
		{"oracle hash", keywords.DialectOracle, "a#", []lexTok{{id, "a#"}}},
		{"oracle hash and dollar", keywords.DialectOracle, "x#y$z", []lexTok{{id, "x#y$z"}}},
		{"snowflake SYSTEM$TYPEOF", keywords.DialectSnowflake, "SYSTEM$TYPEOF(1)", []lexTok{
			{id, "SYSTEM$TYPEOF"}, {models.TokenTypeLeftParen, "("}, {models.TokenTypeNumber, "1"}, {models.TokenTypeRightParen, ")"}}},
		{"snowflake METADATA$FILENAME", keywords.DialectSnowflake, "METADATA$FILENAME", []lexTok{{id, "METADATA$FILENAME"}}},
		{"postgres dollar", keywords.DialectPostgreSQL, "a$b", []lexTok{{id, "a$b"}}},
		{"postgres hash is an operator", keywords.DialectPostgreSQL, "a#>b", []lexTok{{id, "a"}, {models.TokenTypeHashArrow, "#>"}, {id, "b"}}},
		{"dollar cannot start a name", keywords.DialectOracle, "$1", []lexTok{{models.TokenTypePlaceholder, "$1"}}},
		{"mysql hash starts a comment", keywords.DialectMySQL, "a #", []lexTok{{id, "a"}}},
		{"hash cannot continue a name outside oracle", keywords.DialectGeneric, "a #", []lexTok{{id, "a"}, {models.TokenTypeSharp, "#"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lexAll(t, tt.dialect, tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%q\n got %v\nwant %v", tt.sql, got, tt.want)
			}
		})
	}
}

func TestLexPlaceholdersAndBrackets(t *testing.T) {
	ph := models.TokenTypePlaceholder
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    []lexTok
	}{
		{"sqlite named", keywords.DialectSQLite, ":name", []lexTok{{ph, ":name"}}},
		{"sqlite positional", keywords.DialectSQLite, "?1", []lexTok{{ph, "?1"}}},
		{"sqlite bare question mark", keywords.DialectSQLite, "? ,?", []lexTok{{ph, "?"}, {models.TokenTypeComma, ","}, {ph, "?"}}},
		{"sqlite bracket identifier", keywords.DialectSQLite, "[col]", []lexTok{{models.TokenTypeIdentifier, "col"}}},
		{"sqlite bracket identifier with space", keywords.DialectSQLite, "[Order Details]", []lexTok{{models.TokenTypeIdentifier, "Order Details"}}},
		{"mysql question mark is not numbered", keywords.DialectMySQL, "?1", []lexTok{{ph, "?"}, {models.TokenTypeNumber, "1"}}},
		{"postgres colon is not a bind", keywords.DialectPostgreSQL, "a[1:n]", []lexTok{
			{models.TokenTypeIdentifier, "a"}, {models.TokenTypeLBracket, "["}, {models.TokenTypeNumber, "1"},
			{models.TokenTypeColon, ":"}, {models.TokenTypeIdentifier, "n"}, {models.TokenTypeRBracket, "]"}}},
		{"clickhouse typed parameter", keywords.DialectClickHouse, "{p:UInt64}", []lexTok{{ph, "{p:UInt64}"}}},
		{"clickhouse parameter with parenthesised type", keywords.DialectClickHouse, "{d: DateTime64(3, 'UTC')}", []lexTok{{ph, "{d: DateTime64(3, 'UTC')}"}}},
		{"clickhouse array parameter", keywords.DialectClickHouse, "x IN {ids:Array(UInt32)}", []lexTok{
			{models.TokenTypeIdentifier, "x"}, {models.TokenTypeIn, "IN"}, {ph, "{ids:Array(UInt32)}"}}},
		{"clickhouse map literal is not a parameter", keywords.DialectClickHouse, "{'a':1}", []lexTok{
			{models.TokenTypeLBrace, "{"}, {models.TokenTypeSingleQuotedString, "a"}, {models.TokenTypeColon, ":"},
			{models.TokenTypeNumber, "1"}, {models.TokenTypeRBrace, "}"}}},
		{"clickhouse unterminated parameter", keywords.DialectClickHouse, "{p:UInt64", []lexTok{
			{models.TokenTypeLBrace, "{"}, {models.TokenTypeIdentifier, "p"}, {models.TokenTypeColon, ":"}, {models.TokenTypeIdentifier, "UInt64"}}},
		{"other dialects see braces", keywords.DialectPostgreSQL, "{p}", []lexTok{
			{models.TokenTypeLBrace, "{"}, {models.TokenTypeIdentifier, "p"}, {models.TokenTypeRBrace, "}"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lexAll(t, tt.dialect, tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%q\n got %v\nwant %v", tt.sql, got, tt.want)
			}
		})
	}
}

func TestLexPrefixedStrings(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		typ     models.TokenType
		value   string
		quote   rune
	}{
		{"hex mysql", keywords.DialectMySQL, `X'4D'`, models.TokenTypeHexStringLiteral, "4D", 'X'},
		{"hex lower sqlite", keywords.DialectSQLite, `x'CAFE'`, models.TokenTypeHexStringLiteral, "CAFE", 'X'},
		{"bit mysql", keywords.DialectMySQL, `b'101'`, models.TokenTypeByteStringLiteral, "101", 'B'},
		{"bit upper postgres", keywords.DialectPostgreSQL, `B'101'`, models.TokenTypeByteStringLiteral, "101", 'B'},
		{"national oracle", keywords.DialectOracle, `N'x'`, models.TokenTypeNationalStringLiteral, "x", 'N'},
		{"national lower mysql", keywords.DialectMySQL, `n'x'`, models.TokenTypeNationalStringLiteral, "x", 'N'},
		{"national sqlserver", keywords.DialectSQLServer, `N'it''s'`, models.TokenTypeNationalStringLiteral, "it's", 'N'},
		{"escape string tab", keywords.DialectPostgreSQL, `E'tab\there'`, models.TokenTypeEscapedStringLiteral, "tab\there", 'E'},
		{"escape string quotes and backslash", keywords.DialectPostgreSQL, `E'it\'s \\ ok'`, models.TokenTypeEscapedStringLiteral, `it's \ ok`, 'E'},
		{"escape string doubled quote", keywords.DialectPostgreSQL, `e'a''b'`, models.TokenTypeEscapedStringLiteral, "a'b", 'E'},
		{"escape string octal hex unicode", keywords.DialectPostgreSQL, `E'\101\x42C\U00000044'`, models.TokenTypeEscapedStringLiteral, "ABCD", 'E'},
		{"escape string unknown escape", keywords.DialectPostgreSQL, `E'\q'`, models.TokenTypeEscapedStringLiteral, "q", 'E'},
		{"escape string multibyte", keywords.DialectPostgreSQL, "E'é\\n世'", models.TokenTypeEscapedStringLiteral, "é\n世", 'E'},
		{"q-quote brackets", keywords.DialectOracle, `q'[It's quoted]'`, models.TokenTypeSingleQuotedString, "It's quoted", 'q'},
		{"q-quote braces", keywords.DialectOracle, `q'{a}'`, models.TokenTypeSingleQuotedString, "a", 'q'},
		{"q-quote parens", keywords.DialectOracle, `Q'(b)'`, models.TokenTypeSingleQuotedString, "b", 'q'},
		{"q-quote angle", keywords.DialectOracle, `q'<c>'`, models.TokenTypeSingleQuotedString, "c", 'q'},
		{"q-quote custom delimiter", keywords.DialectOracle, `q'!d]'e!'`, models.TokenTypeSingleQuotedString, "d]'e", 'q'},
		{"q-quote with closer inside", keywords.DialectOracle, `q'[a]b]'`, models.TokenTypeSingleQuotedString, "a]b", 'q'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz, _ := NewWithDialect(tt.dialect)
			tokens, err := tkz.TokenizeString(tt.sql)
			if err != nil {
				t.Fatal(err)
			}
			if len(tokens) != 2 { // literal + EOF
				t.Fatalf("got %d tokens, want 1: %v", len(tokens)-1, tokens)
			}
			tok := tokens[0].Token
			if tok.Type != tt.typ || tok.Value != tt.value || tok.Quote != tt.quote {
				t.Errorf("got {%s %q %q}, want {%s %q %q}", tok.Type, tok.Value, tok.Quote, tt.typ, tt.value, tt.quote)
			}
			if tokens[0].End.Column != len(tt.sql)+1 {
				t.Errorf("end column %d, want %d", tokens[0].End.Column, len(tt.sql)+1)
			}
		})
	}
}

// TestLexPrefixLettersOutsideTheirDialect checks that a letter before a quote
// is an introducer only where the dialect has it.
func TestLexPrefixLettersOutsideTheirDialect(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectMySQL, `E'x'`},
		{keywords.DialectOracle, `X'4D'`},
		{keywords.DialectOracle, `E'x'`},
		{keywords.DialectPostgreSQL, `q'[x]'`},
		{keywords.DialectMySQL, `q'[x]'`},
		{keywords.DialectSQLite, `N'x'`},
		{keywords.DialectSQLite, `b'1'`},
		{keywords.DialectClickHouse, `X'4D'`},
	}
	for _, tt := range tests {
		got := lexAll(t, tt.dialect, tt.sql)
		if len(got) != 2 || got[0].typ != models.TokenTypeIdentifier {
			t.Errorf("%s %q: got %v, want identifier then string", tt.dialect, tt.sql, got)
		}
	}
}

func TestLexQQuoteEdgeCases(t *testing.T) {
	tkz, _ := NewWithDialect(keywords.DialectOracle)
	if _, err := tkz.TokenizeString(`SELECT q'[never closed' FROM dual`); err == nil {
		t.Error("unterminated q-quote: expected an error")
	}
	// q followed by a quote and a blank is the word q and a plain string.
	got := lexAll(t, keywords.DialectOracle, `q' x'`)
	if len(got) != 2 || got[0].typ != models.TokenTypeIdentifier || got[1].typ != models.TokenTypeSingleQuotedString {
		t.Errorf("q' x': got %v", got)
	}
	pg, _ := NewWithDialect(keywords.DialectPostgreSQL)
	if _, err := pg.TokenizeString(`E'abc\`); err == nil {
		t.Error("unterminated E-string: expected an error")
	}
}

func TestLexLeadingBOM(t *testing.T) {
	tkz, _ := NewWithDialect(keywords.DialectPostgreSQL)
	for _, api := range []string{"Tokenize", "TokenizeString"} {
		sql := "\xEF\xBB\xBFSELECT 1"
		var tokens []models.TokenWithSpan
		var err error
		if api == "Tokenize" {
			tokens, err = tkz.Tokenize([]byte(sql))
		} else {
			tokens, err = tkz.TokenizeString(sql)
		}
		if err != nil {
			t.Fatalf("%s: %v", api, err)
		}
		if len(tokens) != 3 || tokens[0].Token.Type != models.TokenTypeSelect {
			t.Fatalf("%s: tokens %v", api, tokens)
		}
		if tokens[0].Start != (models.Location{Line: 1, Column: 1}) {
			t.Errorf("%s: SELECT starts at %+v, want 1:1", api, tokens[0].Start)
		}
		if tokens[1].Start != (models.Location{Line: 1, Column: 8}) {
			t.Errorf("%s: number starts at %+v, want 1:8", api, tokens[1].Start)
		}
	}
	// A BOM-only input is empty; a BOM later in the text is still an error.
	if tokens, err := tkz.TokenizeString("\xEF\xBB\xBF"); err != nil || len(tokens) != 1 {
		t.Errorf("BOM only: tokens %v, err %v", tokens, err)
	}
	if _, err := tkz.TokenizeString("SELECT \xEF\xBB\xBF1"); err == nil {
		t.Error("BOM in the middle of the text: expected an error")
	}
}
