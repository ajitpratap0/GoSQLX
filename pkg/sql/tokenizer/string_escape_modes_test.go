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

// firstString tokenizes sql and returns the first string-like token.
func firstString(t *testing.T, tkz *Tokenizer, sql string) (models.Token, error) {
	t.Helper()
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return models.Token{}, err
	}
	for _, tw := range tokens {
		switch tw.Token.Type {
		case models.TokenTypeSingleQuotedString, models.TokenTypeNationalStringLiteral,
			models.TokenTypeHexStringLiteral, models.TokenTypeByteStringLiteral,
			models.TokenTypeEscapedStringLiteral:
			return tw.Token, nil
		}
	}
	t.Fatalf("no string token in %q", sql)
	return models.Token{}, nil
}

// TestStringEscapeModes pins how every dialect reads a backslash inside a
// single-quoted string: PostgreSQL standard strings, Oracle, SQLite, SQL Server
// and generic keep it, MySQL/MariaDB decode escapes (\% and \_ keep their
// backslash, other escaped characters stand for themselves), the remaining
// dialects decode escapes; ClickHouse keeps the backslash of unknown ones and
// Snowflake drops it. See string_escape_strict_test.go for the unconfigured
// tokenizer.
func TestStringEscapeModes(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
		want    string
	}{
		{"postgresql keeps backslash", keywords.DialectPostgreSQL, `SELECT 'a\b'`, `a\b`},
		{"postgresql regex", keywords.DialectPostgreSQL, `SELECT 'x\.y'`, `x\.y`},
		{"postgresql backslash before quote closes", keywords.DialectPostgreSQL, `SELECT '\'`, `\`},
		{"postgresql doubled quote", keywords.DialectPostgreSQL, `SELECT 'it''s'`, `it's`},
		{"oracle keeps backslash", keywords.DialectOracle, `SELECT 'a\b' FROM dual`, `a\b`},
		{"sqlite keeps backslash", keywords.DialectSQLite, `SELECT 'C:\dir\n'`, `C:\dir\n`},
		{"sqlserver keeps backslash", keywords.DialectSQLServer, `SELECT 'a\nb'`, `a\nb`},
		{"generic keeps backslash", keywords.DialectGeneric, `SELECT 'a\nb'`, `a\nb`},

		{"mysql newline escape", keywords.DialectMySQL, `SELECT 'a\nb'`, "a\nb"},
		{"mysql escaped backslash", keywords.DialectMySQL, `SELECT 'a\\b'`, `a\b`},
		{"mysql escaped quote", keywords.DialectMySQL, `SELECT 'it\'s'`, `it's`},
		{"mysql like percent keeps backslash", keywords.DialectMySQL, `SELECT '50\%'`, `50\%`},
		{"mysql like underscore keeps backslash", keywords.DialectMySQL, `SELECT '\_x'`, `\_x`},
		{"mysql unknown escape drops backslash", keywords.DialectMySQL, `SELECT 'a\qb'`, `aqb`},
		{"mysql NUL escape", keywords.DialectMySQL, `SELECT 'a\0b'`, "a\x00b"},
		{"mysql backspace escape", keywords.DialectMySQL, `SELECT 'a\bb'`, "a\bb"},
		{"mysql ctrl-z escape", keywords.DialectMySQL, `SELECT 'a\Zb'`, "a\x1ab"},
		{"mariadb like percent", keywords.DialectMariaDB, `SELECT '50\%'`, `50\%`},

		{"clickhouse escaped quote", keywords.DialectClickHouse, `SELECT 'a\'b'`, `a'b`},
		{"clickhouse unknown escape keeps backslash", keywords.DialectClickHouse, `SELECT 'x\.y'`, `x\.y`},
		{"clickhouse escaped backslash", keywords.DialectClickHouse, `SELECT 'a\\b'`, `a\b`},
		{"snowflake escaped quote", keywords.DialectSnowflake, `SELECT 'a\'b'`, `a'b`},
		{"snowflake tab escape", keywords.DialectSnowflake, `SELECT 'a\tb'`, "a\tb"},
		{"snowflake unknown escape drops backslash", keywords.DialectSnowflake, `SELECT '\d+'`, `d+`},

		{"unconfigured tokenizer decodes", "", `SELECT 'a\nb'`, "a\nb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tkz *Tokenizer
			if tt.dialect == "" {
				tkz, _ = New()
			} else {
				tkz, _ = NewWithDialect(tt.dialect)
			}
			for _, api := range []string{"Tokenize", "TokenizeString"} {
				var tok models.Token
				var err error
				if api == "Tokenize" {
					tokens, e := tkz.Tokenize([]byte(tt.sql))
					err = e
					for _, tw := range tokens {
						if tw.Token.Type == models.TokenTypeSingleQuotedString {
							tok = tw.Token
							break
						}
					}
				} else {
					tok, err = firstString(t, tkz, tt.sql)
				}
				if err != nil {
					t.Fatalf("%s(%q): %v", api, tt.sql, err)
				}
				if tok.Value != tt.want {
					t.Errorf("%s(%q) value = %q, want %q", api, tt.sql, tok.Value, tt.want)
				}
			}
		})
	}
}

// TestStringEscapeMultiLineEscape checks line tracking when a backslash
// escapes a line break.
func TestStringEscapeMultiLineEscape(t *testing.T) {
	tkz, _ := NewWithDialect(keywords.DialectMySQL)
	tokens, err := tkz.TokenizeString("SELECT 'a\\\nb', 1")
	if err != nil {
		t.Fatal(err)
	}
	last := tokens[len(tokens)-2] // the number 1
	if last.Token.Value != "1" || last.Start.Line != 2 {
		t.Errorf("token after escaped newline: value %q at line %d, want 1 at line 2", last.Token.Value, last.Start.Line)
	}
}

// TestStringEscapeUnterminated checks that a backslash before the closing
// quote leaves a string unterminated only where the backslash escapes.
func TestStringEscapeUnterminated(t *testing.T) {
	tests := []struct {
		dialect keywords.SQLDialect
		sql     string
		wantErr bool
	}{
		{keywords.DialectMySQL, `SELECT 'a\'`, true},
		{keywords.DialectClickHouse, `SELECT 'a\'`, true},
		{keywords.DialectPostgreSQL, `SELECT 'a\'`, false},
		{keywords.DialectOracle, `SELECT 'a\'`, false},
		{keywords.DialectSQLite, `SELECT 'a\'`, false},
		{keywords.DialectMySQL, `SELECT 'a\`, true},
	}
	for _, tt := range tests {
		tkz, _ := NewWithDialect(tt.dialect)
		_, err := tkz.TokenizeString(tt.sql)
		if (err != nil) != tt.wantErr {
			t.Errorf("%s %q: err = %v, wantErr %v", tt.dialect, tt.sql, err, tt.wantErr)
		}
	}
}

// TestStringEscapePoolReset checks that a pooled tokenizer does not carry a
// dialect's escape rules to the next user.
func TestStringEscapePoolReset(t *testing.T) {
	tkz := GetTokenizer()
	tkz.SetDialect(keywords.DialectPostgreSQL)
	PutTokenizer(tkz)

	tkz = GetTokenizer()
	defer PutTokenizer(tkz)
	tok, err := firstString(t, tkz, `SELECT 'a\nb'`)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Value != "a\nb" {
		t.Errorf("pooled tokenizer kept PostgreSQL escape rules: value %q", tok.Value)
	}
}
