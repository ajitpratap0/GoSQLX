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

package parser

import (
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestStringAndBytesEntryPointsAgree checks that the string entry points,
// which tokenize the caller's string in place into the tokenizer's scratch
// buffer, report exactly what their []byte counterparts report.
func TestStringAndBytesEntryPointsAgree(t *testing.T) {
	inputs := []string{
		"SELECT id, name FROM users WHERE active = true",
		"",
		" \t\r\n ",
		"\v",
		"SELECT 'unterminated",
		"SELECT FROM",
		"SELECT `a` FROM `t` LIMIT 5",
		"-- only a comment",
		"SELECT 1; SELECT 2",
	}
	errText := func(err error) string {
		if err == nil {
			return "<nil>"
		}
		return err.Error()
	}
	astText := func(tree *ast.AST) string {
		if tree == nil {
			return "<nil>"
		}
		defer ast.ReleaseAST(tree)
		out := ""
		for _, s := range tree.Statements {
			out += fmt.Sprintf("%T|", s)
		}
		return out
	}
	for _, sql := range inputs {
		t.Run(fmt.Sprintf("%q", sql), func(t *testing.T) {
			if got, want := errText(Validate(sql)), errText(ValidateBytes([]byte(sql))); got != want {
				t.Errorf("Validate = %s, ValidateBytes = %s", got, want)
			}
			for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
				if got, want := errText(ValidateWithDialect(sql, d)), errText(ValidateBytesWithDialect([]byte(sql), d)); got != want {
					t.Errorf("%s: ValidateWithDialect = %s, ValidateBytesWithDialect = %s", d, got, want)
				}
				st, serr := ParseWithDialect(sql, d)
				bt, berr := ParseBytesWithDialect([]byte(sql), d)
				if got, want := errText(serr), errText(berr); got != want {
					t.Errorf("%s: ParseWithDialect err = %s, ParseBytesWithDialect err = %s", d, got, want)
				}
				if got, want := astText(st), astText(bt); got != want {
					t.Errorf("%s: ParseWithDialect = %s, ParseBytesWithDialect = %s", d, got, want)
				}
			}
		})
	}
}

// TestParseWithDialect_ASTOutlivesTokenizerReuse checks that an AST built
// from the tokenizer's scratch tokens stays intact after the pooled
// tokenizer and parser are reused for other input.
func TestParseWithDialect_ASTOutlivesTokenizerReuse(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"postgres", keywords.DialectPostgreSQL, `SELECT "Mixed", b AS x FROM s."T" t JOIN u ON t.id = u.id WHERE c > 1`},
		{"mysql", keywords.DialectMySQL, "SELECT `col`, COUNT(*) FROM `db`.`tbl` GROUP BY `col` LIMIT 3"},
		{"sqlserver", keywords.DialectSQLServer, "SELECT TOP 2 [a b], c FROM dbo.t ORDER BY c DESC"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatalf("ParseWithDialect: %v", err)
			}
			defer ast.ReleaseAST(tree)
			sqler, ok := tree.Statements[0].(interface{ SQL() string })
			if !ok {
				t.Fatalf("%T has no SQL method", tree.Statements[0])
			}
			want := sqler.SQL()
			for i := 0; i < 50; i++ {
				other := fmt.Sprintf("SELECT zz%d, yy FROM qq%d WHERE ww = 'v%d'", i, i, i)
				if err := Validate(other); err != nil {
					t.Fatalf("Validate(%q): %v", other, err)
				}
				o, err := ParseBytesWithDialect([]byte(other), tc.dialect)
				if err != nil {
					t.Fatalf("ParseBytesWithDialect(%q): %v", other, err)
				}
				ast.ReleaseAST(o)
			}
			if got := sqler.SQL(); got != want {
				t.Errorf("AST changed after tokenizer reuse:\n got %s\nwant %s", got, want)
			}
		})
	}
}
