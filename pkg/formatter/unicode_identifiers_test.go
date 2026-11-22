// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestUnicodeIdentifierFormatting(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`SELECT U&"d\0061t\+000061" FROM t`, "SELECT U&\"d\\0061t\\+000061\"\nFROM t"},
		{`SELECT U&"d!0061ta" UESCAPE '!' FROM t`, "SELECT U&\"d!0061ta\" UESCAPE '!'\nFROM t"},
		{`SELECT U&"a\000Ab" FROM t`, "SELECT U&\"a\\000Ab\"\nFROM t"},
		{`SELECT U&"t\0031".U&"c\0031" FROM U&"t\0031" AS U&"x\0031"`, "SELECT U&\"t\\0031\".U&\"c\\0031\"\nFROM U&\"t\\0031\" U&\"x\\0031\""},
		{`SELECT "A", U&"\0041", U&"A", '"A"' FROM t`, "SELECT \"A\", U&\"\\0041\", U&\"A\", '\"A\"'\nFROM t"},
		{`SELECT data, U&"d\0061ta", "data", U&"data" FROM t`, "SELECT data, U&\"d\\0061ta\", data, U&\"data\"\nFROM t"},
		{`SELECT U&"select" FROM t`, "SELECT U&\"select\"\nFROM t"},
		{`SELECT U&"\0041" FROM t; SELECT U&"A" FROM t`, "SELECT U&\"\\0041\"\nFROM t;\nSELECT U&\"A\"\nFROM t"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, keywords.DialectPostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			readable := ast.ReadableStyle()
			readable.AddSemicolon = false
			got := formatter.FormatAST(tree, readable)
			if got != tc.want {
				t.Fatalf("FormatAST = %q, want %q", got, tc.want)
			}
			for _, lower := range []bool{false, true} {
				opts := readable
				want := tc.want
				if lower {
					opts.KeywordCase = ast.KeywordLower
					want = strings.ReplaceAll(strings.ReplaceAll(want, "SELECT ", "select "), "FROM ", "from ")
				}
				formatted := formatter.FormatAST(tree, opts)
				if formatted != want {
					t.Errorf("lower=%v: %q, want %q", lower, formatted, want)
				}
				reparsed, err := gosqlx.ParseWithDialect(formatted, keywords.DialectPostgreSQL)
				if err != nil {
					t.Fatalf("reparse: %v", err)
				}
				ast.ReleaseAST(reparsed)
			}
			got, err = gosqlx.FormatWithDialect(tc.input, gosqlx.DefaultFormatOptions(), keywords.DialectPostgreSQL)
			if err != nil || got != tc.want {
				t.Errorf("FormatWithDialect = %q, %v, want %q", got, err, tc.want)
			}
			got, err = formatter.New(formatter.Options{Dialect: string(keywords.DialectPostgreSQL), Uppercase: true}).Format(tc.input)
			if err != nil || got != tc.want+";" {
				t.Errorf("Formatter = %q, %v, want %q", got, err, tc.want+";")
			}
		})
	}
}

func TestUnicodeIdentifierWithComment(t *testing.T) {
	input := "SELECT U&\"a\\000Ab\" FROM t -- tail\n"
	got, err := gosqlx.FormatWithDialect(input, gosqlx.DefaultFormatOptions(), keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	want := "SELECT U&\"a\\000Ab\"\nFROM t -- tail"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUnicodeIdentifierRestorationSkipsNonNames(t *testing.T) {
	tree := &ast.AST{UnicodeIdentifiers: map[int][]ast.UnicodeIdentifierSpelling{0: {{Name: "A", Spelling: `U&"\0041"`, Quoted: true}}}}
	for _, prefix := range []string{
		`'"A"'`, `E'\'"A"'`, `E'a''"A"'`, `$$"A"$$`, `$tag$"A"$tag$`,
		`/* "A" /* nested */ */`, "-- \"A\"\n",
	} {
		got := formatter.RestoreUnicodeIdentifiers(tree, 0, prefix+` "A"`, "postgresql")
		want := prefix + ` U&"\0041"`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestUnicodeIdentifierDecodedFields(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(`SELECT U&"t\0031".U&"c\0031" FROM U&"t\0031" AS U&"x\0031"`, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("statement %T", tree.Statements[0])
	}
	ident, ok := stmt.Columns[0].(*ast.Identifier)
	if !ok {
		t.Fatalf("column %T", stmt.Columns[0])
	}
	if ident.Name != "c1" || ident.Table != "t1" || stmt.From[0].Name != "t1" || stmt.From[0].Alias != "x1" {
		t.Fatalf("decoded fields: %#v %#v", ident, stmt.From[0])
	}
}

// U& is PostgreSQL syntax: other target dialects get the decoded name.
func TestUnicodeIdentifierSpellingOnlyForPostgresTargets(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect(`SELECT U&"d\0061ta" FROM U&"t\0061b"`, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	for dialect, want := range map[string]string{
		"":           `U&"d\0061ta"`,
		"postgresql": `U&"d\0061ta"`,
		"mysql":      "data",
		"sqlserver":  "data",
		"oracle":     "data",
		"sqlite":     "data",
	} {
		opts := ast.CompactStyle()
		opts.Dialect = dialect
		out, err := formatter.FormatASTChecked(tree, opts)
		if err != nil {
			t.Fatalf("%s: %v", dialect, err)
		}
		if !strings.Contains(out, want) || (dialect != "" && dialect != "postgresql" && strings.Contains(out, "U&")) {
			t.Errorf("%s: got %q, want it to contain %q", dialect, out, want)
		}
	}
}
