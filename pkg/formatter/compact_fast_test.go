// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestCompactFastOptions(t *testing.T) {
	queries := []string{
		"SELECT id FROM users WHERE active = 1",
		"SELECT id FROM users ORDER BY id LIMIT 5 OFFSET 2",
		"INSERT INTO users (id) VALUES (1)",
		"UPDATE users SET active = 0 WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"SELECT 1 UNION SELECT 2",
		"ALTER TABLE users ADD COLUMN a INT, ADD COLUMN b INT",
	}
	options := []struct {
		name   string
		change func(*ast.FormatOptions)
	}{
		{"preserve", func(o *ast.FormatOptions) {}},
		{"upper", func(o *ast.FormatOptions) { o.KeywordCase = ast.KeywordUpper }},
		{"lower", func(o *ast.FormatOptions) { o.KeywordCase = ast.KeywordLower }},
		{"spaces", func(o *ast.FormatOptions) { o.IndentWidth = 4 }},
		{"tabs", func(o *ast.FormatOptions) { o.IndentStyle = ast.IndentTabs; o.IndentWidth = 2 }},
		{"semicolon", func(o *ast.FormatOptions) { o.AddSemicolon = true }},
		{"readable", func(o *ast.FormatOptions) { *o = ast.ReadableStyle() }},
		{"newline_per_clause", func(o *ast.FormatOptions) { o.NewlinePerClause = true }},
		{"line_width", func(o *ast.FormatOptions) { o.LineWidth = 80 }},
		{"postgresql", func(o *ast.FormatOptions) { o.Dialect = "postgresql" }},
		{"mysql", func(o *ast.FormatOptions) { o.Dialect = "mysql" }},
		{"sqlserver", func(o *ast.FormatOptions) { o.Dialect = "sqlserver" }},
	}
	for _, query := range queries {
		tree, err := parser.ParseBytesWithDialect([]byte(query), "generic")
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range options {
			t.Run(query+"/"+tc.name, func(t *testing.T) {
				opts := ast.CompactStyle()
				tc.change(&opts)
				prepared, err := prepareDialectNode(tree, opts.Dialect)
				if err != nil {
					t.Fatal(err)
				}
				a, ok := prepared.(*ast.AST)
				if !ok {
					t.Fatalf("unexpected AST %T", prepared)
				}
				stmt := a.Statements[0]
				want := formatStatementSlow(stmt, opts)
				if got := formatStatement(stmt, opts); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
				want = RestoreUnicodeIdentifiers(a, 0, want, opts.Dialect)
				want = EnsureStatementTerminator(stmt, want, opts.AddSemicolon)
				if got := FormatAST(tree, opts); got != want {
					t.Fatalf("AST got %q, want %q", got, want)
				}
			})
		}
		ast.ReleaseAST(tree)
	}
}

func TestCompactFastUnicode(t *testing.T) {
	tree, err := parser.ParseBytesWithDialect([]byte(`SELECT U&"d\0061t" FROM U&"t\0061ble"`), "postgresql")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	opts := ast.CompactStyle()
	want := RestoreUnicodeIdentifiers(tree, 0, formatStatementSlow(tree.Statements[0], opts), "")
	if got := FormatAST(tree, opts); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if want != `SELECT U&"d\0061t" FROM U&"t\0061ble"` {
		t.Fatalf("Unicode source spelling lost: %q", want)
	}
}

func TestCompactFastNil(t *testing.T) {
	for _, stmt := range []ast.Statement{nil, (*ast.SelectStatement)(nil), (*ast.InsertStatement)(nil), (*ast.UpdateStatement)(nil), (*ast.DeleteStatement)(nil)} {
		if got := formatStatement(stmt, ast.CompactStyle()); got != "" {
			t.Fatalf("%T: got %q", stmt, got)
		}
	}
}

// TestCompactFastFormatASTSingleStatement guards the single-statement shortcut
// in formatAST with exact expectations: the execute slash and the statement
// terminator must survive it.
func TestCompactFastFormatASTSingleStatement(t *testing.T) {
	cases := []struct {
		name, dialect, sql string
		semicolon          bool
		want               string
	}{
		{"oracle select slash", "oracle", "SELECT 1 FROM dual\n/", false, "SELECT 1 FROM dual\n/"},
		{"oracle select slash semicolon", "oracle", "SELECT 1 FROM dual\n/", true, "SELECT 1 FROM dual\n/"},
		{"oracle plsql slash", "oracle", "BEGIN NULL; END;\n/", false, "BEGIN NULL; END;\n/"},
		{"oracle plsql slash semicolon", "oracle", "BEGIN NULL; END;\n/", true, "BEGIN NULL; END;\n/"},
		{"mysql show tables", "mysql", "SHOW TABLES", true, "SHOW TABLES;"},
		{"postgresql vacuum", "postgresql", "VACUUM", true, "VACUUM;"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := parser.ParseBytesWithDialect([]byte(tc.sql), keywords.SQLDialect(tc.dialect))
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			opts := ast.CompactStyle()
			opts.AddSemicolon = tc.semicolon
			if got := FormatAST(tree, opts); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCompactFastFormatASTHandBuiltComments reaches the Comments guard, which
// parsed trees never do because they carry StatementEnds.
func TestCompactFastFormatASTHandBuiltComments(t *testing.T) {
	parsed, err := parser.ParseBytesWithDialect([]byte("SELECT 1"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(parsed)
	plain := FormatAST(parsed, ast.CompactStyle())

	withComment := &ast.AST{
		Statements: parsed.Statements,
		Comments:   []models.Comment{{Text: "-- note", Style: models.LineComment}},
	}
	got := FormatAST(withComment, ast.CompactStyle())
	if !strings.Contains(got, "-- note") || !strings.Contains(got, plain) {
		t.Fatalf("comment dropped or statement altered: got %q, plain %q", got, plain)
	}
}
