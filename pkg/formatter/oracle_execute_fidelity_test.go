package formatter_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestOracleExecuteSlashFidelity(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{
		{"block", "BEGIN\n  NULL;\nEND;\n/\nSELECT 1 FROM dual;\n/", "BEGIN NULL; END;\n/\nSELECT 1\nFROM dual\n/"},
		{"queries", "SELECT 1 FROM dual\n/\nSELECT 2 FROM dual\n/\n", "SELECT 1\nFROM dual\n/\nSELECT 2\nFROM dual\n/"},
		{"package", "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END p;\n/\nSELECT 1 FROM dual\n/", "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END p;\n/\nSELECT 1\nFROM dual\n/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.input, keywords.DialectOracle)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			if len(tree.Statements) != 2 || len(tree.StatementStarts) != 2 || !reflect.DeepEqual(tree.ExecuteSlash, []bool{true, true}) {
				t.Fatalf("unexpected statements/starts/slashes: %d/%d/%v", len(tree.Statements), len(tree.StatementStarts), tree.ExecuteSlash)
			}
			for _, semicolon := range []bool{false, true} {
				opts := ast.ReadableStyle()
				opts.AddSemicolon = semicolon
				if got := formatter.FormatAST(tree, opts); got != tc.want {
					t.Errorf("FormatAST semicolon=%v:\ngot %q\nwant %q", semicolon, got, tc.want)
				}
			}
			for name, format := range map[string]func(string) (string, error){
				"Formatter": formatter.New(formatter.Options{Dialect: "oracle", Uppercase: true}).Format,
				"FormatWithDialect": func(s string) (string, error) {
					return gosqlx.FormatWithDialect(s, gosqlx.DefaultFormatOptions(), keywords.DialectOracle)
				},
				"FormatWithDialectSemicolon": func(s string) (string, error) {
					opts := gosqlx.DefaultFormatOptions()
					opts.AddSemicolon = true
					return gosqlx.FormatWithDialect(s, opts, keywords.DialectOracle)
				},
			} {
				got, err := format(tc.input)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if got != tc.want {
					t.Errorf("%s:\ngot %q\nwant %q", name, got, tc.want)
				}
				again, err := format(got)
				if err != nil || again != got {
					t.Errorf("%s not idempotent: %q %v", name, again, err)
				}
				reparsed, err := gosqlx.ParseWithDialect(got, keywords.DialectOracle)
				if err != nil {
					t.Fatal(err)
				}
				if len(reparsed.Statements) != 2 || !reflect.DeepEqual(reparsed.ExecuteSlash, tree.ExecuteSlash) {
					t.Errorf("%s reparsed metadata: %d %v", name, len(reparsed.Statements), reparsed.ExecuteSlash)
				}
				ast.ReleaseAST(reparsed)
			}
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(keywords.DialectOracle)
			tokens, err := tkz.TokenizeString(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			p := parser.GetParser()
			defer parser.PutParser(p)
			p.ApplyOptions(parser.WithDialect("oracle"), parser.WithStrictMode())
			tokenTree, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tokenTree)
			if !reflect.DeepEqual(tokenTree.ExecuteSlash, []bool{true, true}) {
				t.Errorf("token-only marks = %v", tokenTree.ExecuteSlash)
			}
		})
	}
}

func TestOracleExecuteSlashMetadataReset(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT 1 FROM dual\n/\nSELECT 2 FROM dual", keywords.DialectOracle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tree.ExecuteSlash, []bool{true, false}) {
		t.Fatalf("marks = %v", tree.ExecuteSlash)
	}
	ast.ReleaseAST(tree)
	if tree.ExecuteSlash != nil {
		t.Fatalf("release retained slash metadata: %v", tree.ExecuteSlash)
	}
	plain, err := gosqlx.Parse("SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(plain)
	if plain.ExecuteSlash != nil {
		t.Errorf("plain SQL has metadata: %v", plain.ExecuteSlash)
	}
}

func TestOracleExecuteSlashCommentFidelity(t *testing.T) {
	const input = "SELECT 1 FROM dual -- query\n-- before slash\n/\n-- after slash\nSELECT 2 FROM dual\n/\n-- after last\n"
	const want = "SELECT 1\nFROM dual -- query\n-- before slash\n/\n-- after slash\nSELECT 2\nFROM dual\n/\n-- after last"
	tree, err := gosqlx.ParseWithDialect(input, keywords.DialectOracle)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(keywords.DialectOracle)
	if _, err := tkz.TokenizeString(input); err != nil {
		t.Fatal(err)
	}
	tree.Comments = append(tree.Comments, tkz.Comments...)
	if got := formatter.FormatAST(tree, ast.ReadableStyle()); got != want {
		t.Errorf("FormatAST comments:\ngot %q\nwant %q", got, want)
	}
	for name, format := range map[string]func(string) (string, error){
		"Formatter": formatter.New(formatter.Options{Dialect: "oracle", Uppercase: true}).Format,
		"FormatWithDialect": func(s string) (string, error) {
			return gosqlx.FormatWithDialect(s, gosqlx.DefaultFormatOptions(), keywords.DialectOracle)
		},
	} {
		got, err := format(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Errorf("%s:\ngot %q\nwant %q", name, got, want)
		}
	}
}
