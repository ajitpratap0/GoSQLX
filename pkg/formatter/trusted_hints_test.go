// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
	"github.com/ajitpratap0/GoSQLX/pkg/transform"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTrustedHintsMatchWalk(t *testing.T) {
	for _, item := range goldens.Corpus(t) {
		tree, mask, valid, err := renderhint.SourceParse(item.SQL, item.Dialect)
		if err != nil {
			continue
		}
		for _, target := range []string{"postgresql", "mysql", "sqlite", "sqlserver", "oracle", "snowflake", "clickhouse", "mariadb", "generic"} {
			for _, opts := range []ast.FormatOptions{ast.CompactStyle(), ast.ReadableStyle()} {
				opts.Dialect = target
				got, gotErr := renderhint.FormatAST(tree, mask, valid, opts)
				want, wantErr := formatter.FormatASTChecked(tree, opts)
				if got != want || (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
					t.Fatalf("%s %d %s: trusted %q %v, walk %q %v", item.File, item.Index, target, got, gotErr, want, wantErr)
				}
				for i, stmt := range tree.Statements {
					got, gotErr = renderhint.FormatStatement(tree, i, mask, valid, opts)
					want, wantErr = formatter.FormatStatementChecked(stmt, opts)
					if got != want || (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
						t.Fatalf("%s %d %s statement %d: trusted %q %v, walk %q %v", item.File, item.Index, target, i, got, gotErr, want, wantErr)
					}
				}
			}
		}
		ast.ReleaseAST(tree)
	}
}

func TestPublicFormatIgnoresStaleHints(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT a", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	source, err := gosqlx.ParseWithDialect("SELECT a ^ b", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(source)
	target, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("unexpected statement %T", tree.Statements[0])
	}
	from, ok := source.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("unexpected statement %T", source.Statements[0])
	}
	target.Columns[0] = from.Columns[0]
	opts := ast.CompactStyle()
	opts.Dialect = "mysql"
	got, err := formatter.FormatASTChecked(tree, opts)
	if err != nil {
		t.Fatal(err)
	}
	want, err := formatter.FormatASTChecked(source, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("mutated tree = %q, fresh tree = %q", got, want)
	}
}

// Replacing only the internal hooks lets the complete formatSQL pipeline run
// with the same parse and comment handling while forcing the exact walk.
func TestTrustedFormatSQLMatchesForcedWalk(t *testing.T) {
	astHook, statementHook := renderhint.FormatAST, renderhint.FormatStatement
	defer func() { renderhint.FormatAST, renderhint.FormatStatement = astHook, statementHook }()
	for _, item := range goldens.Corpus(t) {
		for _, comments := range []bool{false, true} {
			sql := item.SQL
			if comments {
				sql = "-- leading comment\n" + sql + "\n-- trailing comment"
			}
			for _, indent := range []int{0, 2} {
				opts := gosqlx.DefaultFormatOptions()
				opts.IndentSize = indent
				renderhint.FormatAST, renderhint.FormatStatement = astHook, statementHook
				got, gotErr := gosqlx.FormatWithDialect(sql, opts, keywords.SQLDialect(item.Dialect))
				renderhint.FormatAST = func(tree any, mask uint64, valid bool, options any) (string, error) {
					return astHook(tree, mask, false, options)
				}
				renderhint.FormatStatement = func(tree any, index int, mask uint64, valid bool, options any) (string, error) {
					return statementHook(tree, index, mask, false, options)
				}
				want, wantErr := gosqlx.FormatWithDialect(sql, opts, keywords.SQLDialect(item.Dialect))
				if got != want || !equalRenderErrors(gotErr, wantErr) {
					t.Fatalf("%s %d comments=%v indent=%d: trusted %q %v; walk %q %v", item.File, item.Index, comments, indent, got, gotErr, want, wantErr)
				}
			}
		}
	}
}

func equalRenderErrors(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return got.Error() == want.Error()
}

func TestTrustedOracleUsesItsOwnMask(t *testing.T) {
	p := parser.GetParser()
	tk, err := tokenizer.New()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tk.Tokenize([]byte("SELECT a; SELECT b"))
	if err != nil {
		t.Fatal(err)
	}
	clean, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatal(err)
	}
	ast.ReleaseAST(clean)
	parser.PutParser(p)
	sql := ""
	for _, candidate := range []string{"SELECT CAST(a AS `MyType`) FROM dual", "SELECT CAST(a AS [MyType]) FROM dual", "SELECT ~a FROM dual", "SELECT |/ a FROM dual"} {
		tree, _, _, err := renderhint.SourceParse(candidate, "oracle")
		if err != nil {
			continue
		}
		dirty := formatter.NeedsDialectRewriteForTest(tree.Statements[0], "oracle")
		ast.ReleaseAST(tree)
		if dirty {
			sql = candidate
			break
		}
	}
	if sql == "" {
		t.Fatal("no Oracle parse requiring target rewrite")
	}
	opts := gosqlx.DefaultFormatOptions()
	got, gotErr := gosqlx.FormatWithDialect(sql, opts, keywords.DialectOracle)
	hook := renderhint.FormatAST
	defer func() { renderhint.FormatAST = hook }()
	renderhint.FormatAST = func(tree any, mask uint64, valid bool, options any) (string, error) {
		return hook(tree, mask, false, options)
	}
	want, wantErr := gosqlx.FormatWithDialect(sql, opts, keywords.DialectOracle)
	if gotErr != nil || wantErr != nil {
		t.Fatalf("Oracle case must parse and render: %v / %v", gotErr, wantErr)
	}
	if got != want {
		t.Fatalf("Oracle reused another parser's clean mask: trusted %q; walk %q", got, want)
	}
}

func TestPublicFormattingAfterTransform(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT a", keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	condition := &ast.BinaryExpression{Left: &ast.Identifier{Name: "a"}, Operator: "^", Right: &ast.Identifier{Name: "b"}}
	if err := transform.Apply(tree.Statements[0], transform.AddWhere(condition)); err != nil {
		t.Fatal(err)
	}
	fresh := &ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "a"}}, Where: condition}
	opts := ast.CompactStyle()
	opts.Dialect = "mysql"
	want, err := formatter.FormatStatementChecked(fresh, opts)
	if err != nil {
		t.Fatal(err)
	}
	for name, render := range map[string]func() (string, error){
		"ASTChecked":       func() (string, error) { return formatter.FormatASTChecked(tree, opts) },
		"StatementChecked": func() (string, error) { return formatter.FormatStatementChecked(tree.Statements[0], opts) },
		"AST":              func() (string, error) { return formatter.FormatAST(tree, opts), nil },
		"Statement":        func() (string, error) { return formatter.FormatStatement(tree.Statements[0], opts), nil },
		"transform": func() (string, error) {
			return transform.FormatSQLWithDialectChecked(tree.Statements[0], keywords.DialectMySQL)
		},
	} {
		got, err := render()
		if err != nil || got != want {
			t.Errorf("%s after transform = %q %v, want %q", name, got, err, want)
		}
	}
	wantExpr, err := formatter.FormatExpressionChecked(condition, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got := formatter.FormatExpression(condition, opts); got != wantExpr {
		t.Errorf("expression = %q, want %q", got, wantExpr)
	}
}

// Tree.Format has no target option and transpiler accepts source text, so neither
// can consume a caller's parse mask. Sentinel hooks enforce that boundary while
// exercising the mutations these APIs do expose.
func TestPublicTreeAndTranspilerIgnoreTrustedHints(t *testing.T) {
	astHook, statementHook := renderhint.FormatAST, renderhint.FormatStatement
	defer func() { renderhint.FormatAST, renderhint.FormatStatement = astHook, statementHook }()
	usedTrusted := false
	renderhint.FormatAST = func(any, uint64, bool, any) (string, error) {
		usedTrusted = true
		return "", fmt.Errorf("unexpected trusted AST formatting")
	}
	renderhint.FormatStatement = func(any, int, uint64, bool, any) (string, error) {
		usedTrusted = true
		return "", fmt.Errorf("unexpected trusted statement formatting")
	}
	for _, mutation := range []string{"hand", "transform"} {
		t.Run("Tree/"+mutation, func(t *testing.T) {
			tree, err := gosqlx.ParseTree(context.Background(), "SELECT a")
			if err != nil {
				t.Fatal(err)
			}
			defer tree.Release()
			expression := &ast.BinaryExpression{Left: &ast.Identifier{Name: "a"}, Operator: "^", Right: &ast.Identifier{Name: "b"}}
			if mutation == "hand" {
				stmt, ok := tree.Raw().Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("unexpected statement %T", tree.Raw().Statements[0])
				}
				stmt.Columns[0] = expression
			} else if err := transform.Apply(tree.Raw().Statements[0], transform.AddWhere(expression)); err != nil {
				t.Fatal(err)
			}
			opts := ast.CompactStyle()
			want, err := formatter.FormatASTChecked(tree.Raw(), opts)
			if err != nil {
				t.Fatal(err)
			}
			for name, render := range map[string]func() (string, error){
				"Tree.Format":        func() (string, error) { return tree.Format(gosqlx.WithIndent(0)), nil },
				"Tree.FormatChecked": func() (string, error) { return tree.FormatChecked(gosqlx.WithIndent(0)) },
				"FormatTree":         func() (string, error) { return gosqlx.FormatTree(tree, gosqlx.WithIndent(0)), nil },
				"FormatTreeChecked":  func() (string, error) { return gosqlx.FormatTreeChecked(tree, gosqlx.WithIndent(0)) },
				"FormatAST":          func() (string, error) { return gosqlx.FormatAST(tree.Raw(), gosqlx.WithIndent(0)), nil },
				"FormatASTChecked":   func() (string, error) { return gosqlx.FormatASTChecked(tree.Raw(), gosqlx.WithIndent(0)) },
			} {
				got, err := render()
				if err != nil || got != want {
					t.Errorf("%s: %q %v, want %q", name, got, err, want)
				}
			}
		})
	}
	// Transpiler's public API exposes SQL, with its own rules mutating the parsed
	// AST. Include a clean statement before a dirty one to exercise mask alignment.
	for _, sql := range []string{"SELECT a ILIKE b", "SELECT a; SELECT a ^ b"} {
		got, err := transpiler.Transpile(sql, keywords.DialectPostgreSQL, keywords.DialectMySQL)
		if err != nil {
			t.Fatalf("transpile %q: %v", sql, err)
		}
		if sql == "SELECT a ILIKE b" && got != "SELECT LOWER(a) LIKE LOWER(b)" {
			t.Errorf("ILIKE rule mutation = %q", got)
		}
		if sql == "SELECT a; SELECT a ^ b" && got != "SELECT a;\nSELECT POWER(a, b)" {
			t.Errorf("power rule mutation = %q", got)
		}
	}
	if usedTrusted {
		t.Fatal("public Tree/transpiler formatting invoked trusted mask hooks")
	}
}
