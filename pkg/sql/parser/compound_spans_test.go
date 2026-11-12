// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func compoundTokens(t *testing.T, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatal(err)
	}
	return toks
}

func compoundError(t *testing.T, err error, column int, message, hint string) {
	t.Helper()
	var se *sqlerrors.Error
	if !errors.As(err, &se) {
		t.Fatalf("want structured error, got %T: %v", err, err)
	}
	line := 1
	if column == 0 {
		line = 0
	}
	if se.Location != (models.Location{Line: line, Column: column}) || se.Message != message || se.Hint != hint || se.Code != sqlerrors.ErrCodeExpectedToken {
		t.Errorf("error = code %s, location %+v, message %q, hint %q; want E2002 at %d:%d, %q, %q", se.Code, se.Location, se.Message, se.Hint, line, column, message, hint)
	}
}

func TestCompoundSpansErrorEntryPoints(t *testing.T) {
	for _, tc := range []struct {
		sql           string
		column        int
		message, hint string
	}{
		{"INSERT INTO t (group by) VALUES (1)", 22, "expected ), got BY", "expected ) here"},
		{"UPDATE t SET order by = 1", 20, "expected =, got BY", "expected = here"},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			ctx := context.Background()
			calls := map[string]func() error{
				"parser bytes":          func() error { a, e := parser.ParseBytes([]byte(tc.sql)); ast.ReleaseAST(a); return e },
				"parser validate":       func() error { return parser.Validate(tc.sql) },
				"parser validate bytes": func() error { return parser.ValidateBytes([]byte(tc.sql)) },
				"parser tokens on failure": func() error {
					a, toks, e := parser.ParseBytesWithTokens([]byte(tc.sql))
					ast.ReleaseAST(a)
					if toks != nil {
						t.Error("failed parse returned tokens")
					}
					return e
				},
				"gosqlx string":   func() error { a, e := gosqlx.Parse(tc.sql); ast.ReleaseAST(a); return e },
				"gosqlx bytes":    func() error { a, e := gosqlx.ParseBytes([]byte(tc.sql)); ast.ReleaseAST(a); return e },
				"gosqlx context":  func() error { a, e := gosqlx.ParseWithContext(ctx, tc.sql); ast.ReleaseAST(a); return e },
				"gosqlx timeout":  func() error { a, e := gosqlx.ParseWithTimeout(tc.sql, time.Second); ast.ReleaseAST(a); return e },
				"gosqlx validate": func() error { return gosqlx.Validate(tc.sql) },
				"gosqlx tree": func() error {
					a, e := gosqlx.ParseTree(ctx, tc.sql)
					if a != nil {
						a.Release()
					}
					return e
				},
				"gosqlx reader": func() error {
					a, e := gosqlx.ParseReader(ctx, strings.NewReader(tc.sql))
					if a != nil {
						a.Release()
					}
					return e
				},
			}
			for name, call := range calls {
				t.Run(name, func(t *testing.T) { compoundError(t, call(), tc.column, tc.message, tc.hint) })
			}
			toks := compoundTokens(t, tc.sql)
			for _, name := range []string{"model", "model positions alias", "model context", "preprocessed positions"} {
				t.Run(name, func(t *testing.T) {
					p := parser.NewParser()
					defer p.Release()
					var a *ast.AST
					var e error
					switch name {
					case "model":
						a, e = p.ParseFromModelTokens(toks)
					case "model positions alias":
						a, e = p.ParseFromModelTokensWithPositions(toks)
					case "model context":
						a, e = p.ParseContextFromModelTokens(ctx, toks)
					default:
						a, e = p.ParseWithPositions(&parser.ConversionResult{Tokens: parser.PreprocessTokens(toks)})
					}
					ast.ReleaseAST(a)
					compoundError(t, e, tc.column, tc.message, tc.hint)
				})
			}
			for _, d := range keywords.AllDialects() {
				t.Run(string(d), func(t *testing.T) {
					modelCalls := []func(*parser.Parser) (*ast.AST, error){
						func(p *parser.Parser) (*ast.AST, error) { return p.ParseFromModelTokens(toks) },
						func(p *parser.Parser) (*ast.AST, error) { return p.ParseFromModelTokensWithPositions(toks) },
						func(p *parser.Parser) (*ast.AST, error) { return p.ParseContextFromModelTokens(ctx, toks) },
						func(p *parser.Parser) (*ast.AST, error) {
							return p.ParseWithPositions(&parser.ConversionResult{Tokens: parser.PreprocessTokens(toks)})
						},
					}
					for _, call := range modelCalls {
						p := parser.NewParser(parser.WithDialect(string(d)))
						a, e := call(p)
						ast.ReleaseAST(a)
						p.Release()
						compoundError(t, e, tc.column, tc.message, tc.hint)
					}
					calls := []func() error{
						func() error { a, e := parser.ParseWithDialect(tc.sql, d); ast.ReleaseAST(a); return e },
						func() error { a, e := parser.ParseBytesWithDialect([]byte(tc.sql), d); ast.ReleaseAST(a); return e },
						func() error { return parser.ValidateWithDialect(tc.sql, d) },
						func() error { return parser.ValidateBytesWithDialect([]byte(tc.sql), d) },
						func() error { a, e := gosqlx.ParseWithDialect(tc.sql, d); ast.ReleaseAST(a); return e },
					}
					for _, call := range calls {
						compoundError(t, call(), tc.column, tc.message, tc.hint)
					}
				})
			}
			legacy := make([]token.Token, len(toks))
			for i, tok := range toks {
				legacy[i] = token.Token{Type: tok.Token.Type, Literal: tok.Token.Value}
			}
			for _, withContext := range []bool{false, true} {
				p := parser.NewParser()
				var a *ast.AST
				var e error
				if withContext {
					a, e = p.ParseContext(ctx, legacy)
				} else {
					a, e = p.Parse(legacy)
				}
				ast.ReleaseAST(a)
				p.Release()
				compoundError(t, e, 0, tc.message, tc.hint)
			}
		})
	}
}

func TestCompoundSpansReturnedTokens(t *testing.T) {
	for _, tc := range []struct {
		name, sql                  string
		start, end, byStart, byEnd models.Location
	}{
		{"space", "SELECT a FROM t GROUP BY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 1, Column: 23}, models.Location{Line: 1, Column: 25}},
		{"wide", "SELECT a FROM t GROUP   BY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 1, Column: 25}, models.Location{Line: 1, Column: 27}},
		{"tab", "SELECT a FROM t GROUP\tBY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 1, Column: 23}, models.Location{Line: 1, Column: 25}},
		{"LF", "SELECT a FROM t GROUP\n  BY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 2, Column: 3}, models.Location{Line: 2, Column: 5}},
		{"CRLF", "SELECT a FROM t GROUP\r\n  BY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 2, Column: 3}, models.Location{Line: 2, Column: 5}},
		{"BOM", "\ufeffSELECT a FROM t GROUP BY a", models.Location{Line: 1, Column: 17}, models.Location{Line: 1, Column: 22}, models.Location{Line: 1, Column: 23}, models.Location{Line: 1, Column: 25}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := compoundTokens(t, tc.sql)
			found := false
			for _, tok := range raw {
				if tok.Token.Value == "GROUP BY" {
					found = true
					if tok.Start != tc.start || tok.End != tc.byEnd {
						t.Errorf("public tokenizer compound span changed: %+v", tok)
					}
				}
			}
			if !found {
				t.Fatal("public tokenizer did not retain merged compound")
			}
			a, toks, e := parser.ParseBytesWithTokens([]byte(tc.sql))
			if e != nil {
				t.Fatal(e)
			}
			ast.ReleaseAST(a)
			found = false
			for i, tok := range toks {
				if tok.Token.Value == "GROUP" {
					found = true
					if tok.Start != tc.start || tok.End != tc.end || i+1 >= len(toks) {
						t.Fatalf("GROUP span = %+v", tok)
					}
					by := toks[i+1]
					if by.Token.Value != "BY" || by.Start != tc.byStart || by.End != tc.byEnd {
						t.Errorf("BY span = %+v", by)
					}
				}
			}
			if !found {
				t.Fatal("no GROUP")
			}
			saved := append([]models.TokenWithSpan(nil), toks...)
			p := parser.NewParser()
			defer p.Release()
			a, e = p.ParseWithPositions(&parser.ConversionResult{Tokens: toks})
			if e != nil {
				t.Fatal(e)
			}
			ast.ReleaseAST(a)
			for i := 0; i < 3; i++ {
				a, _, e = parser.ParseBytesWithTokens([]byte("SELECT b FROM other ORDER BY b"))
				if e != nil {
					t.Fatal(e)
				}
				ast.ReleaseAST(a)
			}
			if !reflect.DeepEqual(saved, toks) {
				t.Error("owned returned tokens changed after tokenizer/parser reuse")
			}
		})
	}
}

func TestCompoundSpansLookalikesAndComments(t *testing.T) {
	for _, sql := range []string{"SELECT 'GROUP BY'", `SELECT "group by" FROM t`, "SELECT a FROM t GROUP/* comment */BY a"} {
		raw := compoundTokens(t, sql)
		for _, tok := range raw {
			if tok.Token.Type == models.TokenTypeGroupBy {
				t.Errorf("unexpected compound in %q: %+v", sql, tok)
			}
		}
		a, e := parser.ParseBytes([]byte(sql))
		if e != nil {
			t.Errorf("parse %q: %v", sql, e)
		}
		ast.ReleaseAST(a)
	}
}

func TestCompoundSpansUtility(t *testing.T) {
	for _, tc := range []struct {
		sql, want  string
		dialect    keywords.SQLDialect
		statements int
	}{
		{"GRANT SELECT ON t TO GROUP by", "GRANT SELECT ON t TO GROUP BY", keywords.DialectPostgreSQL, 1},
		{"GRANT SELECT ON t TO GROUP by; SELECT 2", "GRANT SELECT ON t TO GROUP BY", keywords.DialectPostgreSQL, 2},
		{"REVOKE SELECT ON t FROM GROUP by", "REVOKE SELECT ON t FROM GROUP BY", keywords.DialectPostgreSQL, 1},
		{`GRANT SELECT ON t TO GROUP "by"`, `GRANT SELECT ON t TO GROUP "by"`, keywords.DialectPostgreSQL, 1},
		{"PREPARE s AS SELECT a FROM t GROUP\n BY a; SELECT 2", "PREPARE s AS SELECT a FROM t GROUP BY a", keywords.DialectPostgreSQL, 2},
		{`PREPARE s AS SELECT "group by" FROM t ORDER BY a; SELECT 2`, `PREPARE s AS SELECT "group by" FROM t ORDER BY a`, keywords.DialectPostgreSQL, 2},
		{"ALTER TABLE t ORDER BY a, b DESC", "", keywords.DialectMySQL, 1},
	} {
		t.Run(tc.sql, func(t *testing.T) {
			a, e := parser.ParseWithDialect(tc.sql, tc.dialect)
			if e != nil {
				t.Fatal(e)
			}
			defer ast.ReleaseAST(a)
			if len(a.Statements) != tc.statements {
				t.Fatalf("statements = %d", len(a.Statements))
			}
			if tc.want != "" {
				u, ok := a.Statements[0].(*ast.UtilityStatement)
				if !ok {
					t.Fatalf("statement = %T", a.Statements[0])
				}
				if u.Text != tc.want {
					t.Errorf("reconstructed text %q, want %q", u.Text, tc.want)
				}
				if u.Pos != (models.Location{Line: 1, Column: 1}) {
					t.Errorf("utility position = %+v", u.Pos)
				}
			}
		})
	}
}
