// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package linter_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// The probe makes token and AST semantics observable even when the built-in
// rules happen to produce the same violations for two different parse trees.
type poolContextRule struct{ linter.BaseRule }

func (r poolContextRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	b, err := json.Marshal(struct {
		Tokens []models.TokenWithSpan
		AST    any
	}{ctx.Tokens, ctx.AST})
	if err != nil {
		return nil, err
	}
	return []linter.Violation{{Rule: r.ID(), Message: string(b)}}, nil
}

func (r poolContextRule) Fix(s string, _ []linter.Violation) (string, error) { return s, nil }

func poolRules() []linter.Rule {
	return append(benchRules(), poolContextRule{linter.NewBaseRule("POOL", "Context", "Observe pipeline semantics", linter.SeverityInfo, false)})
}

// freshLint deliberately uses no tokenizer or parser pool. Default/Unknown
// means no parser dialect option, matching the public low-level contract.
func freshLint(t *testing.T, sql, filename string, d keywords.SQLDialect, rules []linter.Rule) linter.FileResult {
	t.Helper()
	r := linter.FileResult{Filename: filename, Violations: []linter.Violation{}}
	ctx := linter.NewContext(sql, filename)
	tkz, err := tokenizer.NewWithDialect(d)
	if err != nil {
		t.Fatal(err)
	}
	var opts []parser.ParserOption
	if d != "" && d != keywords.DialectUnknown {
		opts = append(opts, parser.WithDialect(string(d)))
	}
	p := parser.NewParser(opts...)
	defer p.Release()
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		r.TokenizeError = err
	} else {
		ctx.WithTokens(tokens)
		for _, tok := range tokens {
			if tok.Token.Type != models.TokenTypeEOF {
				tree, parseErr := p.ParseFromModelTokens(tokens)
				defer ast.ReleaseAST(tree)
				ctx.WithAST(tree, parseErr)
				r.ParseError = parseErr
				break
			}
		}
	}
	for _, rule := range rules {
		v, err := rule.Check(ctx)
		if err != nil {
			r.Error = fmt.Errorf("rule %s failed: %w", rule.ID(), err)
			return r
		}
		r.Violations = append(r.Violations, v...)
	}
	return r
}

func equalPoolError(t *testing.T, name string, got, want error) bool {
	t.Helper() // Safe from worker goroutines: reports with Errorf, never Fatalf.
	if fmt.Sprint(got) != fmt.Sprint(want) || (got == nil) != (want == nil) {
		t.Errorf("%s: got %v, want %v", name, got, want)
		return false
	}
	var ge, we *sqlerrors.Error
	ga, wa := errors.As(got, &ge), errors.As(want, &we)
	if ga != wa || (ga && !reflect.DeepEqual(ge, we)) {
		t.Errorf("%s: structured errors differ: got %#v, want %#v", name, ge, we)
		return false
	}
	for _, sentinel := range []error{gosqlx.ErrSyntax, gosqlx.ErrTokenize, gosqlx.ErrUnsupportedDialect} {
		if errors.Is(got, sentinel) != errors.Is(want, sentinel) {
			t.Errorf("%s: errors.Is(%v) differs", name, sentinel)
			return false
		}
	}
	return true
}

func equalPoolResult(t *testing.T, got, want linter.FileResult) bool {
	t.Helper() // Safe from worker goroutines: reports with Errorf, never Fatalf.
	if got.Filename != want.Filename || !reflect.DeepEqual(got.Violations, want.Violations) {
		t.Errorf("FileResult differs\n got %#v\nwant %#v", got, want)
		return false
	}
	return equalPoolError(t, "Error", got.Error, want.Error) &&
		equalPoolError(t, "TokenizeError", got.TokenizeError, want.TokenizeError) &&
		equalPoolError(t, "ParseError", got.ParseError, want.ParseError)
}

func poolEdges() []string {
	return []string{
		"", " \t\n", "-- comment only\n/* block */", "SELECT 'unterminated", "SELECT FROM",
		"SELECT 1; SELECT FROM", "SELECT 1; SELECT 'unterminated",
		"SELECT (1, 2), ARRAY[1,2]", `SELECT "naïve" FROM "café" WHERE x != 3 AND y <= 7`,
		"SELECT 42, NULL, TRUE, 'text'; SELECT a FROM t WHERE a <> 1",
		"SELECT * FROM users WHERE id = ?", "SELECT TOP 2 [name] FROM [users]",
		"SELECT 'a' || 'b' FROM users", `SELECT 'a\'b' FROM users`,
		"SELECT * EXCEPT (secret) FROM users QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1",
		"SELECT * FROM users ORDER BY id LIMIT 2 BY name", "SELECT * FROM users FINAL",
		"SELECT NVL(name, 'x') FROM users FETCH FIRST 2 ROWS ONLY",
		"SELECT name::VARCHAR FROM users QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1",
		"SELECT * FROM users DISTSTYLE EVEN", "SELECT $1 FROM users", "SELECT :name FROM dual",
	}
}

func poolDialects() []keywords.SQLDialect {
	return append(keywords.AllDialects(), "", keywords.DialectUnknown, "nosuchdialect")
}

func TestLintPoolDifferential(t *testing.T) {
	inputs := poolEdges()
	for _, d := range rwDialects(t) {
		inputs = append(inputs, rwSQL(t, d)...)
	}
	rules := poolRules()
	for _, d := range poolDialects() {
		t.Run(string(d), func(t *testing.T) {
			l := linter.New(rules...)
			l.SetDialect(d)
			for i, sql := range inputs {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					equalPoolResult(t, l.LintString(sql, "pool.sql"), freshLint(t, sql, "pool.sql", d, rules))
				})
			}
		})
	}
}

func TestLintPoolContamination(t *testing.T) {
	rules := poolRules()
	l := linter.New(rules...)
	for round := 0; round < 3; round++ {
		for _, d := range poolDialects() {
			for _, sql := range poolEdges() {
				// Exercise both pools through unrelated callers, including strict,
				// dialect and operator options that must reset at the boundary.
				tkz := tokenizer.GetTokenizer()
				tkz.SetDialect(keywords.DialectMySQL)
				_, _ = tkz.TokenizeString("SELECT 'a\\'b'")
				tokenizer.PutTokenizer(tkz)
				p := parser.GetParser()
				p.ApplyOptions(parser.WithDialect("mysql"), parser.WithStrictMode(), parser.WithPipesAsConcat())
				parser.PutParser(p)
				tree, _ := gosqlx.ParseWithDialect("SELECT TOP 1 [id] FROM [users]", keywords.DialectSQLServer)
				ast.ReleaseAST(tree)
				l.SetDialect(d)
				equalPoolResult(t, l.LintString(sql, "pool.sql"), freshLint(t, sql, "pool.sql", d, rules))
			}
		}
	}
}

type poolCheckRule struct {
	linter.BaseRule
	check func(*linter.Context) ([]linter.Violation, error)
}

func (r poolCheckRule) Check(ctx *linter.Context) ([]linter.Violation, error) { return r.check(ctx) }
func (r poolCheckRule) Fix(s string, _ []linter.Violation) (string, error)    { return s, nil }

func TestLintPoolRuleErrorReturnsEarly(t *testing.T) {
	sentinel := errors.New("rule stopped")
	laterCalls := 0
	rules := []linter.Rule{
		poolContextRule{linter.NewBaseRule("FIRST", "First", "", linter.SeverityInfo, false)},
		poolCheckRule{linter.NewBaseRule("FAIL", "Fail", "", linter.SeverityInfo, false), func(ctx *linter.Context) ([]linter.Violation, error) {
			if ctx.Filename == "fail.sql" {
				return []linter.Violation{{Rule: "DISCARDED"}}, sentinel
			}
			return nil, nil
		}},
		poolCheckRule{linter.NewBaseRule("LAST", "Last", "", linter.SeverityInfo, false), func(_ *linter.Context) ([]linter.Violation, error) {
			laterCalls++
			return nil, nil
		}},
	}
	l := linter.New(rules...)
	l.SetDialect(keywords.DialectMySQL)
	got := l.LintString("SELECT * FROM users WHERE id = ?", "fail.sql")
	if !errors.Is(got.Error, sentinel) || got.Error.Error() != "rule FAIL failed: rule stopped" || len(got.Violations) != 1 || got.Violations[0].Rule != "FIRST" || laterCalls != 0 {
		t.Fatalf("early return changed: %#v; later calls %d", got, laterCalls)
	}
	want := freshLint(t, "SELECT * FROM users WHERE id = ?", "ok.sql", keywords.DialectMySQL, rules)
	equalPoolResult(t, l.LintString("SELECT * FROM users WHERE id = ?", "ok.sql"), want)
}

func TestLintPoolConcurrent(t *testing.T) {
	type input struct {
		sql   string
		d     keywords.SQLDialect
		l     *linter.Linter
		want  linter.FileResult
		probe linter.FileResult
	}
	var inputs []input
	rules := append(poolRules(), lifetimeRule("SUMMARY", lifetimeSummary))
	for _, d := range poolDialects() {
		l := linter.New(rules...)
		l.SetDialect(d) // Publish immutable linters before starting workers.
		for _, sql := range poolEdges() {
			inputs = append(inputs, input{sql, d, l, freshLint(t, sql, "<input>", d, benchRules()), freshLint(t, sql, "<input>", d, rules)})
		}
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for round := 0; round < 3; round++ {
				for offset := range inputs {
					in := inputs[(offset+worker)%len(inputs)]
					if !equalPoolResult(t, in.l.LintString(in.sql, "<input>"), in.probe) {
						return
					}
					if in.d == keywords.DialectUnknown || in.d == "nosuchdialect" {
						continue // Only the low-level API accepts these dialects.
					}
					got, err := gosqlx.LintWithDialect(in.sql, in.d)
					if got == nil || !reflect.DeepEqual(got.Violations, in.want.Violations) {
						t.Errorf("public lint %q/%q: got %#v, want %#v", in.d, in.sql, got, in.want)
						return
					}
					if errors.Is(err, gosqlx.ErrTokenize) != (in.want.TokenizeError != nil) || errors.Is(err, gosqlx.ErrSyntax) != (in.want.TokenizeError == nil && in.want.ParseError != nil) || (err == nil) != (in.want.SyntaxError() == nil) {
						t.Errorf("public lint syntax %q/%q: %v; want %v", in.d, in.sql, err, in.want.SyntaxError())
					}
				}
			}
		}(worker)
	}
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				tree, err := gosqlx.Parse("SELECT id FROM users WHERE id = 1")
				if err != nil {
					t.Error(err)
				}
				ast.ReleaseAST(tree)
				tree, err = gosqlx.ParseWithDialect("SELECT TOP 1 [id] FROM [users]", keywords.DialectSQLServer)
				if err != nil {
					t.Error(err)
				}
				ast.ReleaseAST(tree)
				if _, err := fingerprint.Normalize("SELECT id FROM users WHERE id = 2"); err != nil {
					t.Error(err)
				}
				if _, err := gosqlx.Format("SELECT id FROM users", gosqlx.DefaultFormatOptions()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
