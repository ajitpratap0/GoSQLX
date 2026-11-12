// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package linter_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/config"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func lifetimeMetrics(t *testing.T) {
	t.Helper()
	enabled := metrics.IsEnabled()
	metrics.Enable()
	t.Cleanup(func() {
		if !enabled {
			metrics.Disable()
		}
	})
}

func lifetimeBalanced(t *testing.T, before map[string]metrics.PoolStat, wantAST int64) {
	t.Helper()
	after := metrics.GetPoolStats()
	for _, name := range []string{"ast", "parser", "tokenizer"} {
		gets, puts := after[name].Gets-before[name].Gets, after[name].Puts-before[name].Puts
		want := int64(1)
		if name == "ast" {
			want = wantAST
		}
		if gets != want || puts != gets {
			t.Errorf("%s gets/puts = %d/%d, want %d/%d", name, gets, puts, want, want)
		}
	}
}

func lifetimeRule(id string, check func(*linter.Context) ([]linter.Violation, error)) linter.Rule {
	return poolCheckRule{linter.NewBaseRule(id, id, "", linter.SeverityInfo, false), check}
}

func TestLintLifetimeUniversal(t *testing.T) {
	lifetimeMetrics(t)
	for _, sql := range []string{"SELECT id FROM users", "SELECT id FROM users; SELECT name FROM users"} {
		var before map[string]metrics.PoolStat
		calls := 0
		probe := lifetimeRule("LIVE", func(ctx *linter.Context) ([]linter.Violation, error) {
			calls++
			now := metrics.GetPoolStats()
			if now["ast"].Puts != before["ast"].Puts || now["parser"].Puts != before["parser"].Puts || now["tokenizer"].Puts != before["tokenizer"].Puts {
				t.Error("resources returned before Check finished")
			}
			if ctx.AST == nil || len(ctx.AST.Statements) == 0 || len(ctx.Tokens) == 0 || len(ctx.Nodes()) == 0 {
				t.Error("missing live resources")
			}
			if _, err := json.Marshal(ctx.AST); err != nil {
				t.Error(err)
			}
			for _, tok := range ctx.Tokens {
				if tok.Token.Word != nil && tok.Token.Word.Value == "" {
					t.Error("cleared Word")
				}
			}
			return nil, nil
		})
		cfg := &config.Config{DefaultSeverity: "error"}
		sets := []struct {
			name  string
			rules []linter.Rule
		}{
			{"builtins", benchRules()}, {"custom", []linter.Rule{probe, probe}},
			{"configured", cfg.Apply([]linter.Rule{probe})}, {"subset", benchRules()[:1]}, {"empty", nil},
		}
		for _, set := range sets {
			t.Run(set.name+"/"+sql, func(t *testing.T) {
				before = metrics.GetPoolStats()
				got := linter.New(set.rules...).LintString(sql, "live.sql")
				if got.Error != nil || got.SyntaxError() != nil {
					t.Fatalf("unexpected error: %#v", got)
				}
				lifetimeBalanced(t, before, 1)
			})
		}
		if calls != 3 {
			t.Fatalf("Check calls = %d, want 3", calls)
		}
	}
}

func TestLintLifetimeExits(t *testing.T) {
	lifetimeMetrics(t)
	stop := errors.New("stopped")
	for _, tc := range []struct {
		name, sql string
		ast       int64
		mode      string
	}{
		{"valid", "SELECT id FROM users", 1, ""}, {"multi", "SELECT 1; SELECT 2", 1, ""},
		{"empty", "", 0, ""}, {"whitespace", " \n\t", 0, ""}, {"comments", "-- comment\n/* block */", 0, ""},
		{"tokenize", "SELECT id FROM users; SELECT 'unterminated", 0, "tokenize"},
		{"parse", "SELECT id FROM users; SELECT FROM", 1, "parse"},
		{"rule-error", "SELECT id FROM users", 1, "error"}, {"panic", "SELECT id FROM users", 1, "panic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			later := 0
			rules := []linter.Rule{
				lifetimeRule("FIRST", func(ctx *linter.Context) ([]linter.Violation, error) {
					if tc.mode == "tokenize" && (ctx.Tokens != nil || ctx.AST != nil) {
						t.Error("tokenizer failure exposed resources")
					}
					if tc.mode == "parse" && (ctx.AST != nil || len(ctx.Tokens) == 0 || ctx.ParseErr == nil) {
						t.Error("parse failure changed context")
					}
					return []linter.Violation{{Rule: "FIRST", Message: ctx.SQL}}, nil
				}),
				lifetimeRule("STOP", func(*linter.Context) ([]linter.Violation, error) {
					if tc.mode == "error" {
						return []linter.Violation{{Rule: "DISCARD"}}, stop
					}
					if tc.mode == "panic" {
						panic(stop)
					}
					return nil, nil
				}),
				lifetimeRule("LAST", func(*linter.Context) ([]linter.Violation, error) { later++; return nil, nil }),
			}
			l := linter.New(rules...)
			before := metrics.GetPoolStats()
			var got linter.FileResult
			func() {
				if tc.mode == "panic" {
					defer func() {
						if recover() != stop {
							t.Error("panic was changed or suppressed")
						}
					}()
				}
				got = l.LintString(tc.sql, "exit.sql")
			}()
			lifetimeBalanced(t, before, tc.ast)
			if tc.mode == "panic" || tc.mode == "error" {
				if later != 0 {
					t.Error("later Check executed")
				}
			} else if later != 1 {
				t.Error("later Check skipped")
			}
			if tc.mode != "panic" {
				if len(got.Violations) != 1 || got.Violations[0].Rule != "FIRST" {
					t.Error("partial violations changed")
				}
				if tc.mode == "error" && (!errors.Is(got.Error, stop) || got.Error.Error() != "rule STOP failed: stopped") {
					t.Errorf("error changed: %v", got.Error)
				}
				if (got.TokenizeError != nil) != (tc.mode == "tokenize") || (got.ParseError != nil) != (tc.mode == "parse") {
					t.Errorf("syntax errors changed: %#v", got)
				}
			}
			// The next call must start clean, including after panic unwinding.
			clean := linter.New(poolRules()...).LintString("SELECT id FROM users", "clean.sql")
			equalPoolResult(t, clean, freshLint(t, "SELECT id FROM users", "clean.sql", keywords.DialectUnknown, poolRules()))
		})
	}
}

// Materialize all summaries while Check owns the borrow. The goroutine joins
// before Check returns; only serialized strings and value locations escape.
func lifetimeSummary(ctx *linter.Context) ([]linter.Violation, error) {
	var wg sync.WaitGroup
	var message string
	var err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		var parts []string
		for _, tok := range ctx.Tokens {
			parts = append(parts, fmt.Sprintf("%v:%s", tok.Token.Type, tok.Token.Value))
			if word := tok.Token.Word; word != nil {
				parts = append(parts, word.Value, fmt.Sprint(word.QuoteStyle))
				if word.Keyword != nil {
					parts = append(parts, fmt.Sprint(*word.Keyword))
				}
			}
		}
		for _, node := range ctx.Nodes() {
			parts = append(parts, fmt.Sprintf("%T:%s", node, node.TokenLiteral()))
		}
		var b []byte
		b, err = json.Marshal(ctx.AST)
		message = strings.Join(parts, "|") + string(b)
	}()
	// Exercise concurrent Nodes cache readers without modifying the Context.
	_ = ctx.Nodes()
	wg.Wait()
	var location models.Location
	if len(ctx.Tokens) > 0 {
		location = ctx.Tokens[0].Start
	}
	return []linter.Violation{{Rule: "SUMMARY", Message: message, Location: location}}, err
}

func TestLintLifetimeSnapshots(t *testing.T) {
	rules := append(benchRules(), lifetimeRule("SUMMARY", lifetimeSummary))
	l := linter.New(rules...)
	saved := l.LintString("SELECT id, 'abc', 42 FROM users WHERE id != 3", "snapshot.sql")
	before, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve independent structured error snapshots as well as Error() text.
	var failures []linter.FileResult
	var texts []string
	var jsonErrors [][]byte
	for _, sql := range []string{"SELECT 1; SELECT FROM", "SELECT 1; SELECT 'unterminated"} {
		r := linter.New().LintString(sql, "bad.sql")
		if r.SyntaxError() == nil {
			t.Fatal("expected syntax error")
		}
		var structured *sqlerrors.Error
		if !errors.As(r.SyntaxError(), &structured) {
			t.Fatalf("expected structured syntax error, got %T", r.SyntaxError())
		}
		failures = append(failures, r)
		texts = append(texts, r.SyntaxError().Error())
		b, e := json.Marshal(r.SyntaxError())
		if e != nil {
			t.Fatal(e)
		}
		jsonErrors = append(jsonErrors, b)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				for _, sql := range []string{"SELECT (1, 2), ARRAY[1,2]", "SELECT \"naïve\" FROM \"table\" WHERE x <> 3", "SELECT " + strings.Repeat("column_name,", 120) + "last_column FROM users"} {
					_ = l.LintString(sql, "churn.sql")
					tree, err := gosqlx.Parse(sql)
					if err != nil {
						t.Error(err)
					}
					ast.ReleaseAST(tree)
					if _, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions()); err != nil {
						t.Error(err)
					}
					if _, err := fingerprint.Normalize(sql); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	after, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("saved FileResult/violations/JSON changed")
	}
	for i, r := range failures {
		b, e := json.Marshal(r.SyntaxError())
		if e != nil {
			t.Fatal(e)
		}
		if texts[i] != r.SyntaxError().Error() || !reflect.DeepEqual(b, jsonErrors[i]) {
			t.Error("saved structured syntax error changed")
		}
	}
}

func TestLintLifetimeScratchAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation comparison excludes race instrumentation")
	}
	sql := "SELECT " + strings.Repeat("identifier,", 120) + "last_identifier FROM users"
	l := linter.New()
	l.SetDialect(keywords.DialectPostgreSQL)
	reference := func() {
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		p := parser.GetParser()
		defer parser.PutParser(p)
		tkz.SetDialect(keywords.DialectPostgreSQL)
		p.ApplyOptions(parser.WithDialect("postgresql"))
		tokens, err := tkz.TokenizeString(sql)
		if err != nil {
			panic(err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			panic(err)
		}
		defer ast.ReleaseAST(tree)
	}
	candidate := func() {
		r := l.LintString(sql, "alloc.sql")
		if r.Error != nil || r.SyntaxError() != nil {
			panic("unexpected lint failure")
		}
	}
	got, want := testing.AllocsPerRun(100, candidate), testing.AllocsPerRun(100, reference)
	if got >= want {
		t.Fatalf("scratch lint allocations %.0f must be less than owned-token reference %.0f", got, want)
	}
	t.Logf("scratch lint %.0f allocs; owned-token reference %.0f", got, want)
}
