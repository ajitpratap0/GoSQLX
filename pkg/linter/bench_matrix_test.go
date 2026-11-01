// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package linter_test

// Lint benchmark matrix (PLAN.md 2.2, W0-06).
//
//	BenchmarkLintRW/<dialect>              gosqlx.LintWithDialect over the dialect's real-world statements
//	BenchmarkLintPhase/<phase>/<dialect>   phase in {tokenize, parse, rules}; the three approximately decompose LintRW
//	BenchmarkLintRule/L001..L030           one rule over the contexts of every dialect
//
// One benchmark op is one pass over the whole input set, so ns/op is
// comparable only between runs of the same corpus. The ns/stmt metric divides
// by the statement count. The package is linter_test (external) because
// internal/benchcorpus imports pkg/gosqlx, which imports pkg/linter.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	lintrules "github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/naming"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// benchRules mirrors the rule list of gosqlx.Lint (pkg/gosqlx/lint.go
// allRules), which is unexported. TestBenchRulesAreTheDefaultSet pins its
// id set to L001..L030 so a drift is caught here.
func benchRules() []linter.Rule {
	core := lintrules.DefaultCoreConfig()
	core.MaxLineLength = 120
	return append(lintrules.CoreRules(core),
		safety.NewDeleteWithoutWhereRule(),
		safety.NewUpdateWithoutWhereRule(),
		safety.NewDropWithoutConditionRule(),
		safety.NewTruncateTableRule(),
		safety.NewSelectIntoOutfileRule(),
		performance.NewSelectStarRule(),
		performance.NewMissingWhereRule(),
		performance.NewLeadingWildcardRule(),
		performance.NewNotInWithNullRule(),
		performance.NewSubqueryInSelectRule(),
		performance.NewOrInsteadOfInRule(),
		performance.NewFunctionOnColumnRule(),
		performance.NewImplicitCrossJoinRule(),
		naming.NewTableAliasRequiredRule(),
		naming.NewReservedKeywordIdentifierRule(),
		naming.NewImplicitColumnListRule(),
		naming.NewUnionAllPreferredRule(),
		naming.NewMissingOrderByLimitRule(),
		naming.NewSubqueryCanBeJoinRule(),
		naming.NewDistinctOnManyColumnsRule(),
	)
}

// rwDialects returns the dialects that have a real-world corpus, in
// benchcorpus.Dialects order.
func rwDialects(tb testing.TB) []string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	var out []string
	for _, d := range benchcorpus.Dialects() {
		if len(set.RealWorld(d)) > 0 {
			out = append(out, d)
		}
	}
	return out
}

// rwSQL returns the SQL text of the dialect's real-world statements below
// the Large bucket (a single statement of 64 KB or more would dominate).
func rwSQL(tb testing.TB, dialect string) []string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	var out []string
	for _, st := range set.RealWorld(dialect) {
		if st.Bucket != benchcorpus.Large {
			out = append(out, st.SQL)
		}
	}
	return out
}

func totalBytes(stmts []string) int64 {
	var n int64
	for _, s := range stmts {
		n += int64(len(s))
	}
	return n
}

func reportPerStmt(b *testing.B, n int) {
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(n), "ns/stmt")
}

// lintInput holds the tokens and tree of one statement, built outside the
// timed region. proto is a prepared Context that is never passed to a rule.
// scratch is the one Context handed to rules: reset overwrites it by value from
// proto, which allocates nothing (the scratch is heap-allocated once during
// setup, because rules take it through an interface) and clears any lazily
// cached state a rule or Context accessor filled in (for example a future
// Context.Nodes()), so that cost stays inside the timed region.
type lintInput struct {
	proto   *linter.Context
	scratch *linter.Context
}

// reset restores the scratch Context to the prepared one, with no state cached
// by earlier Check calls, and returns it. It does not allocate.
func (in lintInput) reset() *linter.Context {
	*in.scratch = *in.proto
	return in.scratch
}

// buildInputs tokenizes and parses each statement with the dialect the way
// Linter.LintString does, so the rules see the same Context.
func buildInputs(tb testing.TB, stmts []string, dialect string) []lintInput {
	tb.Helper()
	d := keywords.SQLDialect(dialect)
	out := make([]lintInput, 0, len(stmts))
	for _, s := range stmts {
		ctx := linter.NewContext(s, "<input>")
		tkz, err := tokenizer.NewWithDialect(d)
		if err != nil {
			tb.Fatalf("tokenizer.NewWithDialect(%q): %v", dialect, err)
		}
		toks, terr := tkz.TokenizeString(s)
		if terr == nil {
			ctx.WithTokens(toks)
			p := parser.NewParser(parser.WithDialect(dialect))
			tree, perr := p.ParseFromModelTokens(toks)
			ctx.WithAST(tree, perr)
		}
		out = append(out, lintInput{proto: ctx, scratch: new(linter.Context)})
	}
	return out
}

func BenchmarkLintRW(b *testing.B) {
	for _, d := range rwDialects(b) {
		stmts := rwSQL(b, d)
		b.Run(d, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(totalBytes(stmts))
			dialect := keywords.SQLDialect(d)
			for i := 0; i < b.N; i++ {
				for _, s := range stmts {
					// Invalid SQL still lints the text and token rules; the
					// error is expected for a few statements.
					_, _ = gosqlx.LintWithDialect(s, dialect)
				}
			}
			reportPerStmt(b, len(stmts))
		})
	}
}

func BenchmarkLintPhase(b *testing.B) {
	rules := benchRules()
	for _, d := range rwDialects(b) {
		stmts := rwSQL(b, d)
		dialect := keywords.SQLDialect(d)

		// Pre-tokenized input for the parse phase. Statements that fail to
		// tokenize are skipped there.
		var tokenized [][]models.TokenWithSpan
		for _, s := range stmts {
			tkz, err := tokenizer.NewWithDialect(dialect)
			if err != nil {
				b.Fatalf("tokenizer.NewWithDialect(%q): %v", d, err)
			}
			if toks, err := tkz.TokenizeString(s); err == nil {
				tokenized = append(tokenized, toks)
			}
		}
		inputs := buildInputs(b, stmts, d)

		b.Run("tokenize/"+d, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(totalBytes(stmts))
			for i := 0; i < b.N; i++ {
				for _, s := range stmts {
					tkz, err := tokenizer.NewWithDialect(dialect)
					if err != nil {
						b.Fatal(err)
					}
					_, _ = tkz.TokenizeString(s)
				}
			}
			reportPerStmt(b, len(stmts))
		})
		b.Run("parse/"+d, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, toks := range tokenized {
					p := parser.NewParser(parser.WithDialect(d))
					// Like Linter.LintString, the tree is not released.
					_, _ = p.ParseFromModelTokens(toks)
					p.Release()
				}
			}
			reportPerStmt(b, len(tokenized))
		})
		b.Run("rules/"+d, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, in := range inputs {
					// One Context per statement shared by all rules, like
					// Linter.LintString, so a cache filled by one rule is
					// visible to the next.
					c := in.reset()
					for _, r := range rules {
						_, _ = r.Check(c)
					}
				}
			}
			reportPerStmt(b, len(inputs))
		})
	}
}

// BenchmarkLintRule times each rule alone over the contexts of every dialect
// (built with that dialect), so a regression in one rule is not hidden in the
// 30-rule total.
func BenchmarkLintRule(b *testing.B) {
	var inputs []lintInput
	for _, d := range rwDialects(b) {
		inputs = append(inputs, buildInputs(b, rwSQL(b, d), d)...)
	}
	rules := benchRules()
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID() < rules[j].ID() })
	for _, r := range rules {
		b.Run(r.ID(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, in := range inputs {
					_, _ = r.Check(in.reset())
				}
			}
			reportPerStmt(b, len(inputs))
		})
	}
}

// TestLintContextHasNoCachedState pins the Context field set. The benchmarks
// check a by-value reset of a prepared Context per op, which is only valid while Context
// has no lazily filled cache. When a field such as a cached node list is added
// (PLAN W6-05) this fails: update lintInput.reset to clear it, then this list.
func TestLintContextHasNoCachedState(t *testing.T) {
	want := []string{"SQL", "Lines", "Tokens", "AST", "ParseErr", "Filename"}
	typ := reflect.TypeOf(linter.Context{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		got = append(got, typ.Field(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linter.Context fields = %v, want %v; clear any new cached field in lintInput.reset", got, want)
	}
}

func TestBenchRulesAreTheDefaultSet(t *testing.T) {
	rules := benchRules()
	if len(rules) != 30 {
		t.Fatalf("got %d rules, want 30", len(rules))
	}
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID()
	}
	sort.Strings(ids)
	for i, id := range ids {
		if want := fmt.Sprintf("L%03d", i+1); id != want {
			t.Errorf("sorted rule %d id = %s, want %s", i, id, want)
		}
	}
}

// TestBenchInputsAreMeaningful guards the benchmarks against measuring
// nothing: every dialect has statements, most of them tokenize and parse, and
// the rule benchmark inputs produce violations at all.
func TestBenchInputsAreMeaningful(t *testing.T) {
	dialects := rwDialects(t)
	if len(dialects) != 8 {
		t.Fatalf("real-world dialects = %v, want 8", dialects)
	}
	violations := 0
	for _, d := range dialects {
		stmts := rwSQL(t, d)
		if len(stmts) == 0 {
			t.Fatalf("%s: no statements", d)
		}
		inputs := buildInputs(t, stmts, d)
		parsed := 0
		for _, in := range inputs {
			if in.proto.AST != nil && in.proto.ParseErr == nil {
				parsed++
			}
			for _, r := range benchRules() {
				v, err := r.Check(in.reset())
				if err != nil {
					t.Fatalf("%s %s: %v", d, r.ID(), err)
				}
				violations += len(v)
			}
		}
		if parsed*2 < len(inputs) {
			t.Errorf("%s: only %d of %d statements parse", d, parsed, len(inputs))
		}
	}
	if violations == 0 {
		t.Error("no rule reported a violation on any benchmark input")
	}
}

// TestLintRWMatchesRuleSet pins the equivalence the phase split relies on:
// LintWithDialect reports exactly the violations obtained by running the
// benchRules over a context built the same way.
func TestLintRWMatchesRuleSet(t *testing.T) {
	for _, d := range []string{"postgresql", "mysql", "sqlserver"} {
		stmts := rwSQL(t, d)
		if len(stmts) > 60 {
			stmts = stmts[:60]
		}
		inputs := buildInputs(t, stmts, d)
		for i, s := range stmts {
			res, _ := gosqlx.LintWithDialect(s, keywords.SQLDialect(d))
			if res == nil {
				t.Fatalf("%s #%d: nil result", d, i)
			}
			var want []string
			for _, r := range benchRules() {
				v, err := r.Check(inputs[i].reset())
				if err != nil {
					t.Fatal(err)
				}
				for _, x := range v {
					want = append(want, fmt.Sprintf("%s@%d:%d", x.Rule, x.Location.Line, x.Location.Column))
				}
			}
			var got []string
			for _, x := range res.Violations {
				got = append(got, fmt.Sprintf("%s@%d:%d", x.Rule, x.Location.Line, x.Location.Column))
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("%s #%d: violations differ\n got %v\nwant %v", d, i, got, want)
			}
		}
	}
}

// TestBenchContextResetIsAllocFree guards the harness: resetting the scratch
// Context and running a cheap rule must not allocate, so the allocs/op and
// B/op of BenchmarkLintRule measure the rule and not the harness.
func TestBenchContextResetIsAllocFree(t *testing.T) {
	if testing.Short() {
		t.Skip("alloc counting under -short is skipped")
	}
	inputs := buildInputs(t, rwSQL(t, "postgresql"), "postgresql")
	if len(inputs) == 0 {
		t.Fatal("no inputs")
	}
	in := inputs[0]
	if n := testing.AllocsPerRun(100, func() { _ = in.reset() }); n != 0 {
		t.Errorf("reset allocs/op = %v, want 0", n)
	}
	for _, r := range benchRules() {
		if r.ID() != "L001" && r.ID() != "L015" {
			continue
		}
		// Use an input whose rule run yields no violations, so only the
		// harness could allocate.
		var quiet *lintInput
		for i := range inputs {
			if v, _ := r.Check(inputs[i].reset()); len(v) == 0 {
				quiet = &inputs[i]
				break
			}
		}
		if quiet == nil {
			continue
		}
		if n := testing.AllocsPerRun(100, func() { _, _ = r.Check(quiet.reset()) }); n != 0 {
			t.Errorf("%s reset+Check allocs/op = %v, want 0", r.ID(), n)
		}
	}
}
