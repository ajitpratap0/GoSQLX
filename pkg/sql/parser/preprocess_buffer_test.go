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

// Tests for the parser-owned preprocess buffer (issue #552): buffer reuse must
// never leak into caller-owned slices or previously returned ASTs, Reset must
// scrub and cap the buffer, and pooled parsers must stay race-free.

package parser

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

const (
	bufLongSQL = `SELECT u.id, u.name, o.total, COUNT(i.id) AS item_count FROM users u ` +
		`INNER JOIN orders o ON u.id = o.user_id LEFT JOIN items i ON i.order_id = o.id ` +
		`LEFT OUTER JOIN shipments s ON s.order_id = o.id WHERE u.active = true AND o.total > 100 ` +
		`GROUP BY u.id, u.name, o.total ORDER BY o.total DESC, u.name LIMIT 50`
	bufShortSQL  = `SELECT 1`
	bufInsertSQL = `INSERT INTO users (id, name, email) VALUES (1, 'alice', 'a@example.com')`
	bufUpdateSQL = `UPDATE users SET name = 'bob', active = false WHERE id = 42`
	bufDeleteSQL = `DELETE FROM orders WHERE total < 10 AND status = 'void'`
)

// tokenizeBuf tokenizes sql and returns a caller-owned copy of the tokens: the
// tokenizer's result must not be retained across PutTokenizer.
func tokenizeBuf(t testing.TB, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize %q: %v", sql, err)
	}
	return append([]models.TokenWithSpan(nil), toks...)
}

// freshParse parses toks on a brand-new parser and returns the rendered SQL and
// statement count, the reference every reused-parser result must match.
func freshParse(t testing.TB, toks []models.TokenWithSpan) (string, int) {
	t.Helper()
	p := NewParser()
	defer p.Release()
	tree, err := p.ParseFromModelTokens(toks)
	if err != nil {
		t.Fatalf("fresh parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	return tree.SQL(), len(tree.Statements)
}

// assertZeroTail fails if any element of buf beyond len(buf) is non-zero.
func assertZeroTail(t *testing.T, buf []models.TokenWithSpan) {
	t.Helper()
	tail := buf[len(buf):cap(buf)]
	for i := range tail {
		if tail[i] != (models.TokenWithSpan{}) {
			t.Fatalf("tokenBuf[%d] (beyond len %d) not zeroed: %+v", len(buf)+i, len(buf), tail[i])
		}
	}
}

func TestParseBytesWithTokens_NotAliasedByLaterParse(t *testing.T) {
	// Independent reference: what the returned slice must keep holding.
	want := preprocessTokens(tokenizeBuf(t, bufLongSQL))

	ast1, toks, err := ParseBytesWithTokens([]byte(bufLongSQL))
	if err != nil {
		t.Fatalf("ParseBytesWithTokens: %v", err)
	}
	defer ast.ReleaseAST(ast1)
	wantSQL := ast1.SQL()

	checkToks := func(when string) {
		t.Helper()
		if !reflect.DeepEqual(toks, want) {
			t.Fatalf("token slice returned by ParseBytesWithTokens was modified (%s)", when)
		}
	}
	// PutParser (deferred inside ParseBytesWithTokens) must not scrub it.
	checkToks("after return")

	other := tokenizeBuf(t, bufUpdateSQL)
	for i := 0; i < 50; i++ {
		short, err := ParseBytes([]byte(bufShortSQL))
		if err != nil {
			t.Fatalf("ParseBytes: %v", err)
		}
		ast.ReleaseAST(short)

		// sync.Pool usually hands back the parser ParseBytesWithTokens used;
		// check while it still holds the new stream (Reset would re-zero it).
		p := GetParser()
		tree, err := p.ParseFromModelTokens(other)
		if err != nil {
			PutParser(p)
			t.Fatalf("ParseFromModelTokens: %v", err)
		}
		checkToks(fmt.Sprintf("during later parse %d", i))
		ast.ReleaseAST(tree)
		PutParser(p)
	}

	checkToks("after later parses")
	if got := ast1.SQL(); got != wantSQL {
		t.Fatalf("AST from ParseBytesWithTokens changed:\n got: %s\nwant: %s", got, wantSQL)
	}
}

func TestParserTokenBuf_ResetClearsAndCaps(t *testing.T) {
	t.Run("reset scrubs and keeps small buffer", func(t *testing.T) {
		p := NewParser()
		tree, err := p.ParseFromModelTokens(tokenizeBuf(t, bufLongSQL))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
		if len(p.tokenBuf) == 0 {
			t.Fatal("expected tokenBuf to hold the preprocessed stream after parse")
		}
		p.Reset()
		if len(p.tokenBuf) != 0 {
			t.Errorf("len(tokenBuf) = %d after Reset, want 0", len(p.tokenBuf))
		}
		if cap(p.tokenBuf) == 0 {
			t.Error("cap(tokenBuf) = 0 after Reset, want the buffer kept for reuse")
		}
		if p.tokens != nil {
			t.Error("p.tokens not nil after Reset")
		}
		assertZeroTail(t, p.tokenBuf)
	})

	t.Run("reset drops buffer above cap", func(t *testing.T) {
		toks := tokenizeBuf(t, buildWideSelect(3000))
		if len(toks) <= maxPooledTokenBuf {
			t.Fatalf("wide select has %d tokens, want > %d", len(toks), maxPooledTokenBuf)
		}
		p := NewParser()
		tree, err := p.ParseFromModelTokens(toks)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
		if cap(p.tokenBuf) <= maxPooledTokenBuf {
			t.Fatalf("cap(tokenBuf) = %d, want > %d", cap(p.tokenBuf), maxPooledTokenBuf)
		}
		p.Reset()
		if p.tokenBuf != nil {
			t.Errorf("tokenBuf not dropped after Reset (cap %d > %d)", cap(p.tokenBuf), maxPooledTokenBuf)
		}
		if p.tokens != nil {
			t.Error("p.tokens not nil after Reset")
		}
	})

	t.Run("release drops buffer", func(t *testing.T) {
		p := NewParser()
		tree, err := p.ParseFromModelTokens(tokenizeBuf(t, bufShortSQL))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
		p.Release()
		if p.tokenBuf != nil {
			t.Error("tokenBuf not nil after Release")
		}
		if p.tokens != nil {
			t.Error("p.tokens not nil after Release")
		}
	})
}

func TestParserTokenBuf_LongThenShortMatchesFresh(t *testing.T) {
	sqls := []string{bufLongSQL, bufShortSQL, bufInsertSQL, bufLongSQL, bufUpdateSQL, bufDeleteSQL, bufShortSQL}
	inputs := make([][]models.TokenWithSpan, len(sqls))
	wantSQL := make([]string, len(sqls))
	wantN := make([]int, len(sqls))
	for i, s := range sqls {
		inputs[i] = tokenizeBuf(t, s)
		wantSQL[i], wantN[i] = freshParse(t, inputs[i])
	}

	type mode struct {
		name    string
		reset   bool // call p.Reset between parses
		pooled  bool // GetParser/PutParser per parse
		release bool // ast.ReleaseAST after each parse is checked
	}
	modes := []mode{
		{name: "same parser no reset"},
		{name: "same parser with reset", reset: true},
		{name: "pooled", pooled: true},
		{name: "same parser no reset release ast", release: true},
		{name: "pooled release ast", pooled: true, release: true},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			var p *Parser
			if !m.pooled {
				p = NewParser()
				defer p.Release()
			}
			var kept []*ast.AST
			defer func() {
				for _, tree := range kept {
					ast.ReleaseAST(tree)
				}
			}()

			for i, toks := range inputs {
				if m.pooled {
					p = GetParser()
				}
				tree, err := p.ParseFromModelTokens(toks)
				if err != nil {
					t.Fatalf("parse %d: %v", i, err)
				}
				if got := tree.SQL(); got != wantSQL[i] {
					t.Errorf("parse %d SQL mismatch:\n got: %s\nwant: %s", i, got, wantSQL[i])
				}
				if len(tree.Statements) != wantN[i] {
					t.Errorf("parse %d: %d statements, want %d", i, len(tree.Statements), wantN[i])
				}
				if !m.pooled && !m.reset && i > 0 && len(toks) < len(inputs[i-1]) {
					// A shorter stream after a longer one must not leave the
					// previous query's tokens pinned in the buffer's tail.
					assertZeroTail(t, p.tokenBuf)
				}
				if m.release {
					ast.ReleaseAST(tree)
				} else {
					kept = append(kept, tree)
				}
				switch {
				case m.pooled:
					PutParser(p)
				case m.reset:
					p.Reset()
				}
			}

			// Earlier ASTs must be unaffected by later parses on the same buffer.
			for i, tree := range kept {
				if got := tree.SQL(); got != wantSQL[i] {
					t.Errorf("retained AST %d changed after later parses:\n got: %s\nwant: %s", i, got, wantSQL[i])
				}
			}
		})
	}
}

func TestParserTokenBuf_RecoveryReuse(t *testing.T) {
	const longSQL = bufLongSQL + `; INVALID foo bar; ` + bufInsertSQL + `; ` + bufUpdateSQL
	longToks := tokenizeBuf(t, longSQL)
	shortToks := tokenizeBuf(t, bufShortSQL)

	type result struct {
		sql  string
		n    int
		errs []string
	}
	summarize := func(stmts []ast.Statement, errs []error) result {
		r := result{sql: ast.AST{Statements: stmts}.SQL(), n: len(stmts)}
		for _, e := range errs {
			r.errs = append(r.errs, e.Error())
		}
		return r
	}
	fresh := func(toks []models.TokenWithSpan) result {
		p := NewParser()
		defer p.Release()
		return summarize(p.ParseWithRecoveryFromModelTokens(toks))
	}
	wantLong, wantShort := fresh(longToks), fresh(shortToks)
	if len(wantLong.errs) == 0 || wantLong.n == 0 {
		t.Fatalf("long input should yield statements and errors, got %d statements, %d errors", wantLong.n, len(wantLong.errs))
	}

	check := func(t *testing.T, label string, got, want result) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s mismatch:\n got: %+v\nwant: %+v", label, got, want)
		}
	}

	t.Run("same parser", func(t *testing.T) {
		p := NewParser()
		defer p.Release()
		gotLong := summarize(p.ParseWithRecoveryFromModelTokens(longToks))
		gotShort := summarize(p.ParseWithRecoveryFromModelTokens(shortToks))
		check(t, "long", gotLong, wantLong)
		check(t, "short", gotShort, wantShort)
	})

	t.Run("ParseMultiWithRecovery", func(t *testing.T) {
		legacyLong, err := convertModelTokens(longToks)
		if err != nil {
			t.Fatalf("convert: %v", err)
		}
		legacyShort, err := convertModelTokens(shortToks)
		if err != nil {
			t.Fatalf("convert: %v", err)
		}
		freshLegacy := func() (result, result) {
			p := NewParser()
			defer p.Release()
			l := summarize(p.ParseWithRecovery(legacyLong))
			s := summarize(NewParser().ParseWithRecovery(legacyShort))
			return l, s
		}
		wantL, wantS := freshLegacy()

		for i := 0; i < 20; i++ {
			rl := ParseMultiWithRecovery(legacyLong)
			gotL := summarize(rl.Statements, rl.Errors)
			rl.Release()
			rs := ParseMultiWithRecovery(legacyShort)
			gotS := summarize(rs.Statements, rs.Errors)
			rs.Release()
			check(t, fmt.Sprintf("iter %d long", i), gotL, wantL)
			check(t, fmt.Sprintf("iter %d short", i), gotS, wantS)
		}
	})
}

func TestParseWithPositions_CallerSliceUntouched(t *testing.T) {
	cr := &ConversionResult{Tokens: preprocessTokens(tokenizeBuf(t, bufLongSQL))}
	snapshot := append([]models.TokenWithSpan(nil), cr.Tokens...)

	p := NewParser()
	defer p.Release()
	tree1, err := p.ParseWithPositions(cr)
	if err != nil {
		t.Fatalf("ParseWithPositions: %v", err)
	}
	defer ast.ReleaseAST(tree1)
	tree2, err := p.ParseFromModelTokens(tokenizeBuf(t, bufShortSQL))
	if err != nil {
		t.Fatalf("ParseFromModelTokens: %v", err)
	}
	defer ast.ReleaseAST(tree2)
	if !reflect.DeepEqual(cr.Tokens, snapshot) {
		t.Fatal("ConversionResult.Tokens was modified by a later parse on the same parser")
	}
	p.Reset()
	if !reflect.DeepEqual(cr.Tokens, snapshot) {
		t.Fatal("ConversionResult.Tokens was modified by Reset")
	}
}

func TestParserTokenBuf_SteadyStateAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not stable under the race detector")
	}

	// Same compound stream as TestPreprocessAllocs: expands by exactly 4.
	stream := []models.TokenWithSpan{
		{Token: mtok(models.TokenTypeSelect, "SELECT")},
		{Token: mtok(models.TokenTypeIdentifier, "id")},
		{Token: mtok(models.TokenTypeFrom, "FROM")},
		{Token: mtok(models.TokenTypeIdentifier, "users")},
		{Token: mtok(models.TokenTypeInnerJoin, "INNER JOIN")},
		{Token: mtok(models.TokenTypeIdentifier, "orders")},
		{Token: mtok(models.TokenTypeKeyword, "FULL JOIN")},
		{Token: mtok(models.TokenTypeIdentifier, "items")},
		{Token: mtok(models.TokenTypeIdentifier, "with")},
		{Token: mtok(models.TokenTypeIdentifier, "where")},
		{Token: mtok(models.TokenTypeGroupBy, "GROUP BY")},
		{Token: mtok(models.TokenTypeIdentifier, "total")},
		{Token: mtok(models.TokenTypeOrderBy, "ORDER BY")},
		{Token: mtok(models.TokenTypeKeyword, "materialized")},
		{Token: mtok(models.TokenTypeIdentifier, "name")},
	}
	p := NewParser()
	sinkTokens = p.preprocess(stream) // warm up: first call sizes the buffer
	if n := testing.AllocsPerRun(1000, func() { sinkTokens = p.preprocess(stream) }); n != 0 {
		t.Errorf("warmed Parser.preprocess allocs = %v, want 0", n)
	}
	p.Release()

	reused := NewParser()
	defer reused.Release()
	parseReused := func() {
		tree, err := reused.ParseFromModelTokens(simpleSelectTokens)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
	}
	parseReused() // warm up the buffer and the AST/statement pools
	reusedAllocs := testing.AllocsPerRun(1000, parseReused)
	freshAllocs := testing.AllocsPerRun(1000, func() {
		fp := NewParser()
		tree, err := fp.ParseFromModelTokens(simpleSelectTokens)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
		fp.Release()
	})
	t.Logf("allocs/parse: reused=%v fresh=%v", reusedAllocs, freshAllocs)
	if reusedAllocs >= freshAllocs {
		t.Errorf("reused parser allocs/parse = %v, want fewer than fresh parser (%v)", reusedAllocs, freshAllocs)
	}
	// Measured at implementation time: a reused parser with ReleaseAST parses
	// simpleSelectTokens in 5 allocations (none for preprocess or Statements;
	// a fresh parser per parse needs 7).
	if reusedAllocs > maxReusedSimpleSelectAllocs {
		t.Errorf("reused parser allocs/parse = %v, want <= %d", reusedAllocs, maxReusedSimpleSelectAllocs)
	}
}

// maxReusedSimpleSelectAllocs is the measured steady-state allocation count of
// a reused parser parsing simpleSelectTokens and releasing the AST.
const maxReusedSimpleSelectAllocs = 5

func TestParserPool_ConcurrentBufferReuse(t *testing.T) {
	sqls := []string{
		bufShortSQL,
		bufInsertSQL,
		bufUpdateSQL,
		bufDeleteSQL,
		bufLongSQL,
		bufLongSQL + "; " + bufLongSQL + "; " + bufInsertSQL, // > 100 tokens: 2-statement estimate
		buildWideSelect(2000),                                // ~4000 tokens: near maxPooledTokenBuf
	}
	inputs := make([][]models.TokenWithSpan, len(sqls))
	want := make([]string, len(sqls))
	for i, s := range sqls {
		inputs[i] = tokenizeBuf(t, s)
		want[i], _ = freshParse(t, inputs[i])
	}
	if n := len(inputs[len(inputs)-1]); n > maxPooledTokenBuf || n < maxPooledTokenBuf*3/4 {
		t.Fatalf("wide select has %d tokens, want close to but not above %d", n, maxPooledTokenBuf)
	}

	const goroutines = 16
	iterations := 500
	if testing.Short() {
		iterations = 100
	}

	failures := make(chan string, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < iterations; i++ {
				idx := (g*7 + i) % len(inputs)
				p := GetParser()
				var (
					tree *ast.AST
					err  error
				)
				if i%2 == 0 {
					tree, err = p.ParseFromModelTokens(inputs[idx])
				} else {
					tree, err = p.ParseContextFromModelTokens(ctx, inputs[idx])
				}
				if err != nil {
					PutParser(p)
					failures <- fmt.Sprintf("goroutine %d iter %d query %d: %v", g, i, idx, err)
					return
				}
				got := tree.SQL()
				ast.ReleaseAST(tree)
				PutParser(p)
				if got != want[idx] {
					failures <- fmt.Sprintf("goroutine %d iter %d query %d: SQL mismatch\n got: %.120s\nwant: %.120s", g, i, idx, got, want[idx])
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(failures)
	for f := range failures {
		t.Error(f)
	}
}
