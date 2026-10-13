// Tests for the parser-owned preprocess buffer (#552), added after the
// pre-merge review: reuse after a parse that fails midway, context
// cancellation, the pooled-buffer capacity cap boundary, recovery-result
// lifetime, pooled AST Statements reuse and concurrent mixed entry points.

package parser

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func preprocessReuseTok(t testing.TB, s string) []models.TokenWithSpan { return tokenizeBuf(t, s) }

// Bot's suggested test: parse that errors midway, then reuse (pooled and non-pooled).
func TestPreprocessBuffer_ErrorMidwayThenReuse(t *testing.T) {
	bad := []string{
		buildWideSelect(500) + " WHERE (((a = ",
		"SELECT 1; SELECT a FROM t; SELECT FROM WHERE; SELECT 2",
		"INSERT INTO t (a,b) VALUES (1, 'x', ",
		"WITH c AS (SELECT * FROM x) SELECT * FROM c WHERE a IN (1,2,",
		"SELECT * FROM t;;;; UPDATE",
	}
	good := []string{bufShortSQL, bufInsertSQL, bufUpdateSQL, bufDeleteSQL, "SELECT 1; SELECT 2; SELECT 3"}
	for _, reuse := range []string{"noReset", "pooled"} {
		p := NewParser()
		for i := 0; i < 200; i++ {
			b := bad[i%len(bad)]
			g := good[i%len(good)]
			if reuse == "pooled" {
				p = GetParser()
			}
			tree, err := p.ParseFromModelTokens(preprocessReuseTok(t, b))
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatalf("expected error for %q", b)
			}
			if reuse == "pooled" {
				PutParser(p)
				p = GetParser()
			}
			assertZeroTail(t, p.tokenBuf)
			toks := preprocessReuseTok(t, g)
			wantSQL, wantN := freshParse(t, toks)
			tree, err = p.ParseFromModelTokens(toks)
			if err != nil {
				t.Fatalf("%s: good parse after error failed: %v", reuse, err)
			}
			if tree.SQL() != wantSQL || len(tree.Statements) != wantN {
				t.Fatalf("%s: mismatch after error: got %q (%d) want %q (%d)", reuse, tree.SQL(), len(tree.Statements), wantSQL, wantN)
			}
			ast.ReleaseAST(tree)
			assertZeroTail(t, p.tokenBuf)
			if reuse == "pooled" {
				PutParser(p)
			}
		}
	}
}

// Context-cancelled midway then reuse.
func TestPreprocessBuffer_ContextCancelThenReuse(t *testing.T) {
	p := NewParser()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.ParseContextFromModelTokens(ctx, preprocessReuseTok(t, buildWideSelect(800)))
	if err == nil {
		t.Fatal("expected ctx error")
	}
	toks := preprocessReuseTok(t, bufShortSQL)
	want, _ := freshParse(t, toks)
	tree, err := p.ParseFromModelTokens(toks)
	if err != nil || tree.SQL() != want {
		t.Fatalf("after cancel: %v %v", err, tree)
	}
	ast.ReleaseAST(tree)
}

// 4096 cap boundary.
func TestPreprocessBuffer_CapBoundary(t *testing.T) {
	for _, n := range []int{2040, 2043, 2044, 2045, 2046} {
		sql := buildWideSelect(n) + ";"
		toks := preprocessReuseTok(t, sql)
		p := NewParser()
		tree, err := p.ParseFromModelTokens(toks)
		if err != nil {
			t.Fatal(err)
		}
		ast.ReleaseAST(tree)
		c := cap(p.tokenBuf)
		p.Reset()
		t.Logf("n=%d len(toks)=%d cap=%d keptAfterReset=%v", n, len(toks), c, p.tokenBuf != nil)
		if (c <= maxPooledTokenBuf) != (p.tokenBuf != nil) {
			t.Fatalf("cap rule violated")
		}
		assertZeroTail(t, p.tokenBuf)
	}
}

// Compound expansion growth past len+4 headroom: still correct, zero tail after reset.
func TestPreprocessBuffer_CompoundGrowth(t *testing.T) {
	// many compound-expanding tokens? Use lots of NULLS FIRST / IS NOT etc.
	var sb strings.Builder
	sb.WriteString("SELECT a FROM t WHERE ")
	for i := 0; i < 50; i++ {
		if i > 0 {
			sb.WriteString(" AND ")
		}
		fmt.Fprintf(&sb, "c%d IS NOT NULL", i)
	}
	sb.WriteString(" ORDER BY a DESC NULLS FIRST")
	toks := preprocessReuseTok(t, sb.String())
	want, _ := freshParse(t, toks)
	p := NewParser()
	for i := 0; i < 3; i++ {
		tree, err := p.ParseFromModelTokens(toks)
		if err != nil || tree.SQL() != want {
			t.Fatalf("compound: %v", err)
		}
		ast.ReleaseAST(tree)
	}
	t.Logf("in=%d out=%d cap=%d", len(toks), len(p.tokenBuf), cap(p.tokenBuf))
	p.Reset()
	assertZeroTail(t, p.tokenBuf)
}

// Recovery lifetime: statements from ParseMultiWithRecovery stay valid while
// other parses churn the pool, and after Release.
func TestPreprocessBuffer_RecoveryLifetime(t *testing.T) {
	sql := "SELECT a, b FROM t1 WHERE x = 'secret1'; SELECT FROM; UPDATE t2 SET y = 'v' WHERE id = 3"
	tkToks := preprocessReuseTok(t, sql)
	conv := make([]modelsTokenShim, 0)
	_ = conv
	p := GetParser()
	stmts, errs := p.ParseWithRecoveryFromModelTokens(tkToks)
	if len(stmts) != 2 || len(errs) != 1 {
		t.Fatalf("stmts=%d errs=%d", len(stmts), len(errs))
	}
	var before []string
	for _, s := range stmts {
		before = append(before, fmt.Sprintf("%#v", s.TokenLiteral())+preprocessReuseStmtSQL(s))
	}
	errBefore := errs[0].Error()
	PutParser(p)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				q := GetParser()
				tr, err := q.ParseFromModelTokens(preprocessReuseTok(t, buildWideSelect(30)))
				if err == nil {
					ast.ReleaseAST(tr)
				}
				PutParser(q)
			}
		}()
	}
	wg.Wait()
	for i, s := range stmts {
		if got := fmt.Sprintf("%#v", s.TokenLiteral()) + preprocessReuseStmtSQL(s); got != before[i] {
			t.Fatalf("stmt %d changed: %s vs %s", i, got, before[i])
		}
	}
	if errs[0].Error() != errBefore {
		t.Fatal("error text changed")
	}
}

type modelsTokenShim struct{}

func preprocessReuseStmtSQL(s ast.Statement) string {
	tr := &ast.AST{Statements: []ast.Statement{s}}
	return tr.SQL()
}

// Pooled AST must not leak statements from a previous longer parse.
func TestPreprocessBuffer_PooledASTStatements(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&sb, "SELECT %d FROM t%d; ", i, i)
	}
	for i := 0; i < 50; i++ {
		tr, err := ParseBytes([]byte(sb.String()))
		if err != nil {
			t.Fatal(err)
		}
		if len(tr.Statements) != 20 {
			t.Fatalf("got %d", len(tr.Statements))
		}
		ast.ReleaseAST(tr)
		tr, err = ParseBytes([]byte("SELECT 1"))
		if err != nil {
			t.Fatal(err)
		}
		if len(tr.Statements) != 1 {
			t.Fatalf("leak: got %d stmts", len(tr.Statements))
		}
		full := tr.Statements[:cap(tr.Statements)]
		for j := 1; j < len(full); j++ {
			if full[j] != nil {
				t.Fatalf("stale stmt pinned in pooled AST tail at %d", j)
			}
		}
		ast.ReleaseAST(tr)
	}
}

// Concurrent mixed API use under -race.
func TestPreprocessBuffer_ConcurrentMixed(t *testing.T) {
	sqls := []string{bufLongSQL, bufShortSQL, "SELECT FROM", buildWideSelect(2100), "SELECT 1; SELECT 2; SELECT 3; SELECT 4"}
	wants := make([]string, len(sqls))
	for i, s := range sqls {
		tr, err := ParseBytes([]byte(s))
		if err == nil {
			wants[i] = tr.SQL()
			ast.ReleaseAST(tr)
		} else {
			wants[i] = "ERR:" + err.Error()
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				k := (i + g) % len(sqls)
				var got string
				switch i % 3 {
				case 0:
					tr, err := ParseBytes([]byte(sqls[k]))
					if err != nil {
						got = "ERR:" + err.Error()
					} else {
						got = tr.SQL()
						ast.ReleaseAST(tr)
					}
				case 1:
					tr, _, err := ParseBytesWithTokens([]byte(sqls[k]))
					if err != nil {
						got = "ERR:" + err.Error()
					} else {
						got = tr.SQL()
						ast.ReleaseAST(tr)
					}
				case 2:
					r := ParseMultiWithRecovery(nil)
					r.Release()
					tr, err := ParseBytes([]byte(sqls[k]))
					if err != nil {
						got = "ERR:" + err.Error()
					} else {
						got = tr.SQL()
						ast.ReleaseAST(tr)
					}
				}
				if got != wants[k] {
					t.Errorf("mismatch k=%d: %q vs %q", k, got, wants[k])
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
