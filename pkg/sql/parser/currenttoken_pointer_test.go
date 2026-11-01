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

package parser

import (
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// currentTokenCorpus covers the parser paths that save, restore, seek over
// and peek past currentToken: speculative lookahead (ALTER TABLE, CREATE
// FUNCTION bodies, index hints), recovery after errors, ClickHouse mutations
// (which temporarily shorten p.tokens) and plain DML/DDL that reaches EOF.
var currentTokenCorpus = []string{
	"SELECT 1",
	"SELECT a, b FROM t WHERE a = 1 AND b <> 2 ORDER BY a LIMIT 5",
	"SELECT a <=> b FROM t",
	"SELECT * FROM t1 JOIN t2 ON t1.id = t2.id LEFT JOIN t3 USING (id)",
	"WITH c AS (SELECT 1) SELECT * FROM c UNION ALL SELECT 2",
	"INSERT INTO t (a, b) VALUES (1, 2) RETURNING a",
	"UPDATE t SET a = 1 FROM s WHERE t.id = s.id RETURNING a",
	"DELETE FROM t WHERE id IN (SELECT id FROM s)",
	"CREATE TABLE t (id INT PRIMARY KEY, name TEXT NOT NULL DEFAULT 'x')",
	"ALTER TABLE t ADD COLUMN c INT, DROP COLUMN d",
	"ALTER TABLE t UPDATE a = 1, b = 2 IN PARTITION p WHERE id > 0",
	"SELECT a FROM t USE INDEX (i1) WHERE a = 1",
	"SELECT INTERVAL '1' DAY TO SECOND",
	"SELECT `a` FROM `t`; SELECT \"b\" FROM [c]",
	"SELECT 1; SELECT 2; ;",
	"SELECT FROM",
	"SELECT a b c FROM",
	"SELECT (",
	"",
	";",
}

func cursorTestTokens(t testing.TB, sql string) []models.TokenWithSpan {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		// Malformed input is part of the corpus: an empty stream still exercises
		// the cursor setup.
		return nil
	}
	// The tokenizer owns its buffer; copy it so the slice outlives the pool.
	return append([]models.TokenWithSpan(nil), toks...)
}

// assertCursorInvariant checks the invariant every parser method relies on:
// currentToken is the token at currentPos, or the parser's own zero EOF
// sentinel once the cursor is past the stream.
func assertCursorInvariant(t *testing.T, p *Parser, ctx string) {
	t.Helper()
	if p.currentToken == nil {
		t.Fatalf("%s: currentToken is nil", ctx)
	}
	if p.currentPos >= 0 && p.currentPos < len(p.tokens) {
		if p.currentToken != &p.tokens[p.currentPos] {
			t.Fatalf("%s: currentToken does not point at tokens[%d]", ctx, p.currentPos)
		}
		return
	}
	if p.currentToken != &p.eof {
		t.Fatalf("%s: past the stream (pos %d of %d) currentToken is not the parser's EOF sentinel", ctx, p.currentPos, len(p.tokens))
	}
	if p.eof != (models.TokenWithSpan{}) {
		t.Fatalf("%s: EOF sentinel was modified: %+v", ctx, p.eof)
	}
}

// TestCurrentToken_TracksCursor walks every position of several streams with
// advance and seek, and checks currentToken follows currentPos exactly,
// including saved/restored cursors and the move past EOF.
func TestCurrentToken_TracksCursor(t *testing.T) {
	for _, sql := range currentTokenCorpus {
		sql := sql
		t.Run(sql, func(t *testing.T) {
			p := NewParser()
			defer p.Release()
			toks := p.preprocess(cursorTestTokens(t, sql))
			p.tokens = toks
			p.currentPos = 0
			p.seek(0)
			assertCursorInvariant(t, p, "seek(0)")

			for i := 0; i <= len(toks)+1; i++ {
				assertCursorInvariant(t, p, "advance")
				// Save/restore, as the speculative-lookahead helpers do.
				savedPos, savedTok := p.currentPos, p.currentToken
				p.advance()
				p.advance()
				p.currentPos, p.currentToken = savedPos, savedTok
				assertCursorInvariant(t, p, "restore")
				p.advance()
			}
			for i := len(toks) + 1; i >= -1; i-- {
				p.seek(i)
				if i < 0 {
					if p.currentPos != len(toks) {
						t.Fatalf("seek(%d): pos = %d, want EOF %d", i, p.currentPos, len(toks))
					}
				}
				assertCursorInvariant(t, p, "seek")
			}
		})
	}
}

// TestCurrentToken_PeekToken checks peekToken against the token slice and
// that past the end it returns the zero sentinel without modifying it.
func TestCurrentToken_PeekToken(t *testing.T) {
	p := NewParser()
	defer p.Release()
	toks := p.preprocess(cursorTestTokens(t, "SELECT a FROM t"))
	p.tokens = toks
	p.seek(0)
	for i := range toks {
		p.seek(i)
		got := p.peekToken()
		if got == nil {
			t.Fatalf("peekToken at %d returned nil", i)
		}
		if i+1 < len(toks) {
			if *got != toks[i+1] {
				t.Errorf("peekToken at %d = %+v, want %+v", i, *got, toks[i+1])
			}
		} else {
			if *got != (models.TokenWithSpan{}) {
				t.Errorf("peekToken past end = %+v, want zero token", *got)
			}
			if got != &p.eof {
				t.Errorf("peekToken past end at %d is not the parser's own EOF sentinel", i)
			}
		}
	}
	if p.eof != (models.TokenWithSpan{}) {
		t.Errorf("EOF sentinel modified by peekToken: %+v", p.eof)
	}
}

// TestCurrentToken_SentinelUnmodifiedAfterParsing runs every parse entry
// point over the corpus, including error and recovery paths and parsers that
// were pooled and reset in between, and requires the per-parser EOF sentinel
// to stay the zero token. A write through currentToken at EOF would corrupt
// every later end-of-input check on that parser.
func TestCurrentToken_SentinelUnmodifiedAfterParsing(t *testing.T) {
	p := GetParser()
	defer PutParser(p)
	for round := 0; round < 3; round++ {
		for _, sql := range currentTokenCorpus {
			toks := cursorTestTokens(t, sql)

			if tree, err := p.ParseFromModelTokens(toks); err == nil {
				ast.ReleaseAST(tree)
			}
			assertSentinelClean(t, p, "ParseFromModelTokens", sql)

			p.ParseWithRecoveryFromModelTokens(toks)
			assertSentinelClean(t, p, "ParseWithRecoveryFromModelTokens", sql)

			if tree, err := p.ParseContextFromModelTokens(t.Context(), toks); err == nil {
				ast.ReleaseAST(tree)
			}
			assertSentinelClean(t, p, "ParseContextFromModelTokens", sql)

			p.Reset()
			assertSentinelClean(t, p, "Reset", sql)
			assertRepointedAtSentinel(t, p, "Reset", sql)
		}
	}
}

func assertSentinelClean(t *testing.T, p *Parser, op, sql string) {
	t.Helper()
	if p.eof != (models.TokenWithSpan{}) {
		t.Fatalf("%s(%q): EOF sentinel modified: %+v", op, sql, p.eof)
	}
	if p.currentToken == nil {
		t.Fatalf("%s(%q): currentToken is nil", op, sql)
	}
}

// assertRepointedAtSentinel requires a reset/released parser to hold no
// interior pointer into a token slice: a stale currentToken would keep a
// dropped oversized tokenBuf or a caller-owned slice alive in the pool.
func assertRepointedAtSentinel(t *testing.T, p *Parser, op, sql string) {
	t.Helper()
	if p.currentToken != &p.eof {
		t.Fatalf("%s(%q): currentToken is not re-pointed at the EOF sentinel (stale interior pointer)", op, sql)
	}
	if p.tokens != nil {
		t.Fatalf("%s(%q): tokens still referenced", op, sql)
	}
}

// TestCurrentToken_ReleaseRepointsSentinel pins Release's re-point.
func TestCurrentToken_ReleaseRepointsSentinel(t *testing.T) {
	for _, sql := range currentTokenCorpus {
		p := NewParser()
		toks := cursorTestTokens(t, sql)
		if tree, err := p.ParseFromModelTokens(toks); err == nil {
			ast.ReleaseAST(tree)
		}
		p.Release()
		assertSentinelClean(t, p, "Release", sql)
		assertRepointedAtSentinel(t, p, "Release", sql)
	}
}

// TestCurrentToken_ResetDropsOversizedBuffer parses a stream whose token
// buffer exceeds maxPooledTokenBuf and requires Reset to leave no pointer
// into the dropped buffer or the caller's slice.
func TestCurrentToken_ResetDropsOversizedBuffer(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("SELECT 1")
	for i := 0; i < maxPooledTokenBuf; i++ {
		sb.WriteString(", 1")
	}
	toks := cursorTestTokens(t, sb.String())
	if len(toks) <= maxPooledTokenBuf {
		t.Fatalf("test stream too small: %d tokens", len(toks))
	}
	p := NewParser()
	if tree, err := p.ParseFromModelTokens(toks); err != nil {
		t.Fatal(err)
	} else {
		ast.ReleaseAST(tree)
	}
	big := cap(p.tokenBuf) > maxPooledTokenBuf
	p.Reset()
	assertRepointedAtSentinel(t, p, "Reset", "oversized")
	if big && p.tokenBuf != nil {
		t.Fatal("oversized tokenBuf was not dropped by Reset")
	}
	// Caller-owned slice (ParseWithPositions style): parse the raw slice
	// directly, then reset.
	p.tokens = toks
	p.seek(len(toks) / 2)
	p.Reset()
	assertRepointedAtSentinel(t, p, "Reset", "caller-owned")
}

// TestCurrentToken_SentinelIsPerParser guards decision D4: the sentinel must
// never be shared between parsers, or a stray write would race across
// goroutines and leak between tests.
func TestCurrentToken_SentinelIsPerParser(t *testing.T) {
	a, b := NewParser(), NewParser()
	if a.currentToken == b.currentToken {
		t.Fatal("two parsers share one EOF sentinel")
	}
	if a.currentToken != &a.eof || b.currentToken != &b.eof {
		t.Fatal("a fresh parser's currentToken is not its own sentinel")
	}
	pa, pb := GetParser(), GetParser()
	defer PutParser(pa)
	defer PutParser(pb)
	if pa.currentToken == pb.currentToken {
		t.Fatal("two pooled parsers share one EOF sentinel")
	}
	if pa.currentToken != &pa.eof || pb.currentToken != &pb.eof {
		t.Fatal("a pooled parser's currentToken is not its own sentinel")
	}
}

// TestCurrentToken_ZeroValueParser covers &Parser{}, which the type's
// documentation allows: every entry point must set up the cursor itself,
// including for an empty token stream, and advance/seek must be safe on a
// parser that was never initialised.
func TestCurrentToken_ZeroValueParser(t *testing.T) {
	for _, sql := range currentTokenCorpus {
		sql := sql
		t.Run(sql, func(t *testing.T) {
			toks := cursorTestTokens(t, sql)
			if tree, err := (&Parser{}).ParseFromModelTokens(toks); err == nil {
				ast.ReleaseAST(tree)
			}
			(&Parser{}).ParseWithRecoveryFromModelTokens(toks)
			if tree, err := (&Parser{}).ParseContextFromModelTokens(t.Context(), toks); err == nil {
				ast.ReleaseAST(tree)
			}
		})
	}

	p := &Parser{tokens: []models.TokenWithSpan{mkSpanToken(models.TokenTypeSelect, "SELECT")}}
	p.advance()
	assertCursorInvariant(t, p, "zero-value advance")
	p = &Parser{tokens: []models.TokenWithSpan{mkSpanToken(models.TokenTypeSelect, "SELECT")}}
	p.seek(0)
	assertCursorInvariant(t, p, "zero-value seek")
	p = &Parser{}
	if tree, err := p.ParseFromModelTokens(nil); err == nil {
		ast.ReleaseAST(tree)
	}
	assertCursorInvariant(t, p, "zero-value empty stream")
}

// TestCurrentToken_EmptyStreamClearsStaleCursor: a reused parser given an
// empty stream must not keep pointing into the previous query's tokens.
func TestCurrentToken_EmptyStreamClearsStaleCursor(t *testing.T) {
	p := NewParser()
	defer p.Release()
	first := cursorTestTokens(t, "SELECT a FROM t")
	if tree, err := p.ParseFromModelTokens(first); err == nil {
		ast.ReleaseAST(tree)
	}
	if tree, err := p.ParseFromModelTokens(nil); err == nil {
		ast.ReleaseAST(tree)
	}
	assertCursorInvariant(t, p, "empty stream after a parse")
	p.ParseWithRecoveryFromModelTokens(first)
	p.ParseWithRecoveryFromModelTokens(nil)
	assertCursorInvariant(t, p, "empty recovery stream after a parse")
	if tree, err := p.ParseContextFromModelTokens(t.Context(), first); err == nil {
		ast.ReleaseAST(tree)
	}
	if tree, err := p.ParseContextFromModelTokens(t.Context(), nil); err == nil {
		ast.ReleaseAST(tree)
	}
	assertCursorInvariant(t, p, "empty context stream after a parse")
	if p.currentToken != &p.eof {
		t.Fatal("empty context stream left a stale cursor")
	}
}

// TestCurrentToken_ConcurrentParsers parses concurrently on independent
// parsers. Under -race this proves no EOF sentinel (or other cursor state) is
// shared between goroutines.
func TestCurrentToken_ConcurrentParsers(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := GetParser()
			defer PutParser(p)
			for i := 0; i < 20; i++ {
				for _, sql := range currentTokenCorpus {
					tkz := tokenizer.GetTokenizer()
					toks, err := tkz.Tokenize([]byte(sql))
					if err == nil {
						if tree, perr := p.ParseFromModelTokens(toks); perr == nil {
							ast.ReleaseAST(tree)
						}
						p.ParseWithRecoveryFromModelTokens(toks)
					}
					tokenizer.PutTokenizer(tkz)
				}
			}
		}()
	}
	wg.Wait()
}

// TestCurrentToken_NextAdjacent pins nextAdjacent, whose rewrite from token
// copies to End/Start comparisons must keep the same answers.
func TestCurrentToken_NextAdjacent(t *testing.T) {
	cases := []struct {
		sql    string
		pos    int // seek here, then ask about offsets 1 and 2
		want1  bool
		want2  bool
		reason string
	}{
		{"a<=>b", 0, true, true, "operator written as one token"},
		{"a < = > b", 0, false, false, "spaces between pieces"},
		{"a<= >b", 0, true, false, "gap before the third piece"},
		{"a<= >b", 2, true, true, "cursor on the middle piece, no gaps after it"},
		{"a<=> b", 0, true, false, "gap before the last token"},
	}
	for _, tc := range cases {
		p := NewParser()
		p.tokens = p.preprocess(cursorTestTokens(t, tc.sql))
		p.seek(tc.pos)
		if got := p.nextAdjacent(1); got != tc.want1 {
			t.Errorf("%q @%d nextAdjacent(1) = %v, want %v (%s)", tc.sql, tc.pos, got, tc.want1, tc.reason)
		}
		if got := p.nextAdjacent(2); got != tc.want2 {
			t.Errorf("%q @%d nextAdjacent(2) = %v, want %v (%s)", tc.sql, tc.pos, got, tc.want2, tc.reason)
		}
		p.Release()
	}
}
