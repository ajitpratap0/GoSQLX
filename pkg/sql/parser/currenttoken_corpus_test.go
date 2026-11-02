// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestCurrentTokenSentinelUnmodifiedOverCorpus drives all three token entry
// points over the whole W0-02 benchmark corpus under every dialect and
// requires the per-parser EOF sentinel to stay the zero token (PLAN W3-02).
// This reaches dialect-specific parse paths where a future write through
// p.currentToken would corrupt end-of-input checks. After each statement the
// parser is reset and must hold no pointer into the token slice.
func TestCurrentTokenSentinelUnmodifiedOverCorpus(t *testing.T) {
	stmts := goldens.Corpus(t)
	for _, dn := range goldens.Dialects() {
		d := keywords.SQLDialect(dn)
		tkz, err := tokenizer.NewWithDialect(d)
		if err != nil {
			t.Fatalf("%s: tokenizer: %v", dn, err)
		}
		p := parser.NewParser(parser.WithDialect(dn))
		for _, st := range stmts {
			toks, terr := tkz.Tokenize([]byte(st.SQL))
			if terr != nil {
				tkz.Reset()
				continue
			}
			toks = append([]models.TokenWithSpan(nil), toks...)
			tkz.Reset()

			// Tokenizer output ends with an EOF token, so the parser almost
			// never walks past len(p.tokens). Also feed the stream with that
			// trailing EOF stripped so currentToken/peekToken reach the
			// per-parser sentinel (&p.eof) on every dialect-specific path.
			streams := [][]models.TokenWithSpan{toks}
			if n := len(toks); n > 0 && toks[n-1].Token.Type == models.TokenTypeEOF {
				streams = append(streams, toks[:n-1])
			}
			for _, ts := range streams {
				if tree, err := p.ParseFromModelTokens(ts); err == nil {
					ast.ReleaseAST(tree)
				}
				p.ParseWithRecoveryFromModelTokens(ts)
				if tree, err := p.ParseContextFromModelTokens(t.Context(), ts); err == nil {
					ast.ReleaseAST(tree)
				}
				if !parser.EOFSentinelClean(p) {
					t.Fatalf("dialect %s, %s#%d: EOF sentinel modified", dn, st.File, st.Index)
				}
			}
			p.Reset()
			// Reset clears the dialect; re-apply so every statement runs under dn.
			p.ApplyOptions(parser.WithDialect(dn))
			if !parser.EOFSentinelClean(p) || !parser.CursorRepointed(p) {
				t.Fatalf("dialect %s, %s#%d: Reset left a stale cursor or dirty sentinel", dn, st.File, st.Index)
			}
		}
		p.Release()
		if !parser.CursorRepointed(p) {
			t.Fatalf("dialect %s: Release left a stale cursor", dn)
		}
	}
}
