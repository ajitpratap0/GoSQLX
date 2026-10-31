// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestGoldenTokens pins the full token stream (type, value, span, quote, Long
// flag and Word metadata) of every benchmark corpus statement under every
// accepted dialect, including bigquery and redshift. Regenerate with
// task goldens:update; inspect a mismatch with task goldens:diff.
func TestGoldenTokens(t *testing.T) {
	stmts := goldens.Corpus(t)
	dialects := goldens.Dialects()
	g := goldens.New("tokens", "tokenizer.Tokenize token dump per corpus statement and dialect", dialects...)
	goldens.Parallel(len(stmts)*len(dialects), func(i int) {
		st, d := stmts[i/len(dialects)], dialects[i%len(dialects)]
		out := goldens.Safe(func() string {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			tkz.SetDialect(keywords.SQLDialect(d))
			toks, err := tkz.Tokenize([]byte(st.SQL))
			if err != nil {
				return goldens.Error(err)
			}
			return goldens.Tokens(toks)
		})
		g.Add(st.File, d, st.Index, st.SQL, out)
	})
	g.Check(t)
}
