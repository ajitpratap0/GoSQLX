// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// tokenizePath is one tokenizer entry point. The scratch paths
// (internal/tokscratch) are the ones gosqlx.Parse, ParseWithDialect and the
// Validate fast paths use; their tokens live in the tokenizer's scratch
// buffer, so they are rendered before the tokenizer is returned.
type tokenizePath struct {
	name string
	run  func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error)
}

var tokenizePaths = []tokenizePath{
	{"public", func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tkz.Tokenize([]byte(sql))
	}},
	{"string", func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tkz.TokenizeString(sql)
	}},
	{"scratch", func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tokscratch.String(tkz, sql)
	}},
	{"scratch_bytes", func(tkz *tokenizer.Tokenizer, sql string) ([]models.TokenWithSpan, error) {
		return tokscratch.Bytes(tkz, []byte(sql))
	}},
}

// TestGoldenTokens pins the full token stream (type, value, span, quote, Long
// flag and Word metadata, a nil Word included) and the captured comments
// (tkz.Comments) of every benchmark corpus statement under every accepted
// dialect, including bigquery and redshift.
//
// The cell is the public Tokenize([]byte) dump. TokenizeString and the
// tokscratch String/Bytes paths are run too; a path whose dump differs from
// the public one is appended to the cell as a "<path>:" section, so today's
// cells (all paths equal) carry only the public dump and any divergence
// changes the hash. Regenerate with task goldens:update; inspect a mismatch
// with task goldens:diff.
func TestGoldenTokens(t *testing.T) {
	stmts := goldens.Corpus(t)
	dialects := goldens.Dialects()
	g := goldens.New("tokens", "tokenizer.Tokenize token+comment dump per corpus statement and dialect; TokenizeString/tokscratch sections only where they differ", dialects...)
	goldens.Parallel(len(stmts)*len(dialects), func(i int) {
		st, d := stmts[i/len(dialects)], dialects[i%len(dialects)]
		out := goldens.Safe(func() string {
			var b strings.Builder
			public := tokenDump(tokenizePaths[0], keywords.SQLDialect(d), st.SQL)
			b.WriteString(public)
			for _, p := range tokenizePaths[1:] {
				if got := tokenDump(p, keywords.SQLDialect(d), st.SQL); got != public {
					fmt.Fprintf(&b, "\n%s:\n%s", p.name, got)
				}
			}
			return b.String()
		})
		g.Add(st.File, d, st.Index, st.SQL, out)
	})
	g.Check(t)
}

// tokenDump runs one path on a fresh pooled tokenizer and renders its tokens
// (or error) followed by its captured comments.
func tokenDump(p tokenizePath, d keywords.SQLDialect, sql string) string {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(d)
	toks, err := p.run(tkz, sql)
	var b strings.Builder
	if err != nil {
		b.WriteString(goldens.Error(err))
	} else {
		b.WriteString(goldens.Tokens(toks))
	}
	for _, c := range tkz.Comments {
		fmt.Fprintf(&b, "comment %d:%d-%d:%d style=%d inline=%t %s\n",
			c.Start.Line, c.Start.Column, c.End.Line, c.End.Column, c.Style, c.Inline, strconv.Quote(c.Text))
	}
	return b.String()
}
