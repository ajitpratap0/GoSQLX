// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

func TestLowerKeywordCorpusMisses(t *testing.T) {
	corpus, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	misses := make(map[string]int)
	restore := formatter.SetLowerKeywordMissHookForTest(func(s string) string { misses[s]++; return strings.ToLower(s) })
	defer restore()
	count := 0
	for _, st := range corpus.All() {
		tree, err := parser.ParseWithDialect(st.SQL, keywords.SQLDialect(st.Dialect))
		if err != nil {
			continue
		}
		opts := ast.ReadableStyle()
		opts.KeywordCase = ast.KeywordLower
		opts.Dialect = st.Dialect
		_, err = formatter.FormatASTChecked(tree, opts)
		ast.ReleaseAST(tree)
		if err == nil {
			count++
		}
	}
	if count == 0 {
		t.Fatal("no corpus statements rendered")
	}
	if len(misses) != 0 {
		t.Errorf("lower keyword fallback misses in %d corpus statements: %v", count, misses)
	}
}
