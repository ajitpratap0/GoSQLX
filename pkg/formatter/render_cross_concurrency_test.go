// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestRenderCrossConcurrent(t *testing.T) {
	tree, err := gosqlx.Parse("WITH c AS (SELECT x FROM t) SELECT (SELECT max(x) FROM c) FROM c UNION SELECT x FROM t")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	dialects := corpusDialects()
	want := make([]string, len(dialects))
	for i, d := range dialects {
		opts := ast.ReadableStyle()
		opts.Dialect = d
		want[i], err = formatter.FormatASTChecked(tree, opts)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(dialects)*8)
	for i, d := range dialects {
		for range 8 {
			wg.Add(1)
			go func(i int, d string) {
				defer wg.Done()
				opts := ast.ReadableStyle()
				opts.Dialect = d
				for range 10 {
					got, err := formatter.FormatASTChecked(tree, opts)
					if err != nil || got != want[i] {
						errs <- fmt.Errorf("%s: got %q, err %v; want %q", d, got, err, want[i])
						return
					}
				}
			}(i, d)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
