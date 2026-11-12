// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func formatDialectCorpus(sql, dialect string) string {
	return goldens.Safe(func() string {
		out, err := gosqlx.FormatWithDialect(sql, gosqlx.FormatOptions{}, keywords.SQLDialect(dialect))
		if err != nil {
			return "ERR:" + err.Error()
		}
		return out
	})
}

func TestGoldenFormatDialectCross(t *testing.T) {
	g := goldens.New("format_dialect_cross", "FormatWithDialect in each corpus statement's own dialect", "own_dialect")
	stmts := goldens.Corpus(t)
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		g.Add(st.File, "own_dialect", st.Index, st.SQL, formatDialectCorpus(st.SQL, st.Dialect))
	})
	g.Check(t)
}

func TestFormatDialectCrossConcurrent(t *testing.T) {
	stmts := goldens.Corpus(t)
	want := make([]string, len(stmts))
	for i, st := range stmts {
		want[i] = formatDialectCorpus(st.SQL, st.Dialect)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, st := range stmts {
				if got := formatDialectCorpus(st.SQL, st.Dialect); got != want[i] {
					errs <- fmt.Errorf("%s#%d: got %q, want %q", st.File, st.Index, got, want[i])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
