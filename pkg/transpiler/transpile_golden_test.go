// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// TestGoldenTranspile pins transpiler.Transpile output (or error) from every
// benchmark corpus statement's own dialect to every dialect of the 9x9 rule
// matrix, identity included. The corpora cover all nine source dialects, so
// together the rows exercise all 81 ordered pairs. Regenerate with
// task goldens:update; inspect a mismatch with task goldens:diff.
func TestGoldenTranspile(t *testing.T) {
	stmts := goldens.Corpus(t)
	targets := goldens.TranspileDialects()
	cols := make([]string, len(targets))
	for i, d := range targets {
		cols[i] = string(d)
	}
	g := goldens.New("transpile", "transpiler.Transpile from the corpus dialect to each target dialect, identity included", cols...)
	goldens.Parallel(len(stmts)*len(targets), func(i int) {
		st, to := stmts[i/len(targets)], targets[i%len(targets)]
		g.Add(st.File, string(to), st.Index, st.SQL, goldens.Safe(func() string {
			out, err := transpiler.Transpile(st.SQL, keywords.SQLDialect(st.Dialect), to)
			if err != nil {
				return goldens.Error(err)
			}
			return out
		}))
	})
	g.Check(t)
}
