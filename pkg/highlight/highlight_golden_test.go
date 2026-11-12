// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package highlight_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestGoldenHighlight(t *testing.T) {
	stmts := goldens.Corpus(t)
	dialects := goldens.Dialects()
	g := goldens.New("highlight", "highlight.Spans per corpus statement and dialect, full statement and half-length prefix (error recovery)", dialects...)
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		for _, d := range dialects {
			g.Add(st.File, d, st.Index, st.SQL, goldens.Safe(func() string {
				var b strings.Builder
				writeSpans := func(sql string) {
					for _, span := range highlight.Spans(sql, highlight.WithDialect(keywords.SQLDialect(d))) {
						fmt.Fprintf(&b, "%d %d %s\n", span.Start, span.End, span.Category)
					}
				}
				writeSpans(st.SQL)
				b.WriteString("--- prefix ---\n")
				writeSpans(st.SQL[:len(st.SQL)/2])
				return b.String()
			}))
		}
	})
	g.Check(t)
}
