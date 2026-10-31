// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// formatGoldenColumns are the renderings pinned per statement, all in the
// statement's own dialect:
//   - format, format_upper: gosqlx.FormatWithDialect (the comment-preserving
//     text path) with default options and with 4-space indent, upper-case
//     keywords and semicolons;
//   - compact, readable, lower: formatter.FormatASTChecked of the parsed tree
//     with ast.CompactStyle, ast.ReadableStyle and ReadableStyle with
//     lower-case keywords, rendered for the dialect;
//   - compact_nodialect: CompactStyle with no target dialect.
var formatGoldenColumns = []string{"format", "format_upper", "compact", "readable", "lower", "compact_nodialect"}

// TestGoldenFormat pins every formatter rendering of every benchmark corpus
// statement. Regenerate with task goldens:update; inspect a mismatch with
// task goldens:diff.
func TestGoldenFormat(t *testing.T) {
	stmts := goldens.Corpus(t)
	g := goldens.New("format", "FormatWithDialect and FormatASTChecked renderings per corpus statement", formatGoldenColumns...)
	upper := gosqlx.FormatOptions{IndentSize: 4, UppercaseKeywords: true, AddSemicolon: true}
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		d := keywords.SQLDialect(st.Dialect)
		text := func(opts gosqlx.FormatOptions) string {
			return goldens.Safe(func() string {
				out, err := gosqlx.FormatWithDialect(st.SQL, opts, d)
				if err != nil {
					return goldens.Error(err)
				}
				return out
			})
		}
		g.Add(st.File, "format", st.Index, st.SQL, text(gosqlx.DefaultFormatOptions()))
		g.Add(st.File, "format_upper", st.Index, st.SQL, text(upper))

		lower := ast.ReadableStyle()
		lower.KeywordCase = ast.KeywordLower
		styles := map[string]ast.FormatOptions{
			"compact":           ast.CompactStyle(),
			"readable":          ast.ReadableStyle(),
			"lower":             lower,
			"compact_nodialect": ast.CompactStyle(),
		}
		tree, err := gosqlx.ParseWithDialect(st.SQL, d)
		for _, col := range formatGoldenColumns[2:] {
			opts := styles[col]
			if col != "compact_nodialect" {
				opts.Dialect = st.Dialect
			}
			out := "parse: " + goldens.Error(err)
			if err == nil {
				out = goldens.Safe(func() string {
					s, ferr := formatter.FormatASTChecked(tree, opts)
					if ferr != nil {
						return s + "\nerror: " + goldens.Error(ferr)
					}
					return s
				})
			}
			g.Add(st.File, col, st.Index, st.SQL, out)
		}
		if err == nil {
			ast.ReleaseAST(tree)
		}
	})
	g.Check(t)
}
