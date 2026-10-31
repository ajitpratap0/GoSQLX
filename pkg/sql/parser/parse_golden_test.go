// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestGoldenParse pins, for every benchmark corpus statement under every
// accepted dialect (bigquery and redshift included):
//   - the gosqlx.ParseWithDialect result: error code, location, hint and
//     message, or the rendered AST.SQL();
//   - every models.Location reachable from the AST (node Pos fields,
//     statement starts and ends, comment spans), which SQL() does not show;
//   - the parser.ValidateWithDialect verdict, which takes a separate path.
//
// Regenerate with task goldens:update; inspect a mismatch with task goldens:diff.
func TestGoldenParse(t *testing.T) {
	stmts := goldens.Corpus(t)
	dialects := goldens.Dialects()
	g := goldens.New("parse", "ParseWithDialect SQL()/error + AST positions + ValidateWithDialect per corpus statement and dialect", dialects...)
	goldens.Parallel(len(stmts)*len(dialects), func(i int) {
		st, d := stmts[i/len(dialects)], keywords.SQLDialect(dialects[i%len(dialects)])
		out := goldens.Safe(func() string { return parseDump(st.SQL, d) })
		g.Add(st.File, string(d), st.Index, st.SQL, out)
	})
	g.Check(t)
}

func parseDump(sql string, d keywords.SQLDialect) string {
	var b strings.Builder
	tree, err := gosqlx.ParseWithDialect(sql, d)
	if err != nil {
		b.WriteString("parse: ")
		b.WriteString(goldens.Error(err))
	} else {
		b.WriteString("parse: ok\nsql: ")
		b.WriteString(tree.SQL())
		b.WriteString("\npositions:\n")
		b.WriteString(goldens.Positions(tree))
		ast.ReleaseAST(tree)
	}
	b.WriteString("\nvalidate: ")
	b.WriteString(goldens.Error(parser.ValidateWithDialect(sql, d)))
	return b.String()
}
