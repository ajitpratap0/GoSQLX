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

// defaultColumn is the parse golden column for the dialect-free entry points.
const defaultColumn = "default"

// TestGoldenParse pins, for every benchmark corpus statement under every
// accepted dialect (bigquery and redshift included):
//   - the gosqlx.ParseWithDialect result: error code, location, hint and
//     message, or the rendered AST.SQL();
//   - every models.Location reachable from the AST (node Pos fields,
//     statement starts and ends, comment spans), which SQL() does not show;
//   - the parser.ValidateWithDialect verdict, which takes a separate path.
//
// The extra "default" column pins the same for the dialect-free entry points,
// which run separate code: gosqlx.Parse (tokscratch.String and
// ParseFromModelTokens, with its own ErrTokenize/ErrSyntax wrapping), the
// parser.Validate fast path and gosqlx.Validate.
//
// Regenerate with task goldens:update; inspect a mismatch with task goldens:diff.
func TestGoldenParse(t *testing.T) {
	stmts := goldens.Corpus(t)
	dialects := goldens.Dialects()
	cols := append(append([]string(nil), dialects...), defaultColumn)
	g := goldens.New("parse", "ParseWithDialect SQL()/error + AST positions + ValidateWithDialect per corpus statement and dialect; default = Parse + parser.Validate + gosqlx.Validate", cols...)
	goldens.Parallel(len(stmts)*len(cols), func(i int) {
		st, col := stmts[i/len(cols)], cols[i%len(cols)]
		out := goldens.Safe(func() string {
			if col == defaultColumn {
				return parseDumpDefault(st.SQL)
			}
			return parseDump(st.SQL, keywords.SQLDialect(col))
		})
		g.Add(st.File, col, st.Index, st.SQL, out)
	})
	g.Check(t)
}

func parseDump(sql string, d keywords.SQLDialect) string {
	var b strings.Builder
	tree, err := gosqlx.ParseWithDialect(sql, d)
	writeParseResult(&b, tree, err)
	b.WriteString("\nvalidate: ")
	b.WriteString(goldens.Error(parser.ValidateWithDialect(sql, d)))
	return b.String()
}

// parseDumpDefault renders the dialect-free entry points.
func parseDumpDefault(sql string) string {
	var b strings.Builder
	tree, err := gosqlx.Parse(sql)
	writeParseResult(&b, tree, err)
	b.WriteString("\nvalidate: ")
	b.WriteString(goldens.Error(parser.Validate(sql)))
	b.WriteString("\ngosqlx.validate: ")
	b.WriteString(goldens.Error(gosqlx.Validate(sql)))
	return b.String()
}

// writeParseResult writes the error, or the SQL() and positions of tree and
// releases it.
func writeParseResult(b *strings.Builder, tree *ast.AST, err error) {
	if err != nil {
		b.WriteString("parse: ")
		b.WriteString(goldens.Error(err))
		return
	}
	b.WriteString("parse: ok\nsql: ")
	b.WriteString(tree.SQL())
	b.WriteString("\npositions:\n")
	b.WriteString(goldens.Positions(tree))
	ast.ReleaseAST(tree)
}
