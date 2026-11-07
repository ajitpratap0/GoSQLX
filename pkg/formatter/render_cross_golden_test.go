// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestGoldenRenderCross(t *testing.T) {
	dialects := corpusDialects()
	if len(dialects) != 8 {
		t.Fatalf("got %d target dialects, want 8", len(dialects))
	}
	styles := []string{"compact", "readable", "lower", "width"}
	entries := []string{"ast_checked", "statement_checked", "expression_checked", "ast", "statement", "expression"}
	var columns []string
	for _, d := range dialects {
		for _, style := range styles {
			for _, entry := range entries {
				columns = append(columns, d+"_"+style+"_"+entry)
			}
		}
	}
	g := goldens.New("render_cross", "cross-dialect formatter entry points", columns...)
	stmts := goldens.Corpus(t)
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		var tree *ast.AST
		var err error
		parse := goldens.Safe(func() string {
			tree, err = gosqlx.ParseWithDialect(st.SQL, keywords.SQLDialect(st.Dialect))
			return ""
		})
		if parse == "" && err == nil {
			defer ast.ReleaseAST(tree)
		}
		for _, d := range dialects {
			for _, style := range styles {
				opts := ast.CompactStyle()
				switch style {
				case "readable":
					opts = ast.ReadableStyle()
					opts.AddSemicolon = true
				case "lower":
					opts = ast.ReadableStyle()
					opts.KeywordCase = ast.KeywordLower
				case "width":
					opts = ast.ReadableStyle()
					opts.NewlinePerClause = true
					opts.LineWidth = 40
				}
				opts.Dialect = d
				for _, entry := range entries {
					out := ""
					switch {
					case parse != "":
						out = "parse: " + parse
					case err != nil:
						out = "ERR:" + err.Error()
					default:
						out = goldens.Safe(func() string { return renderCrossEntry(tree, opts, entry) })
					}
					g.Add(st.File, d+"_"+style+"_"+entry, st.Index, st.SQL, out)
				}
			}
		}
	})
	g.Check(t)
}

func renderCrossEntry(tree *ast.AST, opts ast.FormatOptions, entry string) string {
	checked := func(s string, err error) string {
		if err != nil {
			return "ERR:" + err.Error()
		}
		return s
	}
	var out []string
	switch entry {
	case "ast_checked":
		return checked(formatter.FormatASTChecked(tree, opts))
	case "ast":
		return formatter.FormatAST(tree, opts)
	}
	for _, stmt := range tree.Statements {
		switch entry {
		case "statement_checked":
			out = append(out, checked(formatter.FormatStatementChecked(stmt, opts)))
		case "statement":
			out = append(out, formatter.FormatStatement(stmt, opts))
		case "expression", "expression_checked":
			if sel, ok := stmt.(*ast.SelectStatement); ok {
				for _, expr := range sel.Columns {
					if entry == "expression" {
						out = append(out, formatter.FormatExpression(expr, opts))
					} else {
						out = append(out, checked(formatter.FormatExpressionChecked(expr, opts)))
					}
				}
			}
		default:
			panic(fmt.Sprintf("unknown entry %q", entry))
		}
	}
	return strings.Join(out, "\n---\n")
}
