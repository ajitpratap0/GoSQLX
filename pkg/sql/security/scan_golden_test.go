// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"
)

// TestGoldenSecurity pins the findings and counts of Scanner.ScanSQL (raw
// text) and Scanner.Scan (the AST parsed in the statement's own dialect) for
// every benchmark corpus statement. Regenerate with task goldens:update;
// inspect a mismatch with task goldens:diff.
func TestGoldenSecurity(t *testing.T) {
	stmts := goldens.Corpus(t)
	g := goldens.New("security", "security Scanner.ScanSQL and Scanner.Scan findings per corpus statement", "scan_sql", "scan_ast")
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		g.Add(st.File, "scan_sql", st.Index, st.SQL, goldens.Safe(func() string {
			return scanDump(security.NewScanner().ScanSQL(st.SQL))
		}))
		g.Add(st.File, "scan_ast", st.Index, st.SQL, goldens.Safe(func() string {
			tree, err := gosqlx.ParseWithDialect(st.SQL, keywords.SQLDialect(st.Dialect))
			if err != nil {
				return "parse: " + goldens.Error(err)
			}
			defer ast.ReleaseAST(tree)
			return scanDump(security.NewScanner().Scan(tree))
		}))
	})
	g.Check(t)
}

func scanDump(r *security.ScanResult) string {
	if r == nil {
		return "nil"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "total=%d critical=%d high=%d medium=%d low=%d\n",
		r.TotalCount, r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount)
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "%s %s %d:%d %q risk=%q sql=%q suggestion=%q\n",
			f.Severity, f.Pattern, f.Line, f.Column, f.Description, f.Risk, f.SQL, f.Suggestion)
	}
	return b.String()
}
