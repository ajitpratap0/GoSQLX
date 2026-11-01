// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package linter_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestGoldenLint pins every violation (rule, name, severity, location,
// message, suggestion, auto-fix flag and line text) and the error of the
// all-rules linter for every benchmark corpus statement, both through
// gosqlx.LintWithDialect in the statement's own dialect and through the
// dialect-free gosqlx.Lint. Regenerate with task goldens:update; inspect a
// mismatch with task goldens:diff.
func TestGoldenLint(t *testing.T) {
	stmts := goldens.Corpus(t)
	g := goldens.New("lint", "gosqlx.LintWithDialect (own dialect) and gosqlx.Lint violations per corpus statement", "lint", "lint_default")
	goldens.Parallel(len(stmts), func(i int) {
		st := stmts[i]
		g.Add(st.File, "lint", st.Index, st.SQL, goldens.Safe(func() string {
			return lintDump(gosqlx.LintWithDialect(st.SQL, keywords.SQLDialect(st.Dialect)))
		}))
		g.Add(st.File, "lint_default", st.Index, st.SQL, goldens.Safe(func() string {
			return lintDump(gosqlx.Lint(st.SQL))
		}))
	})
	g.Check(t)
}

func lintDump(res *gosqlx.LintResult, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "error: %s\n", goldens.Error(err))
	if res == nil {
		b.WriteString("result: nil\n")
		return b.String()
	}
	for _, v := range res.Violations {
		fmt.Fprintf(&b, "%s %q %s %d:%d %q suggestion=%q autofix=%t line=%q\n",
			v.Rule, v.RuleName, v.Severity, v.Location.Line, v.Location.Column,
			v.Message, v.Suggestion, v.CanAutoFix, v.Line)
	}
	return b.String()
}
