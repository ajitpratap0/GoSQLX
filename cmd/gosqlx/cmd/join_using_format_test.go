// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatCommand_JoinUsing_Issue603 is the regression test for #603:
// `gosqlx format` printed JOIN ... USING (cols) as "ON cols" (or "ON LIST"
// for several columns).
func TestFormatCommand_JoinUsing_Issue603(t *testing.T) {
	cases := []struct {
		in           string
		wantCompact  string
		wantReadable string
		wantUsing    []string
	}{
		{
			in:           "SELECT * FROM a JOIN b USING (id)",
			wantCompact:  "SELECT * FROM a INNER JOIN b USING (id)",
			wantReadable: "SELECT *\nFROM a\nINNER JOIN b USING (id)",
			wantUsing:    []string{"id"},
		},
		{
			in:           "SELECT * FROM a LEFT JOIN b USING (id, k)",
			wantCompact:  "SELECT * FROM a LEFT JOIN b USING (id, k)",
			wantReadable: "SELECT *\nFROM a\nLEFT JOIN b USING (id, k)",
			wantUsing:    []string{"id", "k"},
		},
	}

	modes := []struct {
		name    string
		opts    CLIFormatterOptions
		compact bool
	}{
		{"compact", CLIFormatterOptions{Compact: true, Uppercase: true}, true},
		{"readable", CLIFormatterOptions{IndentSize: 2, Uppercase: true}, false},
	}

	for _, tc := range cases {
		for _, m := range modes {
			t.Run(m.name+"/"+tc.in, func(t *testing.T) {
				var out, errBuf bytes.Buffer
				f := NewFormatter(&out, &errBuf, m.opts)
				got, err := f.formatSQL(tc.in)
				if err != nil {
					t.Fatalf("formatSQL(%q): %v", tc.in, err)
				}
				got = strings.TrimSpace(got)
				want := tc.wantReadable
				if m.compact {
					want = tc.wantCompact
				}
				if strings.TrimSuffix(got, ";") != want {
					t.Fatalf("formatSQL mismatch\n got: %q\nwant: %q", got, want)
				}
				if strings.Contains(got, "ON LIST") || strings.Contains(got, " ON id") {
					t.Fatalf("output still renders USING as ON: %q", got)
				}

				tree, err := gosqlx.ParseWithDialect(got, keywords.DialectGeneric)
				if err != nil {
					t.Fatalf("re-parse of %q failed: %v", got, err)
				}
				sel, ok := tree.Statements[0].(*ast.SelectStatement)
				if !ok {
					t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
				}
				if len(sel.Joins) != 1 {
					t.Fatalf("re-parsed %d joins, want 1", len(sel.Joins))
				}
				j := sel.Joins[0]
				if j.Condition != nil || len(j.Using) != len(tc.wantUsing) {
					t.Fatalf("re-parsed join: Condition=%T len(Using)=%d, want nil and %d", j.Condition, len(j.Using), len(tc.wantUsing))
				}
				for i, name := range tc.wantUsing {
					id, ok := j.Using[i].(*ast.Identifier)
					if !ok || id.Name != name {
						t.Fatalf("re-parsed Using[%d] = %#v, want identifier %q", i, j.Using[i], name)
					}
				}
			})
		}
	}
}

// TestAnalyzer_JoinUsingHasCondition_Issue603 checks that the analyzer does
// not treat a USING join as a condition-less (cartesian) join.
func TestAnalyzer_JoinUsingHasCondition_Issue603(t *testing.T) {
	analyze := func(t *testing.T, sql string) (*SQLAnalyzer, *AnalysisReport) {
		t.Helper()
		tree, err := gosqlx.Parse(sql)
		if err != nil {
			t.Fatalf("parse %q: %v", sql, err)
		}
		a := NewSQLAnalyzer()
		report, err := a.Analyze(tree)
		if err != nil {
			t.Fatalf("Analyze: %v", err)
		}
		return a, report
	}
	hasIssue := func(r *AnalysisReport, id string) bool {
		for _, is := range r.Issues {
			if is.ID == id {
				return true
			}
		}
		return false
	}

	for _, sql := range []string{
		"SELECT * FROM a JOIN b USING (id)",
		"SELECT * FROM a LEFT JOIN b USING (id, k)",
	} {
		a, r := analyze(t, sql)
		if hasIssue(r, "JOIN_WITHOUT_CONDITION") || a.hasCartesian {
			t.Errorf("%q: USING join reported as condition-less (hasCartesian=%v)", sql, a.hasCartesian)
		}
	}

	a, r := analyze(t, "SELECT * FROM a CROSS JOIN b")
	if !hasIssue(r, "JOIN_WITHOUT_CONDITION") || !a.hasCartesian {
		t.Errorf("CROSS JOIN should still be reported as condition-less (hasCartesian=%v)", a.hasCartesian)
	}
}
