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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFormatCommand_NamedWindows is a regression test for the adversarial
// review of PR #629 (#608): the `gosqlx format` CLI renderer dropped the
// base window of OVER (w ...), rendered OVER w as OVER (), and never emitted
// the WINDOW clause, silently changing query semantics (and `format -i`
// overwrote the file with the altered SQL).
func TestFormatCommand_NamedWindows(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // exact compact uppercase output
	}{
		{
			name: "refined base window",
			in:   "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "parenthesized base window only",
			in:   "SELECT sum(x) OVER (w) FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER (w) FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "bare named window",
			in:   "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)",
			want: "SELECT sum(x) OVER w FROM t WINDOW w AS (PARTITION BY y)",
		},
		{
			name: "window refining another window",
			in:   "SELECT sum(x) OVER w2 FROM t WINDOW w1 AS (PARTITION BY y), w2 AS (w1 ORDER BY z ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)",
			want: "SELECT sum(x) OVER w2 FROM t WINDOW w1 AS (PARTITION BY y), w2 AS (w1 ORDER BY z ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)",
		},
		{
			name: "window clause before order by",
			in:   "SELECT a, rank() OVER w FROM t WHERE a > 1 GROUP BY a HAVING count(*) > 1 WINDOW w AS (ORDER BY a DESC) ORDER BY a LIMIT 5",
			want: "SELECT a, rank() OVER w FROM t WHERE a > 1 GROUP BY a HAVING count(*) > 1 WINDOW w AS (ORDER BY a DESC) ORDER BY a LIMIT 5",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			f := NewFormatter(&out, &errBuf, CLIFormatterOptions{Compact: true, Uppercase: true})

			got, err := f.formatSQL(tc.in)
			if err != nil {
				t.Fatalf("formatSQL(%q) failed: %v", tc.in, err)
			}
			got = strings.TrimSpace(got)
			if got != tc.want {
				t.Fatalf("formatSQL mismatch\n got: %q\nwant: %q", got, tc.want)
			}

			again, err := f.formatSQL(got)
			if err != nil {
				t.Fatalf("formatSQL(%q) (second pass) failed: %v", got, err)
			}
			if strings.TrimSpace(again) != got {
				t.Fatalf("formatting is not idempotent\nfirst:  %q\nsecond: %q", got, strings.TrimSpace(again))
			}
		})
	}
}

// TestFormatCommand_NamedWindowsInPlace checks that `format -i` (non-compact
// layout) keeps the base window reference and the WINDOW clause instead of
// overwriting the file with SQL that has a different meaning.
func TestFormatCommand_NamedWindowsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.sql")
	in := "SELECT sum(x) OVER (w ORDER BY z) FROM t WINDOW w AS (PARTITION BY y);"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	f := NewFormatter(&out, &errBuf, CLIFormatterOptions{InPlace: true, IndentSize: 2, Uppercase: true})
	if _, err := f.Format([]string{path}); err != nil {
		t.Fatalf("Format failed: %v (stderr: %s)", err, errBuf.String())
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{"OVER (w ORDER BY z)", "WINDOW w AS (PARTITION BY y)"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatted file lost %q:\n%s", want, got)
		}
	}
}
