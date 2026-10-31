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

package gosqlx

import (
	"github.com/ajitpratap0/GoSQLX/internal/scaletest"
	"reflect"
	"strings"
	"testing"
)

// TestSplitStatements_OracleAlternativeQuoting checks that the body of an
// Oracle q'[...]' literal, which may hold apostrophes and semicolons, does not
// end or hide a statement.
func TestSplitStatements_OracleAlternativeQuoting(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		dialect string
		want    []string
	}{
		{"apostrophe in body", "SELECT q'[It's quoted]' FROM dual; SELECT 'O''Brien' FROM dual;", "oracle",
			[]string{"SELECT q'[It's quoted]' FROM dual", " SELECT 'O''Brien' FROM dual"}},
		{"semicolon in body", "SELECT q'(a;b)' FROM dual; SELECT 2 FROM dual", "oracle",
			[]string{"SELECT q'(a;b)' FROM dual", " SELECT 2 FROM dual"}},
		{"national and other delimiters", "SELECT nq'#x;y#', Q'{z}' FROM dual; SELECT 3 FROM dual", "oracle",
			[]string{"SELECT nq'#x;y#', Q'{z}' FROM dual", " SELECT 3 FROM dual"}},
		{"identifier ending in q is not a quote", "SELECT seq'a;b' FROM dual", "oracle",
			[]string{"SELECT seq'a;b' FROM dual"}},
		{"other dialects keep their rules", "SELECT q'x'; SELECT 1", "postgresql",
			[]string{"SELECT q'x'", " SELECT 1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SplitStatements(tc.sql, tc.dialect); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SplitStatements(%q, %q)\n got: %q\nwant: %q", tc.sql, tc.dialect, got, tc.want)
			}
		})
	}
}

// TestSplitStatements_OracleQuoteUnterminatedLinear guards against quadratic
// behaviour on unterminated q-quotes (each used to rescan to end of input).
func TestSplitStatements_OracleQuoteUnterminatedLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	assertSplitLinear(t, "bare", func(n int) string { return strings.Repeat("q'(a';", n) }, "oracle", 10000)
	assertSplitLinear(t, "select", func(n int) string { return strings.Repeat("SELECT q'(a' FROM dual;\n", n) }, "oracle", 10000)
}

// assertSplitLinear fails when splitting gen(4n) takes much more than four
// times as long as gen(n): linear work grows about 4x, quadratic work 16x. A
// ratio, unlike a wall-clock bound, holds on slow or race-instrumented CI
// runners, and scaletest repeats the measurement so a load spike cannot fail
// it on its own.
func assertSplitLinear(t *testing.T, name string, gen func(n int) string, dialect string, n int) {
	t.Helper()
	smallSrc, largeSrc := gen(n), gen(4*n)
	scaletest.AssertLinearGrowth(t, name, 10,
		func() { SplitStatements(smallSrc, dialect) },
		func() { SplitStatements(largeSrc, dialect) })
}

// TestSplitStatements_OracleQuoteMemoDoesNotHideLiterals checks that a failed
// search for one closer does not suppress later valid literals with another.
func TestSplitStatements_OracleQuoteMemoDoesNotHideLiterals(t *testing.T) {
	got := SplitStatements("SELECT q'(a' FROM t; SELECT q'[x;y]' FROM dual; SELECT 1", "oracle")
	want := []string{"SELECT q'(a' FROM t", " SELECT q'[x;y]' FROM dual", " SELECT 1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// Terminated literal first, unterminated of the same closer afterwards.
	got = SplitStatements("SELECT q'(a;b)' FROM dual; SELECT q'(c' FROM dual; SELECT 2", "oracle")
	if len(got) < 2 || got[0] != "SELECT q'(a;b)' FROM dual" {
		t.Errorf("terminated literal split wrongly: %q", got)
	}
}

// TestSplitStatements_DelimiterLength covers the MySQL DELIMITER length cap.
func TestSplitStatements_DelimiterLength(t *testing.T) {
	got := SplitStatements("DELIMITER //\nSELECT 1; SELECT 2//\nDELIMITER ;\nSELECT 3;", "mysql")
	want := []string{"SELECT 1; SELECT 2", "SELECT 3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normal DELIMITER: got %q, want %q", got, want)
	}
	if testing.Short() {
		return
	}
	assertSplitLinear(t, "huge delimiter", func(n int) string {
		return "DELIMITER " + strings.Repeat("(", n) + "x\n" + strings.Repeat("(", 3*n)
	}, "mysql", 60000)
}
