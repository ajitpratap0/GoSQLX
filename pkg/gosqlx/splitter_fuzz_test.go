// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gosqlx

import "testing"

// FuzzSplitStatements checks that SplitStatements never panics and that its
// output always tiles the input: the segments are the exact byte ranges
// between top-level semicolons, so nothing is dropped, duplicated or altered.
//
// Run with: go test ./pkg/gosqlx -run xxx -fuzz FuzzSplitStatements -fuzztime 30s
func FuzzSplitStatements(f *testing.F) {
	// Seed corpus: representative inputs for each dialect profile, including
	// the unterminated-context and escape edge cases.
	seeds := []struct{ sql, dialect string }{
		{"", ""},
		{";", ""},
		{";;;", ""},
		{"SELECT 1;", ""},
		{"SELECT 1;  \n", ""},
		{"SELECT 1; SELECT 2", ""},
		{"SELECT 'a;b'; SELECT 1", ""},
		{"SELECT 'it''s;x'; SELECT 1", ""},
		{"-- c ; c\nSELECT 1", ""},
		{"/* ; */ SELECT 1; SELECT 2", ""},
		{"/* /* a; */ ; */ SELECT 1; SELECT 2", "postgresql"},
		{"DO $body$ BEGIN PERFORM 'a;b'; END $body$; SELECT 1", "postgresql"},
		{"SELECT $$open ; SELECT 2", "postgresql"},
		{"SELECT E'\\''; SELECT 1", "postgresql"},
		{"SELECT `c;n` FROM t; SELECT 1", "mysql"},
		{"SELECT [c;n] FROM t; SELECT 1", "sqlserver"},
		{"SELECT `open ; x", "mysql"},
		{"SELECT [open ; x", "sqlserver"},
		{"SELECT $", "postgresql"},
		{"E'", "postgresql"},
		{"'", ""},
		{"--", ""},
	}
	for _, s := range seeds {
		f.Add(s.sql, s.dialect)
	}

	f.Fuzz(func(t *testing.T, src, dialect string) {
		segs := SplitStatements(src, dialect)
		if msg, ok := checkTiling(src, segs); !ok {
			t.Fatalf("SplitStatements(%q, %q) = %q: %s", src, dialect, segs, msg)
		}
	})
}
