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
	"reflect"
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
