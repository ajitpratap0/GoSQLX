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
	"strings"
	"testing"
)

// TestRealworldDroppedWords pins what the corpus drop detector accepts as a
// canonical spelling and what it still reports.
func TestRealworldDroppedWords(t *testing.T) {
	tests := []struct {
		name, in, out string
		lost          string // space-separated, "" when nothing is lost
	}{
		{"select all", "SELECT ALL a FROM t", "SELECT a FROM t", ""},
		{"union all is not a synonym", "SELECT a FROM t UNION ALL SELECT a FROM u", "SELECT a FROM t UNION SELECT a FROM u", "ALL"},
		{"oracle select unique", "SELECT UNIQUE a FROM t", "SELECT DISTINCT a FROM t", ""},
		{"distinctrow", "SELECT DISTINCTROW a FROM t", "SELECT DISTINCT a FROM t", ""},
		{"postfix isnull", "SELECT a FROM t WHERE a ISNULL", "SELECT a FROM t WHERE a IS NULL", ""},
		{"postfix notnull", "SELECT a FROM t WHERE a NOTNULL", "SELECT a FROM t WHERE a IS NOT NULL", ""},
		{"isnull function is not a synonym", "SELECT ISNULL(a, 0) FROM t", "SELECT a FROM t", "ISNULL"},
		{"dollar quoted strings", "SELECT $$dollar quoted$$, $tag$ body 'with' quotes $tag$", "SELECT 'dollar quoted', ' body ''with'' quotes '", ""},
		{"dropped clause", "SELECT a FROM t WHERE b = 1", "SELECT a FROM t", "WHERE B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(realworldDroppedWords(tc.in, tc.out), " ")
			if got != tc.lost {
				t.Errorf("lost words = %q, want %q", got, tc.lost)
			}
		})
	}
}
