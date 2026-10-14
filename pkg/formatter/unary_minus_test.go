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

package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestFormatStatement_NestedUnaryMinus checks that nested unary minus is not
// rendered as "--", which starts a line comment and silently drops the rest
// of the line, and that the output re-parses to the same query.
func TestFormatStatement_NestedUnaryMinus(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"SELECT - -1 FROM t", "SELECT - -1 FROM t"},
		{"SELECT a FROM t WHERE b = - -1", "SELECT a FROM t WHERE b = - -1"},
		{"SELECT - - -x FROM t", "SELECT - - -x FROM t"},
		{"SELECT -(-x) FROM t", "SELECT -(-x) FROM t"},
		{"SELECT - -x + 1 FROM t", "SELECT - -x + 1 FROM t"},
	}
	style := ast.CompactStyle()
	style.KeywordCase = ast.KeywordUpper
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			tree, err := gosqlx.Parse(tc.in)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			if len(tree.Statements) != 1 {
				t.Fatalf("parse %q: expected 1 statement, got %d", tc.in, len(tree.Statements))
			}
			got := formatter.FormatStatement(tree.Statements[0], style)
			if got != tc.want {
				t.Fatalf("FormatStatement(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "--") {
				t.Fatalf("FormatStatement(%q) = %q contains a line comment marker", tc.in, got)
			}
			again, err := gosqlx.Parse(got)
			if err != nil {
				t.Fatalf("output %q does not re-parse: %v", got, err)
			}
			if a, b := tree.SQL(), again.SQL(); a != b {
				t.Fatalf("output changes the query: %q -> %q", a, b)
			}
		})
	}
}
