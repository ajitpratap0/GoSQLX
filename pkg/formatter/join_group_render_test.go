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

package formatter

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestJoinGroupRender checks that a parenthesized join group used as a join
// operand is rendered whole, in compact and readable layouts and with
// lowercase keywords, and that the output parses back to the same text.
func TestJoinGroupRender(t *testing.T) {
	const in = "SELECT * FROM a LEFT JOIN (b JOIN c ON b.id = c.b_id, d) ON a.id = b.a_id WHERE a.x = 1"
	tree, err := parser.ParseWithDialect(in, keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)

	styles := map[string]ast.FormatOptions{
		"compact":  ast.CompactStyle(),
		"readable": ast.ReadableStyle(),
	}
	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	styles["lower"] = lower

	for name, opts := range styles {
		opts.Dialect = "mysql"
		out := FormatAST(tree, opts)
		if !strings.Contains(strings.ToUpper(out), "(B INNER JOIN C ON B.ID = C.B_ID, D)") &&
			!strings.Contains(strings.ToUpper(out), "(B INNER JOIN C ON B.ID = C.B_ID , D)") {
			t.Errorf("%s: group not rendered whole: %s", name, out)
		}
		tree2, err := parser.ParseWithDialect(out, keywords.DialectMySQL)
		if err != nil {
			t.Errorf("%s: output %q does not re-parse: %v", name, out, err)
			continue
		}
		compact := ast.CompactStyle()
		compact.Dialect = "mysql"
		if got, want := FormatAST(tree2, compact), FormatAST(tree, compact); got != want {
			t.Errorf("%s: output re-parses to %q, want %q", name, got, want)
		}
		ast.ReleaseAST(tree2)
	}
}
