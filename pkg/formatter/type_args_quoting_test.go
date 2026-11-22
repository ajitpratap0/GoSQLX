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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestTypeArgsKeepQuoteKinds checks that parenthesised argument text the
// parser keeps as written (ClickHouse PROJECTION bodies, engine arguments,
// type arguments) keeps the delimiters of its names and the escapes of its
// strings: "x" must not become the string 'x', and `x` must not lose its
// backticks.
func TestTypeArgsKeepQuoteKinds(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"projection double quotes", `CREATE TABLE t (a Int32, PROJECTION p (SELECT "a", sum("a") GROUP BY "a")) ENGINE=MergeTree ORDER BY a`},
		{"projection backticks", "CREATE TABLE t (a Int32, PROJECTION p (SELECT `a`, sum(`a`) GROUP BY `a`)) ENGINE=MergeTree ORDER BY a"},
		{"projection string stays string", `CREATE TABLE t (a Int32, PROJECTION p (SELECT 'a', "a" GROUP BY "a")) ENGINE=MergeTree ORDER BY a`},
		{"projection doubled delimiters", "CREATE TABLE t (a Int32, PROJECTION p (SELECT `x``y` GROUP BY `x``y`)) ENGINE=MergeTree ORDER BY a"},
		{"engine args with identifiers", "CREATE TABLE t (a Int32) ENGINE=Distributed(cluster, `db`, \"t\", rand())"},
		{"engine args escaped quote", "CREATE TABLE t (a Int32) ENGINE=ReplicatedMergeTree('/p/it''s', '{replica}') ORDER BY a"},
		{"engine args empty string", "CREATE TABLE t (a Int32) ENGINE=Foo('', 'x')"},
		{"named tuple elements", "CREATE TABLE t (a Tuple(`x y` UInt8, \"z\" String)) ENGINE=Memory"},
		{"enum with empty member", "CREATE TABLE t (a Enum8('' = 0, 'b' = 1)) ENGINE=Memory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tc.in, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			defer ast.ReleaseAST(tree)
			if got := tree.SQL(); got != tc.in {
				t.Errorf("SQL()\n got: %s\nwant: %s", got, tc.in)
			}
			style := ast.CompactStyle()
			style.Dialect = string(keywords.DialectClickHouse)
			if got := formatter.FormatStatement(tree.Statements[0], style); got != tc.in {
				t.Errorf("FormatStatement\n got: %s\nwant: %s", got, tc.in)
			}
		})
	}
}
