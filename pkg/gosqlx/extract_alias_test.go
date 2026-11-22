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
	"slices"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestExtractColumns_SelectAliasScope(t *testing.T) {
	tests := []struct {
		name, sql          string
		columns, qualified []string
	}{
		{"join aggregate", "SELECT u.id, COUNT(o.id) AS orders FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.id ORDER BY orders DESC", []string{"id", "user_id"}, []string{"o.id", "o.user_id", "u.id"}},
		{"count order", "SELECT COUNT(*) AS total FROM t ORDER BY total", nil, nil},
		{"having arithmetic", "SELECT price * qty AS amount FROM items HAVING amount > 10", []string{"price", "qty"}, nil},
		{"count alone", "SELECT COUNT(*) AS total FROM t", nil, nil},
		{"qualified", "SELECT a AS total FROM t ORDER BY t.total", []string{"a", "total"}, []string{"a", "t.total"}},
		{"derived table", "SELECT total FROM (SELECT COUNT(*) AS total FROM t) s ORDER BY total", []string{"total"}, nil},
		{"inner alias", "SELECT x FROM t WHERE x IN (SELECT y AS x FROM u) ORDER BY x", []string{"x", "y"}, nil},
		{"outer alias", "SELECT a AS b FROM t WHERE EXISTS (SELECT 1 FROM u ORDER BY b)", []string{"a", "b"}, nil},
		{"cte", "WITH c AS (SELECT n AS total FROM t ORDER BY total) SELECT total FROM c", []string{"n", "total"}, nil},
		{"order expression", "SELECT a + 1 AS s FROM t ORDER BY s DESC, b", []string{"a", "b"}, nil},
		{"having aggregate", "SELECT dept, SUM(x) AS s FROM t GROUP BY dept HAVING s > 1 AND MAX(y) > 2", []string{"dept", "x", "y"}, nil},
		{"case folding", "SELECT a AS Total FROM t ORDER BY TOTAL + 1", []string{"a"}, nil},
		{"where unchanged", "SELECT a AS b FROM t WHERE b > 0 ORDER BY b", []string{"a", "b"}, nil},
		{"group unchanged", "SELECT a AS b FROM t GROUP BY b ORDER BY b", []string{"a", "b"}, nil},
		{"select unchanged", "SELECT a AS b, b FROM t ORDER BY b", []string{"a", "b"}, nil},
		{"join unchanged", "SELECT t.a AS b FROM t JOIN u ON b = u.x ORDER BY b", []string{"a", "b", "x"}, []string{"b", "t.a", "u.x"}},
		{"order subquery", "SELECT a AS b FROM t ORDER BY (SELECT b FROM u)", []string{"a", "b"}, nil},
		{"having subquery", "SELECT a AS b FROM t HAVING b > (SELECT b FROM u)", []string{"a", "b"}, nil},
		{"union branches", "(SELECT a AS b FROM t ORDER BY b) UNION (SELECT c FROM u ORDER BY b)", []string{"a", "b", "c"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := Parse(tt.sql)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			defer ast.ReleaseAST(tree)
			if got := ExtractColumns(tree); !slices.Equal(got, tt.columns) {
				t.Errorf("ExtractColumns = %v, want %v", got, tt.columns)
			}
			wantQualified := tt.qualified
			if wantQualified == nil {
				wantQualified = tt.columns
			}
			gotQualified := ExtractColumnsQualified(tree)
			names := make([]string, len(gotQualified))
			for i, q := range gotQualified {
				names[i] = q.String()
			}
			if !slices.Equal(names, wantQualified) {
				t.Errorf("ExtractColumnsQualified = %v, want %v", names, wantQualified)
			}
		})
	}
}
