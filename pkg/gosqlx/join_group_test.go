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

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestExtractTables_JoinGroup checks that ExtractTables lists the tables
// inside a parenthesized join group.
func TestExtractTables_JoinGroup(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{"group with join", "SELECT * FROM a LEFT JOIN (b JOIN c ON b.id = c.b_id) ON a.id = b.a_id", []string{"a", "b", "c"}},
		{"comma list", "SELECT * FROM t1 LEFT JOIN (t2, t3) ON t1.id = t2.id", []string{"t1", "t2", "t3"}},
		{"nested", "SELECT * FROM t1 JOIN (t2 LEFT JOIN (t3 JOIN t4 ON t3.a = t4.a) ON t2.b = t3.b) ON t1.c = t2.c", []string{"t1", "t2", "t3", "t4"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectMySQL)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			got := ExtractTables(tree)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractTables = %v, want %v", got, tc.want)
			}
		})
	}
}
