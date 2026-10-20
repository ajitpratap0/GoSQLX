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

package advisor

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestCompositeFieldAccessAnalysis(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT (SELECT payload FROM items).name, (payload).name, (CAST(payload AS item_type)).name FROM t")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected select, got %T", tree.Statements[0])
	}
	if countSubqueries(sel.Columns[0]) != 1 || len(findWhereSubqueries(sel.Columns[0], "OPT-005")) != 1 {
		t.Fatal("field selection must not hide its scalar subquery")
	}
	if names := collectColumnNames(sel.Columns[1]); len(names) != 1 || names[0] != "payload" {
		t.Fatalf("base column references lost: %v", names)
	}
	aliases := map[string]bool{"payload": false}
	markAliasUsed(sel.Columns[1], aliases)
	if !aliases["payload"] {
		t.Fatal("composite-valued alias is used by the field selection")
	}
	if !containsCastExprInWhere(sel.Columns[2]) {
		t.Fatal("field selection must not hide a composite cast")
	}
	if len(findLeadingWildcardLike(sel.Columns[1], "OPT-007")) != 0 ||
		len(findFunctionOnColumn(sel.Columns[1], "OPT-008")) != 0 ||
		containsNotInSubquery(sel.Columns[1]) {
		t.Fatal("ordinary composite-field access must not produce predicate warnings")
	}
}
