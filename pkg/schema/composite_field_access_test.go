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

package schema

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestCompositeFieldAccessValidation(t *testing.T) {
	v := NewValidator(helperSchema())
	errs, err := v.Validate("SELECT (make_item(missing_column)).name FROM users")
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) == 0 {
		t.Fatal("a field selection must not hide an invalid function argument column")
	}

	tree, err := gosqlx.Parse("SELECT (array_agg(name)).item FROM users")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected select, got %T", tree.Statements[0])
	}
	expr := sel.Columns[0]
	if !isAggregateExpr(expr) {
		t.Fatal("field selection must not hide an aggregate")
	}
	if refs := collectColumnRefs(expr); len(refs) != 1 || refs[0] != "name" {
		t.Fatalf("expected base column name, got %v", refs)
	}
	line, column := extractExprPos(expr)
	if line != 1 || column != 25 {
		t.Fatalf("field access position = %d:%d, want 1:25", line, column)
	}
}
