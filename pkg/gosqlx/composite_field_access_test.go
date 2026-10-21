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

package gosqlx_test

import (
	"context"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestCompositeFieldAccessTreeClone(t *testing.T) {
	tree, err := gosqlx.ParseTree(context.Background(), "SELECT (make_item(payload)).name FROM t")
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Release()
	if names := gosqlx.ExtractFunctions(tree.Raw()); len(names) != 1 || names[0] != "make_item" {
		t.Fatalf("field selection lost its function metadata: %v", names)
	}
	if columns := gosqlx.ExtractColumns(tree.Raw()); len(columns) != 1 || columns[0] != "payload" {
		t.Fatalf("field selection lost its column metadata: %v", columns)
	}
	clone := tree.Clone()
	if clone == nil {
		t.Fatal("Clone must preserve a composite-field expression")
	}
	defer clone.Release()
	calls := 0
	clone.WalkFunctionCalls(func(fn *ast.FunctionCall) bool { calls++; fn.Name = "changed"; return true })
	if calls != 1 {
		t.Fatalf("expected one function call in clone, got %d", calls)
	}
	tree.WalkFunctionCalls(func(fn *ast.FunctionCall) bool {
		if fn.Name != "make_item" {
			t.Fatal("mutating the clone must not change the original")
		}
		return true
	})
}
