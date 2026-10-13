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
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestParse_LongCommentRun checks that Parse handles a long run of
// consecutive comments before a statement with a small stack limit.
func TestParse_LongCommentRun(t *testing.T) {
	prev := debug.SetMaxStack(64 << 20)
	defer debug.SetMaxStack(prev)

	// Comments count toward MaxTokens, so stay below it.
	const n = 900_000
	for _, unit := range []string{"--\n", "/**/"} {
		tree, err := Parse(strings.Repeat(unit, n) + "SELECT 1")
		if err != nil {
			t.Fatalf("Parse(%d x %q + SELECT 1): %v", n, unit, err)
		}
		if len(tree.Statements) != 1 {
			t.Fatalf("got %d statements, want 1", len(tree.Statements))
		}
		if _, ok := tree.Statements[0].(*ast.SelectStatement); !ok {
			t.Fatalf("expected *ast.SelectStatement, got %T", tree.Statements[0])
		}
	}
}
