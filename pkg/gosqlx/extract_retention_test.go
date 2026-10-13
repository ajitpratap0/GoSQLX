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
	"runtime"
	"strings"
	"testing"
	"unsafe"
	"weak"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// AST values are substrings of the parsed SQL (#546). The Extract* functions
// must return independent strings, so that keeping only their results does
// not keep a large input alive.

// retentionSQL builds a large, freshly allocated query whose identifiers are
// tiny, and returns it with a weak pointer to its backing array.
func retentionSQL() (string, weak.Pointer[byte]) {
	sql := "/* " + strings.Repeat("x", 1<<20) + " */ " +
		"SELECT u.colz, COUNT(o.id), UPPER(u.name) FROM public.tblq u " +
		"JOIN ord o ON u.id = o.uid WHERE u.flag = 'lit'"
	return sql, weak.Make(unsafe.StringData(sql))
}

// inputCollected reports whether the input behind wp has been freed.
func inputCollected(wp weak.Pointer[byte]) bool {
	runtime.GC()
	runtime.GC()
	return wp.Value() == nil
}

func TestExtract_ResultsDoNotRetainInput(t *testing.T) {
	cases := []struct {
		name    string
		extract func(*ast.AST) any
	}{
		{"ExtractTables", func(a *ast.AST) any { return ExtractTables(a) }},
		{"ExtractTablesQualified", func(a *ast.AST) any { return ExtractTablesQualified(a) }},
		{"ExtractColumns", func(a *ast.AST) any { return ExtractColumns(a) }},
		{"ExtractColumnsQualified", func(a *ast.AST) any { return ExtractColumnsQualified(a) }},
		{"ExtractFunctions", func(a *ast.AST) any { return ExtractFunctions(a) }},
		{"ExtractMetadata", func(a *ast.AST) any { return ExtractMetadata(a) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var kept any
			wp := func() weak.Pointer[byte] {
				sql, wp := retentionSQL()
				tree, err := Parse(sql)
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				kept = tc.extract(tree)
				ast.ReleaseAST(tree)
				return wp
			}()
			if !inputCollected(wp) {
				t.Errorf("%s result %v keeps the 1 MiB input alive", tc.name, kept)
			}
			runtime.KeepAlive(kept)
		})
	}
}

// TestExtract_RetentionHarnessDetectsAliasing is the positive control: a
// string sliced from the input must be reported as keeping it alive.
func TestExtract_RetentionHarnessDetectsAliasing(t *testing.T) {
	var kept string
	wp := func() weak.Pointer[byte] {
		sql, wp := retentionSQL()
		kept = sql[len(sql)-5:]
		return wp
	}()
	if inputCollected(wp) {
		t.Fatal("harness did not detect a retained substring")
	}
	runtime.KeepAlive(kept)
}
