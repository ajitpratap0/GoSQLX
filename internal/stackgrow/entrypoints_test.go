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

package stackgrow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	typ := fn.Recv.List[0].Type
	if pointer, ok := typ.(*ast.StarExpr); ok {
		typ = pointer.X
	}
	if name, ok := typ.(*ast.Ident); ok {
		return name.Name
	}
	return ""
}

func startsWithReserve(fn *ast.FuncDecl) bool {
	if fn.Body == nil || len(fn.Body.List) == 0 {
		return false
	}
	stmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Reserve" {
		return false
	}
	name, ok := selector.X.(*ast.Ident)
	return ok && name.Name == "stackgrow"
}

func TestEntryPointsReserveFirst(t *testing.T) {
	entries := []struct {
		file, receiver, name string
	}{
		{"../tokscratch/tokscratch.go", "", "Bytes"},
		{"../tokscratch/tokscratch.go", "", "String"},
		{"../tokscratch/tokscratch.go", "", "StringContext"},
		{"../../pkg/sql/parser/parser.go", "Parser", "parseTokens"},
		{"../../pkg/sql/parser/parser.go", "Parser", "parseContextTokens"},
		{"../../pkg/sql/parser/recovery.go", "Parser", "parseWithRecovery"},
		{"../../pkg/sql/parser/validate.go", "", "ParseBytesWithTokens"},
		{"../../pkg/gosqlx/analyze.go", "", "Analyze"},
		{"../../pkg/linter/linter.go", "Linter", "LintString"},
		{"../../pkg/lsp/dialect.go", "", "parseWithRecoveryForDialect"},
	}
	for _, entry := range entries {
		t.Run(entry.receiver+"/"+entry.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), entry.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != entry.name || receiverName(fn) != entry.receiver {
					continue
				}
				if !startsWithReserve(fn) {
					t.Errorf("%s: %s.%s must start with stackgrow.Reserve()", entry.file, entry.receiver, entry.name)
				}
				return
			}
			t.Fatalf("%s: function %s.%s not found", entry.file, entry.receiver, entry.name)
		})
	}
}

func TestNoUnreservedTokenizeThenParse(t *testing.T) {
	tokenizeMethods := map[string]bool{
		"Tokenize": true, "TokenizeString": true,
		"TokenizeStringContext": true, "TokenizeContext": true,
	}
	parseMethods := map[string]bool{
		"ParseFromModelTokens": true, "ParseContextFromModelTokens": true,
		"ParseWithRecoveryFromModelTokens": true, "parseTokens": true,
	}
	matches := 0
	for _, root := range []string{"../../pkg", "../../wasm"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var tokenizes, parses bool
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok {
						tokenizes = tokenizes || tokenizeMethods[selector.Sel.Name]
						parses = parses || parseMethods[selector.Sel.Name]
					}
					return true
				})
				if tokenizes && parses {
					matches++
					if !startsWithReserve(fn) {
						t.Errorf("%s: %s.%s tokenizes then parses without reserving first", path, receiverName(fn), fn.Name.Name)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if matches == 0 {
		t.Fatal("no tokenize-then-parse pipelines found")
	}
	t.Logf("checked %d tokenize-then-parse pipelines", matches)
}
