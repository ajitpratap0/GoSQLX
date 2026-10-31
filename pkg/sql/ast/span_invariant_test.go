// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	goast "go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSpanInfoNeverWrittenByLibrary keeps the global spanInfo map (span.go)
// read-only outside tests. The map is unsynchronised, so the first library
// code path that calls SetSpan during parsing would be a data race under
// concurrent use, and it would make node spans visible to GetSpan that the
// behaviour goldens (testdata/goldens) do not cover. Only tests may write it.
func TestSpanInfoNeverWrittenByLibrary(t *testing.T) {
	root := spanTestModuleRoot(t)
	fset := token.NewFileSet()
	var calls []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inAST := f.Name.Name == "ast" && filepath.Base(filepath.Dir(path)) == "ast"
		goast.Inspect(f, func(n goast.Node) bool {
			call, ok := n.(*goast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *goast.Ident: // SetSpan(...) inside package ast
				if inAST && fn.Name == "SetSpan" {
					calls = append(calls, fset.Position(call.Pos()).String())
				}
			case *goast.SelectorExpr: // ast.SetSpan(...) elsewhere
				if x, ok := fn.X.(*goast.Ident); ok && x.Name == "ast" && fn.Sel.Name == "SetSpan" {
					calls = append(calls, fset.Position(call.Pos()).String())
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) > 0 {
		t.Fatalf("library code writes the unsynchronised global spanInfo via SetSpan:\n  %s", strings.Join(calls, "\n  "))
	}
}

func spanTestModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil && strings.Contains(string(data), "module github.com/ajitpratap0/GoSQLX\n") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("module root not found")
		}
		dir = parent
	}
}
