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
	"strconv"
	"strings"
	"testing"
)

// astImportPath is the import path of this package.
const astImportPath = "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

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
		calls = append(calls, spanWrites(fset, f, path)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) > 0 {
		t.Fatalf("library code can write the unsynchronised global spanInfo:\n  %s", strings.Join(calls, "\n  "))
	}
}

// spanWrites lists the places in one non-test file that can write spanInfo:
//   - any reference to SetSpan (a call or a method value such as
//     f := ast.SetSpan), through whatever name the file imports this package
//     under (aliases and dot imports included), or bare inside package ast
//     outside its own declaration;
//   - inside package ast, any write to spanInfo outside SetSpan: an indexed
//     assignment or ++/--, delete/clear(spanInfo, ...), or reassigning the map.
func spanWrites(fset *token.FileSet, f *goast.File, path string) []string {
	inAST := f.Name.Name == "ast" && filepath.Base(filepath.Dir(path)) == "ast"
	names := map[string]bool{} // local names of this package in f
	dot := false
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != astImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			names["ast"] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	var out []string
	report := func(n goast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	isSpanInfo := func(e goast.Expr) bool {
		id, ok := goast.Unparen(e).(*goast.Ident)
		return ok && id.Name == "spanInfo"
	}
	isSpanInfoWrite := func(e goast.Expr) bool {
		e = goast.Unparen(e)
		if ix, ok := e.(*goast.IndexExpr); ok {
			return isSpanInfo(ix.X)
		}
		return isSpanInfo(e)
	}
	for _, decl := range f.Decls {
		var declName *goast.Ident
		inSetSpan := false
		if fd, ok := decl.(*goast.FuncDecl); ok {
			declName = fd.Name
			inSetSpan = inAST && fd.Recv == nil && fd.Name.Name == "SetSpan"
		}
		var visit func(n goast.Node) bool
		visit = func(n goast.Node) bool {
			switch n := n.(type) {
			case *goast.SelectorExpr:
				if x, ok := n.X.(*goast.Ident); ok && names[x.Name] && n.Sel.Name == "SetSpan" {
					report(n, "reference to "+x.Name+".SetSpan")
				}
				// Walk only X: Sel is a field or method name, never the
				// package-level SetSpan.
				goast.Inspect(n.X, visit)
				return false
			case *goast.Ident:
				if n.Name == "SetSpan" && (inAST || dot) && n != declName {
					report(n, "reference to SetSpan")
				}
			case *goast.AssignStmt:
				if inAST && !inSetSpan {
					for _, l := range n.Lhs {
						if isSpanInfoWrite(l) {
							report(n, "write to spanInfo outside SetSpan")
						}
					}
				}
			case *goast.IncDecStmt:
				if inAST && !inSetSpan && isSpanInfoWrite(n.X) {
					report(n, "write to spanInfo outside SetSpan")
				}
			case *goast.CallExpr:
				if id, ok := n.Fun.(*goast.Ident); ok && inAST && !inSetSpan &&
					(id.Name == "delete" || id.Name == "clear") && len(n.Args) > 0 && isSpanInfo(n.Args[0]) {
					report(n, id.Name+"(spanInfo) outside SetSpan")
				}
			}
			return true
		}
		goast.Inspect(decl, visit)
	}
	return out
}

// TestSpanWritesDetector checks spanWrites on synthetic sources, so the
// invariant above cannot pass by missing a write.
func TestSpanWritesDetector(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            int
	}{
		{"plain call", "x/p.go", `package p; import "` + astImportPath + `"; func f() { ast.SetSpan(nil, ast.Span{}) }`, 1},
		{"aliased import", "x/p.go", `package p; import a "` + astImportPath + `"; func f() { a.SetSpan(nil, a.Span{}) }`, 1},
		{"method value", "x/p.go", `package p; import "` + astImportPath + `"; func f() { g := ast.SetSpan; _ = g }`, 1},
		{"dot import", "x/p.go", `package p; import . "` + astImportPath + `"; func f() { SetSpan(nil, Span{}) }`, 1},
		{"other package named ast", "x/p.go", `package p; import "go/ast"; func f() { ast.SetSpan() }`, 0},
		{"method of another type", "x/p.go", `package p; func f(x T) { x.SetSpan() }`, 0},
		{"SetSpan itself", "sql/ast/span.go", `package ast; var spanInfo = map[any]int{}; func SetSpan(n any, s int) { spanInfo[n] = s }`, 0},
		{"bare call in ast", "sql/ast/x.go", `package ast; func f() { SetSpan(nil, 0) }`, 1},
		{"bare method value in ast", "sql/ast/x.go", `package ast; var g = SetSpan`, 1},
		{"index write outside SetSpan", "sql/ast/x.go", `package ast; func f(n any) { spanInfo[n] = 1 }`, 1},
		{"map reassignment", "sql/ast/x.go", `package ast; func f() { spanInfo = nil }`, 1},
		{"delete", "sql/ast/x.go", `package ast; func f(n any) { delete(spanInfo, n) }`, 1},
		{"read is fine", "sql/ast/x.go", `package ast; func f(n any) int { return spanInfo[n] }`, 0},
		{"selector on other value in ast", "sql/ast/x.go", `package ast; func f(x T) { x.SetSpan() }`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, c.path, c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			if got := spanWrites(fset, f, c.path); len(got) != c.want {
				t.Errorf("spanWrites = %d %v, want %d", len(got), got, c.want)
			}
		})
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
