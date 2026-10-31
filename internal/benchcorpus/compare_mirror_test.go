// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

// compareQueries extracts the Corpus literal of benchmarks/compare/corpus.go
// from source. That package lives in a separate Go module, so it cannot be
// imported from here.
func compareQueries(t *testing.T, root string) []Query {
	t.Helper()
	path := filepath.Join(root, "benchmarks", "compare", "corpus.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var lit *ast.CompositeLit
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "Corpus" || len(vs.Values) != 1 {
				continue
			}
			lit, _ = vs.Values[0].(*ast.CompositeLit)
		}
	}
	if lit == nil {
		t.Fatalf("%s: var Corpus composite literal not found", path)
	}
	var out []Query
	for _, el := range lit.Elts {
		q, ok := el.(*ast.CompositeLit)
		if !ok {
			t.Fatalf("Corpus element is %T, want composite literal", el)
		}
		var got Query
		for _, f := range q.Elts {
			kv, ok := f.(*ast.KeyValueExpr)
			if !ok {
				t.Fatalf("Corpus field is %T, want key: value", f)
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				t.Fatalf("Corpus field key is %T, want identifier", kv.Key)
			}
			val, err := constString(kv.Value)
			if err != nil {
				t.Fatalf("Corpus field %s: %v", key.Name, err)
			}
			switch key.Name {
			case "ID":
				got.ID = val
			case "Name":
				got.Name = val
			case "SQL":
				got.SQL = val
			default:
				t.Fatalf("Corpus field %q is not mirrored in testdata/bench/portable_queries.txt; extend the mirror", key.Name)
			}
		}
		out = append(out, got)
	}
	return out
}

// constString folds string literals joined with "+".
func constString(e ast.Expr) (string, error) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", fmt.Errorf("literal %s is not a string", v.Value)
		}
		return strconv.Unquote(v.Value)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", fmt.Errorf("operator %s is not +", v.Op)
		}
		l, err := constString(v.X)
		if err != nil {
			return "", err
		}
		r, err := constString(v.Y)
		if err != nil {
			return "", err
		}
		return l + r, nil
	case *ast.ParenExpr:
		return constString(v.X)
	}
	return "", fmt.Errorf("unsupported expression %T", e)
}

// TestPortableQueriesMatchCompare keeps the 11 portable queries in
// testdata/bench/portable_queries.txt equal to benchmarks/compare/corpus.go,
// in order and byte for byte.
func TestPortableQueriesMatchCompare(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	want := compareQueries(t, root)
	got := set.Portable()
	if len(want) != 11 {
		t.Fatalf("benchmarks/compare/corpus.go has %d queries, want the 11 portable ones", len(want))
	}
	if len(got) != len(want) {
		t.Fatalf("portable_queries.txt has %d queries, compare corpus has %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("query %d differs\n  mirror:  %+v\n  compare: %+v", i, got[i], want[i])
		}
	}
}
