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

package ast

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// releaseDrawnConstructors lists the pool constructors in this package that
// pkg/sql/parser calls, i.e. the node types releaseDrawn must return to their
// pools. It mirrors the unconditional Put cases of putExpressionImpl and
// releaseStatement. It lives in this test file because it has no production
// use: TestReleaseDrawnPolicy_MatchesParser compares that policy with the parser's actual ast.Get*/ast.New* calls.
// When the parser starts drawing a new type, add its constructor here and
// make sure the matching Put case runs in releaseDrawn mode.
var releaseDrawnConstructors = []string{
	"GetTupleExpression",
	"GetArrayConstructor",
	"GetArraySubscriptExpression",
	"GetArraySliceExpression",
	"GetUnsupportedStatement",
	"GetAlterStatement",
	"GetShowStatement",
	"GetDescribeStatement",
	"GetReplaceStatement",
	"NewCreateSequenceStatement",
	"NewDropSequenceStatement",
	"NewAlterSequenceStatement",
}

// This file guards the hand-maintained releaseDrawn policy (issue #556)
// against drift from pkg/sql/parser. ReleaseAST only recycles node types the
// parser draws from pools, so a pool constructor the parser starts calling
// without a matching policy entry would silently stop being recycled.
//
// It is an internal test (package ast) so it can read the unexported policy;
// it must not import pkg/sql/parser (that would be an import cycle), so the
// parser is inspected as source with go/parser and go/ast.

const astImportSuffix = "/pkg/sql/ast"

// parseNonTestFiles parses the non-test .go files of dir.
func parseNonTestFiles(t *testing.T, dir string) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := goparser.ParseFile(fset, path, nil, goparser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no non-test .go files found in %s (wrong relative path?)", dir)
	}
	return files
}

// poolConstructors returns the exported package-level Get*/New* functions of
// this package whose body calls Get on a sync.Pool variable (by naming
// convention an identifier ending in "Pool").
func poolConstructors(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range parseNonTestFiles(t, ".") {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			if !strings.HasPrefix(name, "Get") && !strings.HasPrefix(name, "New") {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Get" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && strings.HasSuffix(id.Name, "Pool") {
					out[name] = true
				}
				return true
			})
		}
	}
	return out
}

// parserDrawnConstructors returns the pool constructors the parser package
// references through its import of this package.
func parserDrawnConstructors(t *testing.T, pooled map[string]bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range parseNonTestFiles(t, filepath.Join("..", "parser")) {
		local := ""
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !strings.HasSuffix(path, astImportSuffix) {
				continue
			}
			local = "ast"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		if local == "" || local == "_" || local == "." {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == local && pooled[sel.Sel.Name] {
				out[sel.Sel.Name] = true
			}
			return true
		})
	}
	// NewAST hands out the container that ReleaseAST itself returns; it is not
	// a node type and has no place in the node policy.
	delete(out, "NewAST")
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestReleaseDrawnPolicy_MatchesParser fails when the set of pool constructors
// pkg/sql/parser calls differs from releaseDrawnConstructors.
func TestReleaseDrawnPolicy_MatchesParser(t *testing.T) {
	pooled := poolConstructors(t)
	// Sanity: the detector must see the constructors we know exist, or an
	// empty intersection would make the comparison below vacuously pass.
	for _, want := range []string{"GetTupleExpression", "NewAlterSequenceStatement", "NewAST", "GetSelectStatement"} {
		if !pooled[want] {
			t.Fatalf("pool constructor detection is broken: %s not found among %v", want, sortedKeys(pooled))
		}
	}

	parser := parserDrawnConstructors(t, pooled)
	policy := map[string]bool{}
	for _, name := range releaseDrawnConstructors {
		if policy[name] {
			t.Errorf("releaseDrawnConstructors lists %s twice", name)
		}
		policy[name] = true
		if !pooled[name] {
			t.Errorf("releaseDrawnConstructors lists %s, which is not a pool constructor in package ast", name)
		}
	}

	for _, name := range sortedKeys(parser) {
		if !policy[name] {
			t.Errorf("pkg/sql/parser draws ast.%s from a pool but it is MISSING from the release policy "+
				"(releaseDrawnConstructors in pool_drawn_policy_test.go). Add it there and make sure "+
				"putExpressionImpl / releaseStatement Puts that type in releaseDrawn mode, "+
				"otherwise ReleaseAST will never recycle it", name)
		}
	}
	for _, name := range sortedKeys(policy) {
		if !parser[name] {
			t.Errorf("release policy lists ast.%s but pkg/sql/parser never calls it: "+
				"it is MISSING from the parser side. Remove it from releaseDrawnConstructors "+
				"(or restore the parser's pool draw)", name)
		}
	}
}

// drawnCases maps every releaseDrawnConstructors entry to a builder that
// returns a dirty node and the function that releases it the way ReleaseAST
// does. It verifies that each listed type really is Put (and so reset) in
// releaseDrawn mode, so the list cannot drift from the release switches.
var drawnCases = map[string]func() (node any, release func()){
	"GetTupleExpression": func() (any, func()) {
		n := GetTupleExpression()
		n.Expressions = append(n.Expressions, GetLiteralValue())
		return n, func() { releaseExpression(n, releaseDrawn) }
	},
	"GetArrayConstructor": func() (any, func()) {
		n := GetArrayConstructor()
		n.Elements = append(n.Elements, GetLiteralValue())
		return n, func() { releaseExpression(n, releaseDrawn) }
	},
	"GetArraySubscriptExpression": func() (any, func()) {
		n := GetArraySubscriptExpression()
		n.Array = GetIdentifier()
		n.Indices = append(n.Indices, GetLiteralValue())
		return n, func() { releaseExpression(n, releaseDrawn) }
	},
	"GetArraySliceExpression": func() (any, func()) {
		n := GetArraySliceExpression()
		n.Array = GetIdentifier()
		n.Start = GetLiteralValue()
		n.End = GetLiteralValue()
		return n, func() { releaseExpression(n, releaseDrawn) }
	},
	"GetUnsupportedStatement": func() (any, func()) {
		n := GetUnsupportedStatement()
		n.Kind, n.RawSQL = "USE", "USE db"
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"GetAlterStatement": func() (any, func()) {
		n := GetAlterStatement()
		n.Name = "t"
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"GetShowStatement": func() (any, func()) {
		n := GetShowStatement()
		n.ShowType, n.ObjectName, n.From = "TABLES", "t", "db"
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"GetDescribeStatement": func() (any, func()) {
		n := GetDescribeStatement()
		n.TableName = "t"
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"GetReplaceStatement": func() (any, func()) {
		n := GetReplaceStatement()
		n.TableName = "t"
		n.Columns = append(n.Columns, GetIdentifier())
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"NewCreateSequenceStatement": func() (any, func()) {
		n := NewCreateSequenceStatement()
		n.Name, n.IfNotExists = GetIdentifier(), true
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"NewDropSequenceStatement": func() (any, func()) {
		n := NewDropSequenceStatement()
		n.Name, n.IfExists = GetIdentifier(), true
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
	"NewAlterSequenceStatement": func() (any, func()) {
		n := NewAlterSequenceStatement()
		n.Name, n.IfExists = GetIdentifier(), true
		return n, func() { releaseStatement(n, releaseDrawn) }
	},
}

// isReset reports whether the value behind pointer p is a reset pooled node:
// every field is its zero value, except that slices may be empty non-nil
// (pools keep backing arrays).
func isReset(p any) bool {
	return resetValue(reflect.ValueOf(p).Elem())
}

func resetValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice:
		return v.Len() == 0
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !resetValue(v.Field(i)) {
				return false
			}
		}
		return true
	default:
		return v.IsZero()
	}
}

func TestReleaseDrawnPolicy_EveryListedTypeIsReleased(t *testing.T) {
	for _, name := range releaseDrawnConstructors {
		if _, ok := drawnCases[name]; !ok {
			t.Errorf("releaseDrawnConstructors lists %s but drawnCases has no behavioural check for it; add one", name)
		}
	}
	listed := map[string]bool{}
	for _, name := range releaseDrawnConstructors {
		listed[name] = true
	}
	for name, build := range drawnCases {
		if !listed[name] {
			t.Errorf("drawnCases has a case for %s that is not in releaseDrawnConstructors", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			node, release := build()
			if isReset(node) {
				t.Fatalf("test bug: %s node was not dirtied before release", name)
			}
			release()
			if !isReset(node) {
				t.Errorf("ast.%s is listed as drawn by the parser, but releaseDrawn left it dirty: %+v. "+
					"The matching Put case is missing or conditional on releaseAll", name, reflect.ValueOf(node).Elem().Interface())
			}
		})
	}
}
