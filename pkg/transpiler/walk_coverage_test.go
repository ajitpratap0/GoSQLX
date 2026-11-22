// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/internal/reflplan"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

type walkCoverageKey struct {
	address uintptr
	typ     reflect.Type
}

type walkCoverageSet map[walkCoverageKey]struct{}

// recordWalkCoverage records interface slots (including scalar dynamic values)
// and the pointer rewrite sites that do not require an interface slot. Addressable
// interface slots identify scalar values; pointer values identify their pointees.
func recordWalkCoverage(v reflect.Value, found walkCoverageSet) {
	if v.Kind() == reflect.Interface && !v.IsNil() {
		dynamic := v.Elem()
		var address uintptr
		if dynamic.Kind() == reflect.Pointer {
			address = dynamic.Pointer()
		} else if v.CanAddr() {
			address = v.Addr().Pointer()
		}
		found[walkCoverageKey{address, dynamic.Type()}] = struct{}{}
	}
	if v.Kind() == reflect.Pointer && !v.IsNil() &&
		(v.Type() == reflect.TypeFor[*ast.LiteralValue]() || v.Type() == reflect.TypeFor[*ast.BinaryExpression]()) {
		found[walkCoverageKey{v.Pointer(), v.Type()}] = struct{}{}
	}
}

// naiveWalkCoverage deliberately examines every exported field and every
// container element without consulting reflplan or any static reachability test.
func naiveWalkCoverage(root reflect.Value) walkCoverageSet {
	found := make(walkCoverageSet)
	seen := make(map[walkCoverageKey]bool)
	stack := []reflect.Value{root}
	for len(stack) > 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !v.IsValid() {
			continue
		}
		recordWalkCoverage(v, found)
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				continue
			}
			key := walkCoverageKey{v.Pointer(), v.Type()}
			if seen[key] {
				continue
			}
			seen[key] = true
			stack = append(stack, v.Elem())
		case reflect.Interface:
			if !v.IsNil() {
				stack = append(stack, v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					stack = append(stack, v.Field(i))
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				stack = append(stack, v.Index(i))
			}
		case reflect.Map:
			iter := v.MapRange()
			for iter.Next() {
				stack = append(stack, iter.Value())
			}
		}
	}
	return found
}

func plannedWalkCoverage(root reflect.Value) walkCoverageSet {
	type frame struct {
		v reflect.Value
		p *reflplan.Plan
	}
	found := make(walkCoverageSet)
	seen := make(map[walkCoverageKey]bool)
	stack := []frame{{root, reflplan.Of(root.Type())}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		v, p := f.v, f.p
		if !v.IsValid() {
			continue
		}
		recordWalkCoverage(v, found)
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() || !p.Elem.Reach {
				continue
			}
			key := walkCoverageKey{v.Pointer(), v.Type()}
			if seen[key] {
				continue
			}
			seen[key] = true
			stack = append(stack, frame{v.Elem(), p.Elem})
		case reflect.Interface:
			if !v.IsNil() {
				elem := v.Elem()
				stack = append(stack, frame{elem, reflplan.Of(elem.Type())})
			}
		case reflect.Struct:
			for _, field := range p.Fields {
				stack = append(stack, frame{v.Field(field.Index), field.Plan})
			}
		case reflect.Slice, reflect.Array:
			if p.Elem.Reach {
				for i := 0; i < v.Len(); i++ {
					stack = append(stack, frame{v.Index(i), p.Elem})
				}
			}
		case reflect.Map:
			if p.Elem.Reach {
				iter := v.MapRange()
				for iter.Next() {
					stack = append(stack, frame{iter.Value(), p.Elem})
				}
			}
		}
	}
	return found
}

func TestReflectionPlanRealWorldWalkCoverage(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "realworld")
	parsed, skipped := 0, 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".sql" {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		dialect := strings.Split(filepath.ToSlash(rel), "/")[0]
		if !keywords.IsValidDialect(dialect) {
			return fmt.Errorf("invalid corpus dialect %q", dialect)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, sql := range gosqlx.SplitStatements(string(data), dialect) {
			tree, err := parser.ParseWithDialect(sql, keywords.SQLDialect(dialect))
			if err != nil {
				// The corpus intentionally includes known parser failures.
				skipped++
				continue
			}
			func() {
				defer ast.ReleaseAST(tree)
				for j, stmt := range tree.Statements {
					parsed++
					value := reflect.ValueOf(stmt)
					want, got := naiveWalkCoverage(value), plannedWalkCoverage(value)
					if !reflect.DeepEqual(got, want) {
						t.Errorf("%s#%d statement %d: planned coverage has %d sites, naive has %d", rel, i, j, len(got), len(want))
						for site := range want {
							if _, ok := got[site]; !ok {
								t.Errorf("missing rewrite site: %v at %#x", site.typ, site.address)
							}
						}
					}
				}
			}()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed == 0 {
		t.Fatal("no corpus statements parsed")
	}
	t.Logf("compared %d parsed statements; skipped %d known/unparseable inputs", parsed, skipped)
}
