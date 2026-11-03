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

package astjson

import (
	"encoding/json"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func pruned(x any) any {
	switch v := x.(type) {
	case map[string]any:
		out := make(map[string]any)
		for k, v := range v {
			if k == "node_type" || k == "version" {
				continue
			}
			p := pruned(v)
			if !emptyJSON(p) {
				out[k] = p
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = pruned(x)
		}
		return out
	default:
		return x
	}
}
func emptyJSON(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}
func compareJSON(t testing.TB, value any, encoded []byte) {
	t.Helper()
	baseline, err := json.Marshal(value)
	if err != nil {
		t.Errorf("reference %T: %v", value, err)
		return
	}
	var a, b any
	if err := json.Unmarshal(baseline, &a); err != nil {
		t.Error(err)
		return
	}
	if err := json.Unmarshal(encoded, &b); err != nil {
		t.Errorf("invalid JSON %q: %v", encoded, err)
		return
	}
	if !reflect.DeepEqual(pruned(a), pruned(b)) {
		t.Errorf("differential %T\nreference: %s\nencoded: %s", value, baseline, encoded)
	}
}
func TestAppend_MatchesEncodingJSON(t *testing.T) {
	corpus := goldens.Corpus(t)
	goldens.Parallel(len(corpus), func(i int) {
		s := corpus[i]
		for _, d := range []string{s.Dialect, ""} {
			tree, err := parseTest(s.SQL, d)
			if err != nil {
				continue
			}
			out, err := Marshal(tree)
			if err != nil {
				t.Errorf("%s/%s: %v", s.File, d, err)
				ast.ReleaseAST(tree)
				continue
			}
			compareJSON(t, tree, out)
			var root map[string]any
			if err := json.Unmarshal(out, &root); err != nil {
				t.Error(err)
			}
			if root["version"] != float64(1) || root["node_type"] != "AST" {
				t.Errorf("root contract: %s", out)
			}
			ast.ReleaseAST(tree)
		}
	})
}
func observe(v reflect.Value, types map[reflect.Type]bool, seen map[any]bool) {
	if !v.IsValid() {
		return
	}
	if v.Kind() == reflect.Interface {
		if !v.IsNil() {
			observe(v.Elem(), types, seen)
		}
		return
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		if v.CanInterface() {
			p := v.Interface()
			if seen[p] {
				return
			}
			seen[p] = true
		}
		observe(v.Elem(), types, seen)
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		types[v.Type()] = true
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				observe(v.Field(i), types, seen)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			observe(v.Index(i), types, seen)
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			observe(it.Value(), types, seen)
		}
	}
}
func filled(typ reflect.Type, depth int) reflect.Value {
	v := reflect.New(typ).Elem()
	if depth > 3 {
		return v
	}
	switch typ.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	case reflect.Pointer:
		v.Set(reflect.New(typ.Elem()))
		v.Elem().Set(filled(typ.Elem(), depth+1))
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				v.Field(i).Set(filled(typ.Field(i).Type, depth+1))
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(typ, 1, 1))
		v.Index(0).Set(filled(typ.Elem(), depth+1))
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			v.Index(i).Set(filled(typ.Elem(), depth+1))
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(typ))
		v.SetMapIndex(filled(typ.Key(), depth+1), filled(typ.Elem(), depth+1))
	case reflect.Interface:
		for _, candidate := range []any{&ast.Identifier{Name: "x"}, &ast.LiteralValue{Value: "x", Type: "string"}, &ast.SelectStatement{}} {
			cv := reflect.ValueOf(candidate)
			if cv.Type().AssignableTo(typ) {
				v.Set(cv)
				break
			}
		}
	}
	return v
}
func TestAppend_SyntheticFullyPopulated(t *testing.T) {
	corpus := goldens.Corpus(t)
	all := make(map[reflect.Type]bool)
	var mu sync.Mutex
	goldens.Parallel(len(corpus), func(i int) {
		local := make(map[reflect.Type]bool)
		for _, d := range []string{corpus[i].Dialect, ""} {
			tree, err := parseTest(corpus[i].SQL, d)
			if err != nil {
				continue
			}
			observe(reflect.ValueOf(tree), local, make(map[any]bool))
			ast.ReleaseAST(tree)
		}
		mu.Lock()
		for typ := range local {
			all[typ] = true
		}
		mu.Unlock()
	})
	types := make([]reflect.Type, 0, len(all))
	for typ := range all {
		types = append(types, typ)
	}
	sort.Slice(types, func(i, j int) bool { return types[i].String() < types[j].String() })
	t.Logf("synthetic types: %d", len(types))
	for _, typ := range types {
		t.Run(typ.String(), func(t *testing.T) {
			v := filled(typ, 0)
			out, err := appendValue(nil, v)
			if err != nil {
				t.Fatal(err)
			}
			compareJSON(t, v.Interface(), out)
		})
	}
}
func checkDiscriminator(t *testing.T, v reflect.Value, j any, root bool) {
	t.Helper()
	if !v.IsValid() {
		return
	}
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		obj, ok := j.(map[string]any)
		if !ok {
			return
		}
		node := reflect.PointerTo(v.Type()).Implements(reflect.TypeFor[ast.Node]()) || v.Type().Implements(reflect.TypeFor[ast.Node]())
		if node || root {
			if obj["node_type"] != v.Type().Name() {
				t.Errorf("%v discriminator: %v", v.Type(), obj["node_type"])
			}
		} else if _, ok := obj["node_type"]; ok {
			t.Errorf("non-node %v has discriminator", v.Type())
		}
		checkDiscriminatorFields(t, v, obj)
	case reflect.Slice, reflect.Array:
		arr, ok := j.([]any)
		if ok {
			for i := 0; i < v.Len() && i < len(arr); i++ {
				checkDiscriminator(t, v.Index(i), arr[i], false)
			}
		}
	}
}
func checkDiscriminatorFields(t *testing.T, v reflect.Value, obj map[string]any) {
	t.Helper()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		if field.PkgPath != "" {
			continue
		}
		fv := v.Field(i)
		if field.Anonymous {
			if fv.Kind() == reflect.Pointer {
				if fv.IsNil() {
					continue
				}
				fv = fv.Elem()
			}
			if fv.Kind() == reflect.Struct {
				checkDiscriminatorFields(t, fv, obj)
				continue
			}
		}
		if child, ok := obj[field.Name]; ok {
			checkDiscriminator(t, fv, child, false)
		}
	}
}
func TestAppend_Discriminator(t *testing.T) {
	tree, err := parseTest(goldenQueries[1].sql, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	out, err := Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var j any
	if err := json.Unmarshal(out, &j); err != nil {
		t.Fatal(err)
	}
	checkDiscriminator(t, reflect.ValueOf(tree), j, true)
}
