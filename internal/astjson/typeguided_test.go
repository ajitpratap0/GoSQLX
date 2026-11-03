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
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// referenceOmitted describes the contract from the Go field's type. In
// particular an interface containing false, 0 or "" is present, unlike nil.
// This oracle intentionally does not share encoder helpers or plans.
func referenceOmitted(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer:
		return v.IsNil()
	case reflect.Interface:
		if v.IsNil() {
			return true
		}
		dynamic := v.Elem()
		return dynamic.Kind() == reflect.Pointer && dynamic.IsNil()
	case reflect.Slice, reflect.Array, reflect.Map:
		return v.Len() == 0
	case reflect.String:
		return v.String() == ""
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	default:
		return v.IsZero()
	}
}

func assertObservedNoJSONTags(t testing.TB, value any) bool {
	t.Helper()
	types := make(map[reflect.Type]bool)
	observe(reflect.ValueOf(value), types, make(map[any]bool))
	valid := true
	for typ := range types {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if tag, exists := field.Tag.Lookup("json"); exists {
				t.Errorf("type-guided oracle requires no json tags: %s.%s has %q", typ, field.Name, tag)
				valid = false
			}
		}
	}
	return valid
}

// referenceLiteralFields independently mirrors the legacy literalJSON field
// names. The private AST representation is deliberately not the JSON schema.
func referenceLiteralFields(v reflect.Value) reflect.Value {
	literal, ok := v.Interface().(ast.LiteralValue)
	if !ok {
		return v
	}
	extras := literal.DialectExtras()
	return reflect.ValueOf(struct {
		Value        any
		Type         string
		Prefix       string
		RawBackslash bool
	}{literal.Value, literal.Type, extras.Prefix, extras.RawBackslash})
}

// expectedTypeGuided retains the legacy token stream's field ordering and
// scalars, using reflection solely to decide field presence and node identity.
func expectedTypeGuided(legacy any, v reflect.Value) (any, error) {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return legacy, nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return legacy, nil
	}
	switch old := legacy.(type) {
	case referenceObject:
		if v.Kind() == reflect.Map {
			return referenceMap(old, v)
		}
		if v.Kind() != reflect.Struct {
			return nil, fmt.Errorf("object has Go type %s", v.Type())
		}
		typ := v.Type()
		expected := make(referenceObject, 0, len(old)+2)
		if typ == reflect.TypeFor[ast.AST]() {
			expected = append(expected, referenceMember{"version", referenceVersion})
		}
		if typ == reflect.TypeFor[ast.AST]() || typ.Implements(reflect.TypeFor[ast.Node]()) || reflect.PointerTo(typ).Implements(reflect.TypeFor[ast.Node]()) {
			expected = append(expected, referenceMember{"node_type", typ.Name()})
		}
		fields := referenceLiteralFields(v)
		for _, member := range old {
			field := fields.FieldByName(member.key)
			if !field.IsValid() {
				return nil, fmt.Errorf("legacy key %q missing in %s", member.key, typ)
			}
			if referenceOmitted(field) {
				continue
			}
			child, err := expectedTypeGuided(member.value, field)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", typ, member.key, err)
			}
			expected = append(expected, referenceMember{member.key, child})
		}
		return expected, nil
	case []any:
		if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
			return nil, fmt.Errorf("array has Go type %s", v.Type())
		}
		expected := make([]any, len(old))
		for i := range old {
			child, err := expectedTypeGuided(old[i], v.Index(i))
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			expected[i] = child
		}
		return expected, nil
	default:
		return legacy, nil
	}
}

func referenceMap(old referenceObject, v reflect.Value) (referenceObject, error) {
	expected := make(referenceObject, 0, len(old))
	for _, member := range old {
		key := reflect.New(v.Type().Key()).Elem()
		switch key.Kind() {
		case reflect.String:
			key.SetString(member.key)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n, err := strconv.ParseInt(member.key, 10, key.Type().Bits())
			if err != nil {
				return nil, err
			}
			key.SetInt(n)
		default:
			n, err := strconv.ParseUint(member.key, 10, key.Type().Bits())
			if err != nil {
				return nil, err
			}
			key.SetUint(n)
		}
		child, err := expectedTypeGuided(member.value, v.MapIndex(key))
		if err != nil {
			return nil, err
		}
		expected = append(expected, referenceMember{member.key, child})
	}
	return expected, nil
}

func TestAppend_MatchesEncodingJSONTypeGuided(t *testing.T) {
	corpus := goldens.Corpus(t)
	goldens.Parallel(len(corpus), func(i int) {
		s := corpus[i]
		for _, dialect := range []string{s.Dialect, ""} {
			tree, err := parseTest(s.SQL, dialect)
			if err != nil {
				continue
			}
			out, err := Marshal(tree)
			if err != nil {
				t.Errorf("%s/%s: %v", s.File, dialect, err)
			} else {
				compareTypeGuided(t, tree, out, s.File+"/"+dialect+" SQL="+s.SQL)
			}
			ast.ReleaseAST(tree)
		}
	})
}

func TestTypeGuidedReference_PresencePrecisionAndOrder(t *testing.T) {
	value := struct {
		Pointer  *models.Location
		False    any
		Zero     any
		Empty    any
		TypedNil any
		Location models.Location
		Big      uint64
	}{Pointer: &models.Location{}, False: false, Zero: 0, Empty: "", TypedNil: (*ast.Identifier)(nil), Big: 1<<63 + 17}
	want := []byte(`{"Pointer":{},"False":false,"Zero":0,"Empty":"","Big":9223372036854775825}`)
	compareTypeGuided(t, value, want, "oracle presence and numeric precision")
	expected, err := decodeReferenceJSON(want)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := decodeReferenceJSON([]byte(`{"False":false,"Pointer":{},"Zero":0,"Empty":"","Big":9223372036854775825}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(referencePlain(expected), referencePlain(reordered)) {
		t.Fatal("order self-test must contain identical values")
	}
	if referenceOrderDifference(expected, reordered, "$oracle") == "" {
		t.Fatal("token-stream oracle accepted reordered object keys")
	}
}
