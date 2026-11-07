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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

type testEmbedded struct {
	Promoted  string
	Shadow    string
	Ambiguous string
}
type testOther struct{ Ambiguous string }
type testFields struct {
	testEmbedded
	testOther
	Shadow  string
	Ignored string `json:"-"`
	Renamed string `json:"rename"`
}
type testJSONFallback int

func (testJSONFallback) MarshalJSON() ([]byte, error) { return []byte(` { "native": true } `), nil }

type testBadJSON int

func (testBadJSON) MarshalJSON() ([]byte, error) { return []byte("{"), nil }

type testTextFallback string

func (v testTextFallback) MarshalText() ([]byte, error) { return []byte(v), nil }

type testCycle struct{ Next *testCycle }

type testPointerJSON struct{ Value string }

func (*testPointerJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"custom":true}`), nil
}

type testMarshalerPriority struct{ Value string }

func (testMarshalerPriority) MarshalText() ([]byte, error) { return []byte("text"), nil }
func (*testMarshalerPriority) MarshalJSON() ([]byte, error) {
	return []byte(`{"json":true}`), nil
}

func TestAppend_MarshalerMethodSets(t *testing.T) {
	cases := []struct {
		name  string
		value reflect.Value
		want  string
	}{
		{"unaddressable_value", reflect.ValueOf(testPointerJSON{Value: "x"}), `{"Value":"x"}`},
		{"map_value", reflect.ValueOf(map[string]testPointerJSON{"a": {Value: "x"}}), `{"a":{"Value":"x"}}`},
		{"addressable_pointer", reflect.ValueOf(&testPointerJSON{Value: "x"}), `{"custom":true}`},
		{"unaddressable_text", reflect.ValueOf(testMarshalerPriority{Value: "x"}), `"text"`},
	}
	priority := testMarshalerPriority{Value: "x"}
	cases = append(cases, struct {
		name  string
		value reflect.Value
		want  string
	}{"addressable_json_over_text", reflect.ValueOf(&priority).Elem(), `{"json":true}`})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := appendValue(nil, tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != tc.want {
				t.Errorf("got %s, want %s", out, tc.want)
			}
		})
	}
}

func TestAppend_OmissionRules(t *testing.T) {
	encode := func(v any) string {
		t.Helper()
		out, err := appendValue(nil, reflect.ValueOf(v))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	var typedNil *ast.Identifier
	value := struct {
		Pointer  *models.Location
		Elements []*ast.Identifier
		TypedNil any
		Location models.Location
		False    bool
		Zero     int
		Empty    string
		Array    [0]int
		Map      map[int]string
	}{Pointer: &models.Location{}, Elements: []*ast.Identifier{nil}, TypedNil: typedNil, Map: map[int]string{2: "two", 10: "ten"}}
	if got := encode(value); got != `{"Pointer":{},"Elements":[null],"Map":{"10":"ten","2":"two"}}` {
		t.Errorf("omission/order: %s", got)
	}
	fields := testFields{testEmbedded: testEmbedded{"a", "embedded", "drop"}, testOther: testOther{"drop"}, Shadow: "outer", Ignored: "ignore", Renamed: "yes"}
	out := encode(fields)
	compareJSON(t, fields, []byte(out))
	if strings.Contains(out, "Ambiguous") || strings.Contains(out, "Ignored") {
		t.Error(out)
	}
	if got := encode("<>&\u2028\u2029\xff\"\\\n"); got != `"<>&\u2028\u2029�\"\\\n"` {
		t.Errorf("escaping: %s", got)
	}
	if got := encode([]byte{0, 1, 2, 255}); got != `"AAEC/w=="` {
		t.Errorf("bytes: %s", got)
	}
	if got := encode(struct {
		Values []any
		Map    map[string]any
	}{[]any{nil, typedNil, false, 0, "", models.Location{}}, map[string]any{"nil": nil, "false": false, "zero": 0, "empty": ""}}); got != `{"Values":[null,null,false,0,"",{}],"Map":{"empty":"","false":false,"nil":null,"zero":0}}` {
		t.Errorf("element and map value positions: %s", got)
	}
	for _, v := range []any{1e-9, 1e-6, 1e20, 1e21, float32(1.2345), math.Copysign(0, -1)} {
		out := encode(v)
		want, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if out != string(want) {
			t.Errorf("float %v: %s != %s", v, out, want)
		}
	}
	if got := encode(testJSONFallback(1)); got != `{"native":true}` {
		t.Errorf("fallback: %s", got)
	}
	if got := encode(testTextFallback("<x>")); got != `"<x>"` {
		t.Errorf("text fallback: %s", got)
	}
	lit := &ast.LiteralValue{Value: "a", Type: "string"}
	lit.EnsureExtras().Prefix = "E"
	lit.SetRawBackslash(true)
	if got := encode(lit); got != `{"node_type":"LiteralValue","Value":"a","Type":"string","Prefix":"E","RawBackslash":true}` {
		t.Errorf("literal extras: %s", got)
	}
	for _, v := range []any{make(chan int), func() {}, complex(1, 2), unsafe.Pointer(nil), struct{ Unsupported chan int }{}, math.NaN(), math.Inf(1), testBadJSON(1), struct {
		V int `json:",string"`
	}{1}} {
		if out, err := appendValue(nil, reflect.ValueOf(v)); err == nil {
			t.Errorf("unsupported %T accepted: %s", v, out)
		}
	}
	if _, err := Marshal(nil); err == nil {
		t.Error("nil tree accepted")
	}
	cycle := &testCycle{}
	cycle.Next = cycle
	if _, err := appendValue(nil, reflect.ValueOf(cycle)); err == nil {
		t.Error("cycle accepted")
	}
}

// resetPlanCache is used only by the concurrent-first-use regression test.
func resetPlanCache() {
	planMu.Lock()
	defer planMu.Unlock()
	planCache.Store(nil)
}

func TestAppend_ConcurrentFirstUse(t *testing.T) {
	trees := make([]*ast.AST, 64)
	wants := make([][]byte, 64)
	for i := range trees {
		tree, err := parseTest(fmt.Sprintf("SELECT c%d FROM t WHERE a = %d", i, i), "")
		if err != nil {
			t.Fatal(err)
		}
		trees[i] = tree
		defer ast.ReleaseAST(tree)
		wants[i], err = Marshal(tree)
		if err != nil {
			t.Fatal(err)
		}
	}
	resetPlanCache()
	var wg sync.WaitGroup
	for i := range trees {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := Marshal(trees[i])
			if err != nil || !bytes.Equal(out, wants[i]) {
				t.Errorf("concurrent %d: %s %v", i, out, err)
			}
		}()
	}
	wg.Wait()
}
