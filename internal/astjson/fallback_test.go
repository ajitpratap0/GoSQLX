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
	"reflect"
	"testing"
)

type nilJSONSlice []int

func (nilJSONSlice) MarshalJSON() ([]byte, error) { return []byte(`{"custom":true}`), nil }

type nilTextMap map[string]int

func (nilTextMap) MarshalText() ([]byte, error) { return []byte("custom"), nil }

func TestAppend_NilMarshalerContainers(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  string
	}{{nilJSONSlice(nil), `{"custom":true}`}, {nilTextMap(nil), `"custom"`}} {
		out, err := appendValue(nil, reflect.ValueOf(tc.value))
		if err != nil || string(out) != tc.want {
			t.Errorf("%T: got %s, %v; want %s", tc.value, out, err, tc.want)
		}
	}
}

type recursiveInvalidA struct {
	B   *recursiveInvalidB
	Bad chan int
}
type recursiveInvalidB struct{ A *recursiveInvalidA }

func TestAppend_RecursivePlanErrorsAreCacheIndependent(t *testing.T) {
	// Use distinct new types so no earlier test can have primed their plans.
	_, err := appendValue(nil, reflect.ValueOf(recursiveInvalidA{}))
	if err == nil {
		t.Fatal("unsupported field in A accepted")
	}
	_, err = appendValue(nil, reflect.ValueOf(recursiveInvalidB{}))
	if err == nil {
		t.Fatal("cached B hid reachable unsupported field in A")
	}
}
