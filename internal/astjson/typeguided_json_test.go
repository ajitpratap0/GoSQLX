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
	"io"
	"reflect"
	"testing"
)

type referenceMember struct {
	key   string
	value any
}

// A slice retains every key from the decoder token stream, including duplicate
// keys, so map equality cannot accidentally excuse ordering or duplication.
type referenceObject []referenceMember

const referenceVersion = json.Number("1")

func decodeReferenceJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readReferenceJSON(decoder)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON token %v: %v", token, err)
	}
	return value, nil
}

func readReferenceJSON(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(referenceObject, 0)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := token.(string)
			if !ok {
				return nil, fmt.Errorf("object key is %T", token)
			}
			value, err := readReferenceJSON(decoder)
			if err != nil {
				return nil, err
			}
			object = append(object, referenceMember{key, value})
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, err := readReferenceJSON(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", delim)
	}
}

func referencePlain(value any) any {
	switch value := value.(type) {
	case referenceObject:
		object := make(map[string]any, len(value))
		for _, member := range value {
			object[member.key] = referencePlain(member.value)
		}
		return object
	case []any:
		array := make([]any, len(value))
		for i := range value {
			array[i] = referencePlain(value[i])
		}
		return array
	default:
		return value
	}
}

func referenceOrderDifference(expected, actual any, path string) string {
	switch expected := expected.(type) {
	case referenceObject:
		actual, ok := actual.(referenceObject)
		if !ok {
			return path + ": expected an object"
		}
		expectedKeys := make([]string, len(expected))
		actualKeys := make([]string, len(actual))
		for i := range expected {
			expectedKeys[i] = expected[i].key
		}
		for i := range actual {
			actualKeys[i] = actual[i].key
		}
		if !reflect.DeepEqual(expectedKeys, actualKeys) {
			return fmt.Sprintf("%s: object key order: got %q, want %q", path, actualKeys, expectedKeys)
		}
		for i := range expected {
			if difference := referenceOrderDifference(expected[i].value, actual[i].value, path+"."+expected[i].key); difference != "" {
				return difference
			}
		}
	case []any:
		actual, ok := actual.([]any)
		if !ok || len(actual) != len(expected) {
			return path + ": array shape differs"
		}
		for i := range expected {
			if difference := referenceOrderDifference(expected[i], actual[i], fmt.Sprintf("%s[%d]", path, i)); difference != "" {
				return difference
			}
		}
	}
	return ""
}

func compareTypeGuided(t testing.TB, value any, out []byte, label string) {
	t.Helper()
	if !assertObservedNoJSONTags(t, value) {
		return
	}
	legacyBytes, err := json.Marshal(value)
	if err != nil {
		t.Errorf("%s: legacy: %v", label, err)
		return
	}
	legacy, err := decodeReferenceJSON(legacyBytes)
	if err != nil {
		t.Errorf("%s: legacy decode: %v", label, err)
		return
	}
	expected, err := expectedTypeGuided(legacy, reflect.ValueOf(value))
	if err != nil {
		t.Errorf("%s: type-guided reference: %v", label, err)
		return
	}
	actual, err := decodeReferenceJSON(out)
	if err != nil {
		t.Errorf("%s: v1 decode: %v", label, err)
		return
	}
	// No pruning: a leaked zero or omitted present field remains a mismatch.
	if !reflect.DeepEqual(referencePlain(expected), referencePlain(actual)) {
		t.Errorf("%s: type-guided exact differential\nexpected: %#v\nactual: %#v", label, referencePlain(expected), referencePlain(actual))
	}
	if difference := referenceOrderDifference(expected, actual, "$parse"); difference != "" {
		t.Errorf("%s: %s", label, difference)
	}
}
