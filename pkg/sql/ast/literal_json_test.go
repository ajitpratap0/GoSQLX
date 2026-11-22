// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"encoding/json"
	"testing"
)

// The WASM parse endpoint serializes ASTs directly. Cold storage must preserve
// the literal metadata in that public JSON representation.
func TestLiteralJSONMetadata(t *testing.T) {
	for _, metadata := range []LiteralExtras{{}, {RawBackslash: true}, {Prefix: "N", RawBackslash: true}, {Prefix: "E"}} {
		lit := LiteralValue{Value: "text", Type: "string"}
		if metadata.Prefix != "" {
			lit.EnsureExtras().Prefix = metadata.Prefix
		}
		lit.SetRawBackslash(metadata.RawBackslash)
		for _, value := range []any{lit, &lit} {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 4 || fields["Prefix"] == nil || fields["RawBackslash"] == nil {
				t.Fatalf("literal JSON lost metadata: %s", data)
			}
			decoded := LiteralValue{Value: "old", Type: "old"}
			decoded.EnsureExtras().Prefix = "stale"
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Value != lit.Value || decoded.Type != lit.Type || decoded.DialectExtras() != metadata || decoded.SQL() != lit.SQL() {
				t.Fatalf("literal JSON round trip changed value or metadata: %s", data)
			}
		}
	}
}

func TestLiteralJSONErrors(t *testing.T) {
	if _, err := json.Marshal(LiteralValue{Value: make(chan int)}); err == nil {
		t.Fatal("unsupported literal value must report a marshal error")
	}
	var lit LiteralValue
	if err := json.Unmarshal([]byte(`{"RawBackslash":"invalid"}`), &lit); err == nil {
		t.Fatal("invalid literal metadata must report a decode error")
	}
}

func TestLiteralJSONPartialUpdate(t *testing.T) {
	lit := LiteralValue{Value: "old", Type: "string"}
	lit.EnsureExtras().Prefix = "N"
	lit.SetRawBackslash(true)
	if err := json.Unmarshal([]byte(`{"Value":"new"}`), &lit); err != nil {
		t.Fatal(err)
	}
	if lit.Value != "new" || lit.Type != "string" || lit.DialectExtras() != (LiteralExtras{Prefix: "N", RawBackslash: true}) {
		t.Fatal("partial JSON update cleared fields absent from the input")
	}
}
