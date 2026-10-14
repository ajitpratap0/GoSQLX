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
	"bytes"
	"testing"
)

func TestQuoteName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"a", "a"},
		{"select", `"select"`},
		{"SELECT", `"SELECT"`},
		{"Select", `"Select"`},
		{"key", `"key"`},
		{"a b", `"a b"`},
		{`a"b`, `"a""b"`},
		{"#temp", `"#temp"`},
		{"naïve", "naïve"},
		{"ROW_NUMBER", "ROW_NUMBER"},
	}
	for _, tc := range cases {
		if got := QuoteName(tc.in); got != tc.want {
			t.Errorf("QuoteName(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestQuoteQualifiedName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"key", "key"},
		{"select", `"select"`},
		{"db.select", `db."select"`},
		{"my db.t", `"my db".t`},
		{"#temp", "#temp"},
		{"@stage", "@stage"},
		{"DUAL", "DUAL"},
		{"db..t", `db."".t`},
	}
	for _, tc := range cases {
		if got := QuoteQualifiedName(tc.in); got != tc.want {
			t.Errorf("QuoteQualifiedName(%q) = %s, want %s", tc.in, got, tc.want)
		}
		// The unexported writer must agree with the exported helper.
		var buf bytes.Buffer
		writeQualifiedName(&buf, tc.in)
		if got := buf.String(); got != tc.want {
			t.Errorf("writeQualifiedName(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestWriteNameList(t *testing.T) {
	var buf bytes.Buffer
	writeNameList(&buf, []string{"a", "select", "a b", "Mixed"})
	if got, want := buf.String(), `a, "select", "a b", Mixed`; got != want {
		t.Errorf("writeNameList = %s, want %s", got, want)
	}
}

func TestQuoteName_FastPathAllocs(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() { _ = QuoteName("users") }); n != 0 {
		t.Errorf("QuoteName(users) allocs = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = QuoteQualifiedName("db.users") }); n != 0 {
		t.Errorf("QuoteQualifiedName(db.users) allocs = %v, want 0", n)
	}
	if n := testing.AllocsPerRun(100, func() { _ = isReservedName("select", true) }); n != 0 {
		t.Errorf("isReservedName allocs = %v, want 0", n)
	}
}

func TestReservedNameWords_LengthBound(t *testing.T) {
	for w := range reservedNameWords {
		if len(w) > maxReservedNameLen {
			t.Errorf("%s is longer than maxReservedNameLen (%d)", w, maxReservedNameLen)
		}
		if !isReservedName(w, false) {
			t.Errorf("isReservedName(%q, false) = false", w)
		}
	}
}

// TestIdentifierPool_ResetsQuoted checks that a pooled Identifier comes back
// with Quoted cleared. Not parallel: it relies on sync.Pool handing the
// just-Put object back on the same P.
func TestIdentifierPool_ResetsQuoted(t *testing.T) {
	for try := 0; try < maxReuseTries; try++ {
		id := GetIdentifier()
		id.Name = "x"
		id.Quoted = true
		PutIdentifier(id)
		got := GetIdentifier()
		reused := got == id
		quoted := got.Quoted
		PutIdentifier(got)
		if !reused {
			continue
		}
		if quoted {
			t.Fatal("pooled Identifier kept Quoted = true after PutIdentifier")
		}
		return
	}
	t.Skip("sync.Pool did not hand back the same Identifier")
}
