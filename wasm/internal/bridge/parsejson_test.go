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

package bridge

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/astjson"
	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestParseJSON_Versions(t *testing.T) {
	inputs := goldens.Corpus(t)
	goldens.Parallel(len(inputs), func(i int) {
		in := inputs[i]
		for _, d := range []string{in.Dialect, ""} {
			tree, err := Parse(in.SQL, d)
			if err != nil {
				continue
			}
			legacy, e := json.MarshalIndent(tree, "", "  ")
			if e != nil {
				t.Error(e)
				ast.ReleaseAST(tree)
				continue
			}
			compact, e := astjson.Marshal(tree)
			ast.ReleaseAST(tree)
			if e != nil {
				t.Error(e)
				continue
			}
			for version, want := range map[int]string{ASTJSONLegacy: string(legacy), astjson.Version: string(compact)} {
				got, e := ParseJSON(in.SQL, d, version)
				if e != nil || got != want {
					t.Errorf("sql=%q dialect=%q version=%d got=%q err=%v want=%q", in.SQL, d, version, got, e, want)
				}
			}
		}
	})
	for _, v := range []int{2, -1} {
		want := fmt.Sprintf("unsupported AST JSON version %d (supported: 1)", v)
		if _, err := ParseJSON("SELEC", "", v); err == nil || err.Error() != want {
			t.Errorf("version %d: got %v want %q", v, err, want)
		}
	}
	_, want := Parse("SELEC 1", "")
	_, got := ParseJSON("SELEC 1", "", 1)
	if got == nil || got.Error() != want.Error() {
		t.Errorf("parse error got %v want %v", got, want)
	}
	if _, e := ParseJSON("SELECT TOP 5 * FROM t", "sqlserver", 1); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseJSON("SELECT TOP 5 * FROM t", "", 1); e == nil {
		t.Fatal("generic accepted TOP")
	}
}

func TestParseJSON_ReusedBufferIsolation(t *testing.T) {
	first, err := ParseJSON("SELECT 'first'", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	saved := strings.Clone(first)
	if _, err := ParseJSON("SELECT 'second, different output'", "", 1); err != nil {
		t.Fatal(err)
	}
	if first != saved {
		t.Fatal("pooled buffer changed first string")
	}
	large, err := ParseJSON("SELECT '"+strings.Repeat("x", (1<<20)+1)+"'", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(large) <= 1<<20 {
		t.Fatal("large input did not exceed drop cap")
	}
	buf, ok := parseJSONBuffers.Get().(*[]byte)
	if !ok {
		t.Fatal("unexpected pool value")
	}
	defer putParseJSONBuffer(buf)
	if cap(*buf) > 1<<20 {
		t.Fatalf("retained large buffer capacity %d", cap(*buf))
	}
}

func TestParseJSON_ReleaseReuseCorpus(t *testing.T) {
	corpus := goldens.Corpus(t)
	// Retain every reference across both passes, without returning it or its
	// nodes to any pool. Each fresh parse is interleaved with ParseJSON so a
	// duplicate pool entry cannot hide behind strictly sequential reuse.
	references := make([]*ast.AST, 0, 4*len(corpus))
	for pass := 1; pass <= 2; pass++ {
		for _, input := range corpus {
			for _, dialect := range []string{input.Dialect, ""} {
				tree, parseErr := Parse(input.SQL, dialect)
				if parseErr != nil {
					_, err := ParseJSON(input.SQL, dialect, astjson.Version)
					if err == nil || err.Error() != parseErr.Error() {
						t.Fatalf("pass %d %s dialect=%q sql=%q: got error %v, want %v", pass, input.Key(), dialect, input.SQL, err, parseErr)
					}
					continue
				}
				references = append(references, tree)
				want, err := astjson.Marshal(tree)
				if err != nil {
					t.Fatalf("reference %s dialect=%q sql=%q: %v", input.Key(), dialect, input.SQL, err)
				}
				got, err := ParseJSON(input.SQL, dialect, astjson.Version)
				if err != nil || got != string(want) {
					t.Fatalf("pass %d %s dialect=%q sql=%q: got %q, error %v; want %q", pass, input.Key(), dialect, input.SQL, got, err, want)
				}
				// Marshal again after ParseJSON has released its own tree. If a double
				// put made the two parses share pooled nodes, that release changes the
				// never-released reference even when the returned JSON still matches.
				afterRelease, err := astjson.Marshal(tree)
				if err != nil || string(afterRelease) != string(want) {
					t.Fatalf("pass %d %s dialect=%q sql=%q: reference changed after ParseJSON release: got %q, error %v; want %q", pass, input.Key(), dialect, input.SQL, afterRelease, err, want)
				}
			}
		}
	}
	runtime.KeepAlive(references)
}
