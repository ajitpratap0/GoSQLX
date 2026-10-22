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

package gosqlx

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
)

func TestFormat_PreservesCommentsAndHints(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.UppercaseKeywords = true
	compact := opts
	compact.IndentSize = 0

	tests := []struct {
		name string
		sql  string
		opts FormatOptions
		want string
	}{
		{"hint and trailing comment", "select /*+ hint */ a from t -- note", compact, "SELECT /*+ hint */ a FROM t -- note"},
		{"oracle full hint", "select /*+ FULL(t) */ a from t", compact, "SELECT /*+ FULL(t) */ a FROM t"},
		{"leading comment", "-- report\nselect a from t", compact, "-- report\nSELECT a FROM t"},
		{"comment between statements", "select 1; -- one\n-- two\nselect 2", compact, "SELECT 1; -- one\n-- two\nSELECT 2"},
		{"inner comment moves up", "select a, /* new */ b from t", compact, "/* new */\nSELECT a, b FROM t"},
		{"no comments unchanged path", "select a from t", compact, "SELECT a FROM t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Format(tt.sql, tt.opts)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormat_RefusesToDropAnOptimizerHint(t *testing.T) {
	_, err := Format("select * from (select /*+ FULL(t) */ a from t) s", DefaultFormatOptions())
	if !errors.Is(err, formatter.ErrUnplaceableComment) {
		t.Fatalf("err = %v, want it to wrap formatter.ErrUnplaceableComment", err)
	}
}

func TestFormat_AddSemicolonWithComments(t *testing.T) {
	opts := DefaultFormatOptions()
	opts.AddSemicolon = true
	opts.IndentSize = 0
	got, err := Format("select 1 -- a\n; select 2 -- b", opts)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Count(got, ";") != 2 {
		t.Fatalf("got %q, want exactly two semicolons", got)
	}
	for _, c := range []string{"-- a", "-- b"} {
		if !strings.Contains(got, c) {
			t.Fatalf("got %q, lost %q", got, c)
		}
	}
}

func TestParseTree_WithCommentsKeepsThemForFormatTree(t *testing.T) {
	const sql = "-- header\nSELECT a FROM t -- trailing"
	plain, err := ParseTree(context.Background(), sql)
	if err != nil {
		t.Fatal(err)
	}
	if out := FormatTree(plain); strings.Contains(out, "--") {
		t.Fatalf("comments kept without WithComments: %q", out)
	}
	withC, err := ParseTree(context.Background(), sql, WithComments())
	if err != nil {
		t.Fatal(err)
	}
	out := FormatTree(withC)
	for _, c := range []string{"-- header", "-- trailing"} {
		if !strings.Contains(out, c) {
			t.Fatalf("FormatTree output %q lost %q", out, c)
		}
	}
}
