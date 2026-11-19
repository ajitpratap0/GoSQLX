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

package whitespace_test

import (
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

func compareRedundantWhitespace(t *testing.T, sql string) {
	t.Helper()
	rule := whitespace.NewRedundantWhitespaceRule()
	ctx := linter.NewContext(sql, "differential.sql")
	got, err := rule.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, err := oldRedundantWhitespaceCheck(rule, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SQL %q:\n got %#v\nwant %#v", sql, got, want)
	}
}

func TestRedundantWhitespaceDifferentialCorpus(t *testing.T) {
	for _, root := range []string{"realworld", "corpus"} {
		t.Run(root, func(t *testing.T) {
			files, statements := 0, 0
			err := filepath.WalkDir(filepath.Join("../../../../testdata", root), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || filepath.Ext(path) != ".sql" {
					return nil
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				dialect := ""
				if root == "realworld" {
					dialect = filepath.Base(filepath.Dir(path))
				}
				t.Run(path, func(t *testing.T) {
					compareRedundantWhitespace(t, string(data))
					for i, stmt := range gosqlx.SplitStatements(string(data), dialect) {
						t.Run(fmt.Sprintf("statement_%d", i), func(t *testing.T) { compareRedundantWhitespace(t, stmt) })
						statements++
					}
				})
				files++
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if files == 0 || statements == 0 {
				t.Fatal("empty differential corpus")
			}
			t.Logf("compared %d files and %d statements", files, statements)
		})
	}
}

func TestRedundantWhitespaceDifferentialRandom(t *testing.T) {
	count := 300000
	if testing.Short() || redundantWhitespaceRace {
		count = 30000
	}
	rng := rand.New(rand.NewSource(104010))
	// Invalid UTF-8 is tested separately because its columns intentionally differ.
	pieces := []string{"", " ", "  ", "    ", "\t", "\r", "\v", "\x00", "'", `"`, "\\", ";", "--", "/*", "*/", "SELECT", "x", "é", "日本語", "🙂", "\u00a0", "\u2003"}
	for i := 0; i < count; i++ {
		var line strings.Builder
		n := rng.Intn(40)
		for j := 0; j < n; j++ {
			line.WriteString(pieces[rng.Intn(len(pieces))])
		}
		compareRedundantWhitespace(t, line.String())
	}
	t.Logf("compared %d seeded random lines", count)
}

func TestRedundantWhitespaceInvalidUTF8ByteColumns(t *testing.T) {
	tests := []struct {
		line                string
		columns, oldColumns []int
	}{
		{"a\xff  b", []int{3}, []int{5}},
		{"\xff\xfe  x  y", []int{3, 6}, []int{7, 10}},
		{"'\xff'  x", []int{4}, []int{4}},
		{"\xff 'q'\xfe  x", []int{7}, []int{9}},
		{"  \xff  x", []int{4}, []int{6}},
		{"\xc3  x", []int{2}, []int{4}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x", tt.line), func(t *testing.T) {
			rule := whitespace.NewRedundantWhitespaceRule()
			ctx := linter.NewContext(tt.line, "invalid.sql")
			got, err := rule.Check(ctx)
			if err != nil {
				t.Fatal(err)
			}
			old, err := oldRedundantWhitespaceCheck(rule, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.columns) || len(old) != len(tt.oldColumns) {
				t.Fatalf("unexpected violations: got %#v, old %#v", got, old)
			}
			for i := range got {
				if got[i].Location.Column != tt.columns[i] || old[i].Location.Column != tt.oldColumns[i] {
					t.Fatalf("column %d: got %d, old %d; want %d, %d", i, got[i].Location.Column, old[i].Location.Column, tt.columns[i], tt.oldColumns[i])
				}
				old[i].Location.Column = got[i].Location.Column
			}
			if !reflect.DeepEqual(got, old) {
				t.Fatalf("fields other than byte columns changed: got %#v, old %#v", got, old)
			}
		})
	}
}
