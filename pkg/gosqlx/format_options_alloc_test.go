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

import "testing"

// TestFormatAST_Options checks how FormatAST applies its options, including
// none and nil ones, which take the allocation-free default path.
func TestFormatAST_Options(t *testing.T) {
	tree, err := Parse("select a, b from t where c = 1")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	def := FormatAST(tree)
	tests := []struct {
		name string
		opts []FormatOption
		want string
	}{
		{"none", nil, def},
		{"nil option", []FormatOption{nil}, def},
		{"default indent", []FormatOption{WithIndent(2)}, def},
		{"compact", []FormatOption{WithIndent(0)}, "SELECT a, b FROM t WHERE c = 1"},
		{"uppercase compact", []FormatOption{WithIndent(0), WithUppercaseKeywords(true)}, "SELECT a, b FROM t WHERE c = 1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatAST(tree, tc.opts...); got != tc.want {
				t.Errorf("FormatAST = %q, want %q", got, tc.want)
			}
		})
	}
	if def == "SELECT a, b FROM t WHERE c = 1" {
		t.Errorf("default FormatAST = %q, want the indented layout", def)
	}
}

// TestFormatAST_NoOptionsAllocatesLess checks that a call without options
// does not pay for the option bag a call with options needs.
func TestFormatAST_NoOptionsAllocatesLess(t *testing.T) {
	if testing.CoverMode() != "" {
		t.Skip("allocation counts are not stable under coverage instrumentation")
	}
	tree, err := Parse("SELECT a FROM t")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plain := testing.AllocsPerRun(50, func() { _ = FormatAST(tree) })
	withOpt := testing.AllocsPerRun(50, func() { _ = FormatAST(tree, WithIndent(2)) })
	if plain >= withOpt {
		t.Errorf("FormatAST allocs: no options %v, with an option %v; want fewer without", plain, withOpt)
	}
}
