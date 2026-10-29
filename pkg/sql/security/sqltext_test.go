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

package security

import "testing"

func TestNormalizeComments(t *testing.T) {
	tests := []struct {
		input, flat, nested string
	}{
		{"a/*x*/b", "a b", "a b"},
		{"a--x\rb", "a \rb", "a \rb"},
		{"a--x\nb", "a \nb", "a \nb"},
		{"a/*unfinished", "a ", "a "},
		{"a/*!50000unfinished", "a ", "a "},
		{"a/*!50000UNION*/b", "a UNION b", "a UNION b"},
		{"a/*!UNION*/b", "a UNION b", "a UNION b"},
		{"a/*+ hint */b", "a b", "a b"},
		{"a/* /* */ */b", "a  */b", "a b"},
		{"a#x\nb", "a#x\nb", "a#x\nb"},
		{"'a''/*b*/' --x", "'a''/*b*/'  ", "'a''/*b*/'  "},
		{"\"a\"\"/*b*/\"", "\"a\"\"/*b*/\"", "\"a\"\"/*b*/\""},
		{"`a``--b`", "`a``--b`", "`a``--b`"},
		{"\xff/*x*/\xfe", "\xff \xfe", "\xff \xfe"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			for _, nested := range []bool{false, true} {
				want := tt.flat
				if nested {
					want = tt.nested
				}
				if got, _ := normalizeComments(tt.input, nested); got != want {
					t.Errorf("nested=%v: got %q, want %q", nested, got, want)
				}
			}
		})
	}
}

func FuzzSQLTextViews(f *testing.F) {
	for _, seed := range []string{"", "$", "-", "/", "'", "\xff", "/*!", "/*/*/", "$$raw$$", "'a\\' $x$"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, sql string) {
		stripped := stripDollarQuotedStrings(sql)
		if len(stripped) > len(sql) {
			t.Fatal("stripping grew input")
		}
		for _, nested := range []bool{false, true} {
			_, _ = normalizeComments(stripped, nested)
		}
	})
}
