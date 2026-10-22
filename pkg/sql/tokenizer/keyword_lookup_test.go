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

package tokenizer

import (
	"strings"
	"testing"
)

func TestIsKeyword(t *testing.T) {
	tests := []struct {
		word string
		want bool
	}{
		{"select", true},
		{"SELECT", true},
		{"Table", true},
		{"order", true},
		{"users", false},
		{"", false},
		{"émoji", false},
		{strings.Repeat("a", keywordKeyBufLen+1), false},
	}
	for _, tc := range tests {
		if got := IsKeyword(tc.word); got != tc.want {
			t.Errorf("IsKeyword(%q) = %v, want %v", tc.word, got, tc.want)
		}
	}
	if n := testing.AllocsPerRun(100, func() { IsKeyword("order") }); n != 0 {
		t.Errorf("IsKeyword allocates %v times per call, want 0", n)
	}
}
