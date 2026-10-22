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
	"testing"
	"unsafe"
)

// TestHotStructSizes pins the size of AST structs the parser allocates for
// almost every statement, where crossing a malloc size class costs every
// parse. A new field that pushes one past its limit belongs behind a pointer
// (as the rarer SELECT clauses are, in SelectExtras), or the limit should be
// raised knowingly.
func TestHotStructSizes(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("sizes are pinned for 64-bit platforms")
	}
	tests := []struct {
		name string
		size uintptr
		max  uintptr
	}{
		// 448 is a size class; above 512 bytes a pointerful object also
		// carries an 8-byte malloc header and lands in the 576 class.
		{"SelectStatement", unsafe.Sizeof(SelectStatement{}), 448},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.size > tc.max {
				t.Errorf("%s is %d bytes, want <= %d", tc.name, tc.size, tc.max)
			}
		})
	}
}
