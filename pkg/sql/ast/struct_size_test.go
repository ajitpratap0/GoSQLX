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
		// The origin/main fields remain inline for API compatibility. On a
		// 64-bit platform, a cold-fields pointer requires one additional
		// word where the original layout has no reusable pointer-sized padding.
		{"InsertStatement", unsafe.Sizeof(InsertStatement{}), 184},
		{"LiteralValue", unsafe.Sizeof(LiteralValue{}), 40},
		{"SelectStatement", unsafe.Sizeof(SelectStatement{}), 392},
		{"TableReference", unsafe.Sizeof(TableReference{}), 144},
		{"BinaryExpression", unsafe.Sizeof(BinaryExpression{}), 88},
		{"FunctionCall", unsafe.Sizeof(FunctionCall{}), 184},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.size > tc.max {
				t.Errorf("%s is %d bytes, want <= %d", tc.name, tc.size, tc.max)
			}
		})
	}
}
