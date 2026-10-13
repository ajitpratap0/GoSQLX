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

import "unsafe"

// stringBytes returns a read-only []byte view of s without copying it. It
// returns nil for the empty string.
//
// The view is sound only because of the tokenizer's invariant on t.input: the
// scanner never writes to, appends to, or returns t.input or any sub-slice of
// it. Every value it hands out is a substring of t.src or a fresh copy. Never
// use unsafe in the other direction (aliasing a caller's mutable []byte as a
// string): Tokenize copies its []byte input precisely so that returned tokens
// never alias the caller's buffer.
func stringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s)) // #nosec G103 -- read-only view
}
