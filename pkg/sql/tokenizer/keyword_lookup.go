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

import "strings"

// IsKeyword reports whether word, written bare, is read by the tokenizer as a
// keyword token (SELECT, TABLE, ORDER, KEY, ...) rather than as a plain
// identifier. Case is ignored. The parser uses it to decide whether a name
// that was written as a delimited identifier ("table", `order`) must keep its
// delimiters when it is rendered back. Pure-ASCII words are looked up without
// allocating.
func IsKeyword(word string) bool {
	if word == "" {
		return false
	}
	var kbuf [keywordKeyBufLen]byte
	if len(word) <= keywordKeyBufLen && asciiUpper(kbuf[:len(word)], word) {
		_, ok := keywordTokenTypes[string(kbuf[:len(word)])]
		return ok
	}
	if isASCII(word) {
		return false // longer than any keyword
	}
	_, ok := keywordTokenTypes[strings.ToUpper(word)]
	return ok
}
