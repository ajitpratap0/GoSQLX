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

import "unicode/utf8"

// clickHouseParamEnd reports where a ClickHouse query parameter such as
// {id:UInt64} or {d:DateTime64(3, 'UTC')} that starts at t.pos ends, as an
// index just past the closing brace. It returns 0 when the text at t.pos is
// not a parameter: the brace must be followed by a name, a colon and a
// non-empty type, and the type may nest parentheses and quoted strings. A map
// or object literal such as {'a': 1} is therefore left to the caller.
func (t *Tokenizer) clickHouseParamEnd() int {
	in := t.input
	i := t.pos.Index + 1 // past '{'
	for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
		i++
	}
	nameStart := i
	for i < len(in) {
		r, size := utf8.DecodeRune(in[i:])
		if !(i == nameStart && isIdentifierStart(r)) && !(i > nameStart && isIdentifierChar(r)) {
			break
		}
		i += size
	}
	if i == nameStart {
		return 0
	}
	for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
		i++
	}
	if i >= len(in) || in[i] != ':' {
		return 0
	}
	i++
	typeStart := i
	depth := 0
	for i < len(in) {
		switch c := in[i]; c {
		case '\'', '"', '`':
			// Skip a quoted string or identifier inside the type.
			q := c
			i++
			for i < len(in) && in[i] != q {
				if in[i] == '\\' && i+1 < len(in) {
					i++
				}
				i++
			}
			if i >= len(in) {
				return 0
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return 0
			}
		case '}':
			if depth == 0 {
				if i == typeStart {
					return 0
				}
				return i + 1
			}
		case '\n', ';':
			return 0
		}
		i++
	}
	return 0
}
