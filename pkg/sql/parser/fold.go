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

package parser

import (
	"unicode"
	"unicode/utf8"
)

// equalsUpper reports whether strings.ToUpper(s) == upper, without allocating.
//
// upper must consist of ASCII characters only (it is always a keyword
// constant). The tokenizer classifies keywords with strings.ToUpper, which
// maps each rune with unicode.ToUpper, so this helper mirrors that mapping
// exactly instead of using strings.EqualFold, whose simple case folding
// differs: ToUpper maps U+0131 (dotless i) to 'I' and U+017F (long s) to 'S',
// and does not map U+212A (Kelvin sign) to 'K'. A non-ASCII rune can therefore
// upper-case to a single ASCII byte, so the comparison is made on the mapped
// runes rather than on byte lengths. Invalid UTF-8 bytes become U+FFFD under
// ToUpper and so never match an ASCII upper.
//
// It is called for many keyword probes on the hot path, so a necessary
// condition is screened inline: every rune of s, at least one byte long,
// must map to one byte of upper, so s is at least as long as upper.
func equalsUpper(s, upper string) bool {
	return len(s) >= len(upper) && equalsUpperRunes(s, upper)
}

// equalsUpperRunes is equalsUpper without the screens.
func equalsUpperRunes(s, upper string) bool {
	j := 0
	for i := 0; i < len(s); {
		var u rune
		if c := s[i]; c < utf8.RuneSelf {
			u = rune(c)
			if 'a' <= c && c <= 'z' {
				u = rune(c - 'a' + 'A')
			}
			i++
		} else {
			r, size := utf8.DecodeRuneInString(s[i:])
			u = unicode.ToUpper(r)
			i += size
		}
		if u >= utf8.RuneSelf || j >= len(upper) || upper[j] != byte(u) {
			return false
		}
		j++
	}
	return j == len(upper)
}
