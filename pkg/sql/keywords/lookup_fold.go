package keywords

import (
	"strings"
	"unicode/utf8"
)

// keyBufLen bounds the stack buffer lookupFold upper-cases into. Every
// built-in key is far shorter (longest is 20 bytes on origin/main); a test pins
// that every built-in key fits, so every built-in hit takes the fast path.
const keyBufLen = 64

// lookupFold returns m[strings.ToUpper(s)] without allocating when s is pure
// ASCII and at most keyBufLen bytes: it upper-cases into a stack buffer and
// indexes the map with string(buf[:n]), which the compiler does not allocate.
// Any other input (a non-ASCII byte, or longer than keyBufLen) takes the
// strings.ToUpper path, so results are identical to the old code for every
// input, including Unicode simple case mappings such as U+017F (ſ) -> 'S' and
// U+0131 (ı) -> 'I', and invalid UTF-8.
func lookupFold[V any](m map[string]V, s string) (V, bool) {
	if len(s) <= keyBufLen {
		var buf [keyBufLen]byte
		i := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c >= utf8.RuneSelf {
				break
			}
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			buf[i] = c
		}
		if i == len(s) {
			v, ok := m[string(buf[:len(s)])]
			return v, ok
		}
	}
	v, ok := m[strings.ToUpper(s)]
	return v, ok
}
