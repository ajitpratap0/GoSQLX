// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package batch

// TextEnd returns the end of a GO directive whose GO word ends at wordEnd.
// The caller must check that GO is the first word on its line. As with Line,
// comments are trivia: both line and block comments may follow GO [count].
// A block comment can span lines; text after its closing delimiter belongs to
// the next line, not the GO line. Repeat counts must be positive whole numbers;
// zero and nonnumeric arguments are rejected rather than silently ignored.
// This is sqlcmd's GO [count] syntax with SQL comments allowed on the line.
func TextEnd(src string, wordEnd int) (int, bool) {
	if wordEnd < 0 || wordEnd > len(src) {
		return 0, false
	}
	k := wordEnd
	count := false
	for k < len(src) {
		switch src[k] {
		case ' ', '\t', '\r':
			k++
		case '\n':
			return k + 1, true
		case '-':
			if k+1 >= len(src) || src[k+1] != '-' {
				return 0, false
			}
			for k < len(src) && src[k] != '\n' {
				k++
			}
		case '/':
			if k+1 >= len(src) || src[k+1] != '*' {
				return 0, false
			}
			k += 2
			depth := 1
			crossedLine := false
			for k < len(src) && depth > 0 {
				if src[k] == '\n' {
					crossedLine = true
				}
				// Match the tokenizer: block comments do not nest.
				if k+1 < len(src) && src[k:k+2] == "*/" {
					depth--
					k += 2
				} else {
					k++
				}
			}
			if depth != 0 {
				return 0, false
			}
			if crossedLine {
				return k, true
			}
		default:
			if count {
				return 0, false
			}
			start := k
			for k < len(src) && src[k] >= '0' && src[k] <= '9' {
				k++
			}
			if _, valid := Count(src[start:k]); !valid {
				return 0, false
			}
			count = true
		}
	}
	return k, true
}
