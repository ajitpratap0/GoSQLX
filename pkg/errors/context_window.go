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

package errors

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Bounded SQL context rendering (#615).
//
// Error messages show the offending source line plus its neighbours with a caret
// under the error column. Rendering those lines verbatim, and padding the caret
// with Column-1 spaces, makes the size of the message proportional to the size
// of the input: a single 100 KB line used to yield a ~205 KB error string, and a
// 1 MiB line a ~2 MiB one. The helpers below clip long lines to a window around
// the error column so the context block has a fixed upper bound.
const (
	// contextRadius is the number of bytes shown on each side of the error column
	// when a line has to be clipped.
	contextRadius = 60
	// contextMaxLine is the longest line (in bytes) that is rendered verbatim.
	contextMaxLine = 2 * contextRadius
	// contextEllipsis marks the side(s) of a clipped line that were cut off.
	contextEllipsis = "..."
)

// lineRange returns the '\n'-separated lines first..last (1-based, inclusive) of
// sql. It is equivalent to strings.Split(sql, "\n")[first-1 : min(last, n)] where
// n is the number of lines, but it stops scanning after the last requested line
// and never allocates proportionally to the size of sql. It returns nil when
// first is past the last line.
func lineRange(sql string, first, last int) []string {
	if first < 1 {
		first = 1
	}
	if last < first {
		return nil
	}
	rest := sql
	for i := 1; i < first; i++ {
		idx := strings.IndexByte(rest, '\n')
		if idx < 0 {
			return nil
		}
		rest = rest[idx+1:]
	}
	capHint := last - first + 1
	if capHint > 8 || capHint < 1 { // callers may pass a huge last; do not trust it for sizing
		capHint = 8
	}
	out := make([]string, 0, capHint)
	for n := first; n <= last; n++ {
		idx := strings.IndexByte(rest, '\n')
		if idx < 0 {
			out = append(out, rest)
			break
		}
		out = append(out, rest[:idx])
		rest = rest[idx+1:]
	}
	return out
}

// clipLine returns the text to display for line, given the byte offset off of the
// error column within it. Lines of at most contextMaxLine bytes are returned
// verbatim. Longer lines are cut to about contextRadius bytes on either side of
// off, on UTF-8 boundaries, with contextEllipsis marking each cut side. start is
// the byte index in line where the displayed text begins and prefixLen is the
// length of the leading ellipsis (0 or len(contextEllipsis)).
func clipLine(line string, off int) (display string, start, prefixLen int) {
	if len(line) <= contextMaxLine {
		return line, 0, 0
	}
	center := off
	if center < 0 {
		center = 0
	}
	if center > len(line) {
		center = len(line)
	}
	start = center - contextRadius
	if start < 0 {
		start = 0
	}
	end := center + contextRadius
	if end > len(line) {
		end = len(line)
	}
	for start < len(line) && !utf8.RuneStart(line[start]) {
		start++
	}
	for end > start && end < len(line) && !utf8.RuneStart(line[end]) {
		end--
	}

	var sb strings.Builder
	sb.Grow(end - start + 2*len(contextEllipsis))
	if start > 0 {
		sb.WriteString(contextEllipsis)
		prefixLen = len(contextEllipsis)
	}
	sb.WriteString(line[start:end])
	if end < len(line) {
		sb.WriteString(contextEllipsis)
	}
	return sb.String(), start, prefixLen
}

// caretPad returns the number of spaces to put between the gutter and the caret
// line, for a line whose displayed text is display (see clipLine). It is never
// larger than the displayed text, so the caret line is bounded too.
func caretPad(off int, display string, start, prefixLen int, verbatim bool) int {
	if off < 0 {
		off = 0
	}
	if verbatim {
		if off > contextMaxLine {
			return contextMaxLine
		}
		return off
	}
	pad := off - start + prefixLen
	if pad > len(display) {
		pad = len(display)
	}
	if pad < 0 {
		pad = 0
	}
	return pad
}

// clampHighlight bounds the caret run length to [1, contextMaxLine].
func clampHighlight(n int) int {
	if n < 1 {
		return 1
	}
	if n > contextMaxLine {
		return contextMaxLine
	}
	return n
}

// renderContext writes the source context block for loc to sb: linesBefore lines
// before the error line, the error line, a caret indicator (when loc.Column > 0)
// and linesAfter lines after it, each prefixed by a right-aligned line number
// gutter. Lines longer than contextMaxLine bytes are clipped around the error
// column (see clipLine), so the output size does not depend on the input size.
//
// It returns the number of lines written after the error line, and ok=false (with
// nothing written) when sql is empty or loc does not address a line of sql.
func renderContext(sb *strings.Builder, sql string, loc models.Location, highlightLen, linesBefore, linesAfter int) (afterPrinted int, ok bool) {
	if sql == "" || loc.Line <= 0 || loc.Line > len(sql)+1 {
		return 0, false
	}
	if linesBefore < 0 {
		linesBefore = 0
	}
	if linesAfter < 0 {
		linesAfter = 0
	}
	if linesAfter > len(sql)+1 {
		linesAfter = len(sql) + 1
	}

	first := loc.Line - linesBefore
	if first < 1 {
		first = 1
	}
	lines := lineRange(sql, first, loc.Line+linesAfter)
	errIdx := loc.Line - first
	if errIdx >= len(lines) {
		return 0, false
	}

	endLine := first + len(lines) - 1
	width := len(strconv.Itoa(endLine))
	if width < 2 {
		width = 2
	}
	off := loc.Column - 1

	sb.WriteString("\n")
	for i, line := range lines {
		num := first + i
		display, start, prefixLen := clipLine(line, off)
		fmt.Fprintf(sb, "  %*d | %s\n", width, num, display)

		if i == errIdx && loc.Column > 0 {
			gutter := len("  ") + width + len(" | ")
			pad := caretPad(off, display, start, prefixLen, len(line) <= contextMaxLine)
			sb.WriteString(strings.Repeat(" ", gutter+pad))
			sb.WriteString(strings.Repeat("^", clampHighlight(highlightLen)))
			sb.WriteString("\n")
		}
	}
	return len(lines) - errIdx - 1, true
}
