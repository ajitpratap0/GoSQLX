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

package bridge

import (
	stderrors "errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	gerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ErrorSpan locates a parse error in the submitted SQL so the playground
// editor can mark it.
//
// Lines are 1-based. Columns are 1-based and counted in UTF-16 code units,
// the unit JavaScript strings and CodeMirror positions use, so the editor can
// map them to document offsets without re-reading the text. The span is
// end-exclusive; when it is empty (EndLine/EndColumn equal Line/Column) the
// error sits between characters, typically at the end of the input.
type ErrorSpan struct {
	Code      string `json:"code,omitempty"`
	Message   string `json:"message"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line"`
	EndColumn int    `json:"end_column"`
}

// positionedError returns the innermost structured error in err's chain that
// carries a position: the root cause the parser reported. Wrappers such as the
// parser's "tokenization error" (E2004) may have no position at all, and those
// that do repeat the wrapped error's full text in their own message.
func positionedError(err error) *gerrors.Error {
	var found *gerrors.Error
	for err != nil {
		var e *gerrors.Error
		if !stderrors.As(err, &e) {
			break
		}
		if e.Location.Line >= 1 && e.Location.Column >= 1 {
			found = e
		}
		err = e.Unwrap()
	}
	return found
}

// embeddedError matches the "Error E2002 at line 1, column 21: " prefix that
// an error's formatted text carries when a wrapper flattens it into its own
// message instead of keeping it as the cause.
var embeddedError = regexp.MustCompile(`Error (E\d{4}) at line \d+, column \d+: `)

// summarize returns the code and one-line message of the innermost error that
// e describes. Some wrappers embed the wrapped error's formatted text (prefix,
// source excerpt, hint and help URL) in their message rather than keeping it
// as the cause; the last embedded error is the root cause, and only the first
// line of its text is the message.
func summarize(e *gerrors.Error) (string, string) {
	code, msg := string(e.Code), e.Message
	if m := embeddedError.FindAllStringSubmatchIndex(msg, -1); len(m) > 0 {
		last := m[len(m)-1]
		code, msg = msg[last[2]:last[3]], msg[last[1]:]
	}
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	return code, strings.TrimSpace(msg)
}

// tokenEndAt returns the end of the token that starts at loc, if the SQL
// tokenizes and such a token exists.
func tokenEndAt(sql string, loc models.Location) (models.Location, bool) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return models.Location{}, false
	}
	for _, tok := range tokens {
		if tok.Start == loc {
			return tok.End, true
		}
	}
	return models.Location{}, false
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// errorSpan returns the location of err in sql, or nil when err carries no
// position. The tokenizer reports columns in bytes (a tab is one column) and a
// token's start is the token itself, not the whitespace or comments before it;
// the byte offset is converted to a UTF-16 column here. The span covers the token that starts at the error position, or one
// character when no token does (for example after a tokenizer error).
func errorSpan(sql string, err error) *ErrorSpan {
	e := positionedError(err)
	if e == nil {
		return nil
	}

	src := newSourceLines(sql)
	start := src.offset(e.Location)
	end := start

	if tokEnd, ok := tokenEndAt(sql, e.Location); ok {
		end = src.offset(tokEnd)
	} else if line, off := src.locate(start); off < len(src.text(line)) {
		_, size := utf8.DecodeRuneInString(src.text(line)[off:])
		end = start + size
	}
	if end < start {
		end = start
	}

	line, col := src.utf16Position(start)
	endLine, endCol := src.utf16Position(end)
	code, msg := summarize(e)
	return &ErrorSpan{
		Code:      code,
		Message:   msg,
		Line:      line,
		Column:    col,
		EndLine:   endLine,
		EndColumn: endCol,
	}
}

// sourceLines indexes the lines of the SQL by byte offset.
type sourceLines struct {
	lines  []string
	starts []int // byte offset of each line's first byte
}

func newSourceLines(sql string) sourceLines {
	lines := strings.Split(sql, "\n")
	starts := make([]int, len(lines))
	off := 0
	for i, l := range lines {
		starts[i] = off
		off += len(l) + 1
	}
	return sourceLines{lines: lines, starts: starts}
}

// text returns 1-based line n without a trailing carriage return, which
// editors drop.
func (s sourceLines) text(n int) string {
	return strings.TrimSuffix(s.lines[n-1], "\r")
}

// offset converts a tokenizer location to a byte offset in the SQL.
func (s sourceLines) offset(loc models.Location) int {
	line, off := clampLocation(s.lines, loc)
	return s.starts[line-1] + off
}

// locate returns the 1-based line holding byte offset abs and the byte offset
// within it, clamped to the line's text.
func (s sourceLines) locate(abs int) (int, int) {
	i := sort.Search(len(s.starts), func(i int) bool { return s.starts[i] > abs }) - 1
	if i < 0 {
		i = 0
	}
	line := i + 1
	off := min(abs-s.starts[i], len(s.text(line)))
	return line, max(off, 0)
}

// utf16Position returns the 1-based line and UTF-16 column of byte offset abs.
func (s sourceLines) utf16Position(abs int) (int, int) {
	line, off := s.locate(abs)
	return line, utf16Len(s.text(line)[:off]) + 1
}

// clampLocation converts a 1-based line and tokenizer column into a line
// number and a byte offset within that line, clamped to the text and moved
// back to a rune boundary. The tokenizer counts one column per byte. A trailing
// carriage return is excluded, since editors drop it.
func clampLocation(lines []string, loc models.Location) (int, int) {
	line := min(max(loc.Line, 1), len(lines))
	text := strings.TrimSuffix(lines[line-1], "\r")
	if loc.Line > len(lines) {
		return line, len(text)
	}
	off := min(max(loc.Column-1, 0), len(text))
	for off > 0 && off < len(text) && !utf8.RuneStart(text[off]) {
		off--
	}
	return line, off
}
