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

// errorSpan returns the location of err in sql, or nil when err carries no
// position. The tokenizer reports columns in bytes; they are converted here.
// The span covers the token that starts at the error position, or one
// character when no token does (for example after a tokenizer error).
func errorSpan(sql string, err error) *ErrorSpan {
	e := positionedError(err)
	if e == nil {
		return nil
	}

	lines := strings.Split(sql, "\n")
	line, startByte := clampLocation(lines, e.Location)
	endLine, endByte := line, startByte

	if end, ok := tokenEndAt(sql, e.Location); ok {
		endLine, endByte = clampLocation(lines, end)
	} else if text := strings.TrimSuffix(lines[line-1], "\r"); startByte < len(text) {
		_, size := utf8.DecodeRuneInString(text[startByte:])
		endByte = startByte + size
	}
	if endLine < line || (endLine == line && endByte < startByte) {
		endLine, endByte = line, startByte
	}

	return &ErrorSpan{
		Code:      string(e.Code),
		Message:   e.Message,
		Line:      line,
		Column:    utf16Len(lines[line-1][:startByte]) + 1,
		EndLine:   endLine,
		EndColumn: utf16Len(lines[endLine-1][:endByte]) + 1,
	}
}

// positionedError returns the outermost structured error in err's chain that
// carries a position. Wrappers such as the parser's "tokenization error"
// (E2004) have none; the tokenizer error they wrap does.
func positionedError(err error) *gerrors.Error {
	for err != nil {
		var e *gerrors.Error
		if !stderrors.As(err, &e) {
			return nil
		}
		if e.Location.Line >= 1 && e.Location.Column >= 1 {
			return e
		}
		err = e.Unwrap()
	}
	return nil
}

// clampLocation converts a 1-based line and byte column into a line number and
// a byte offset within that line, clamped to the text and moved back to a rune
// boundary. A trailing carriage return is excluded, since editors drop it.
func clampLocation(lines []string, loc models.Location) (int, int) {
	line := loc.Line
	if line > len(lines) {
		line = len(lines)
	}
	text := strings.TrimSuffix(lines[line-1], "\r")
	off := loc.Column - 1
	if loc.Line > len(lines) || off > len(text) {
		off = len(text)
	}
	if off < 0 {
		off = 0
	}
	for off > 0 && off < len(text) && !utf8.RuneStart(text[off]) {
		off--
	}
	return line, off
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
