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

package formatter

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ErrUnplaceableComment is returned by JoinWithComments for a comment that
// carries meaning to the database (an optimizer hint such as /*+ FULL(t) */ or
// a MySQL executable comment such as /*!40101 ... */) and cannot be put back
// where it was. Writing such a comment elsewhere, or dropping it, would change
// what the statement does, so the caller must leave the input unformatted.
var ErrUnplaceableComment = errors.New("formatter: cannot preserve comment")

// CommentLayout describes how JoinWithComments separates statements.
type CommentLayout struct {
	// Terminator is written after every statement except the last. Use ";"
	// when the rendered statements carry no terminator, "" when they already
	// end with one.
	Terminator string
	// Gap separates one statement (and its trailing comments) from the next:
	// "\n\n", "\n" or " ". It is widened to a line break whenever a line
	// comment would otherwise swallow the following text.
	Gap string
}

// JoinWithComments joins already-rendered statements and puts the comments of
// the original text back.
//
// stmts holds the rendered text of every statement in source order, tokens the
// token stream of the source (EOF is ignored) and comments the comments the
// tokenizer captured from it. Statements are matched to the source by
// splitting tokens at ';'.
//
// Where a comment goes:
//
//   - A comment between two statements goes in front of the next statement,
//     except one that follows the previous statement on the same line, which
//     stays after it (SELECT 1; -- done).
//   - A comment inside a statement is moved in front of that statement, in
//     source order. The renderer lays statements out afresh, so there is no
//     position inside them to return to.
//   - A comment after the last statement stays after it.
//   - An optimizer hint directly after a SELECT, INSERT, UPDATE, DELETE,
//     MERGE or REPLACE keyword (SELECT /*+ ... */, also one inside a CTE,
//     subquery or union branch) stays there, provided the rendered statement
//     has the same number of that keyword. A hint anywhere else, and a MySQL
//     executable comment (/*! ... */) inside a statement, make the call fail
//     with ErrUnplaceableComment. An executable comment followed by ';' on its
//     own is a statement of its own and is kept verbatim with its ';'.
//
// When the statements cannot be matched to the source (stmts and the
// semicolon-separated runs of tokens differ in number) every comment is put
// in front of the first statement, under the same restriction on hints.
//
// No comment is ever dropped: the comments of the result are those of the
// input.
func JoinWithComments(stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout) (string, error) {
	if len(comments) == 0 {
		return joinPlain(stmts, layout), nil
	}
	items := splitItems(tokens)
	var nStmt int
	for _, it := range items {
		if !it.empty {
			nStmt++
		}
	}
	if nStmt != len(stmts) || len(stmts) == 0 {
		return joinHoisted(stmts, comments, layout)
	}

	// Attach every comment to an item.
	type attach struct {
		leading  []string
		trailing []string
		hints    []placedHint
	}
	att := make([]attach, len(items))
	var tail []string
	for ci := range comments {
		c := comments[ci]
		sig := isSignificantComment(c.Text)
		idx, role := locateComment(items, tokens, c)
		switch role {
		case roleLeading:
			if sig && !items[idx].empty && isExecutable(c.Text) {
				// An executable comment in front of a statement, with no ';'
				// of its own, runs together with it.
				return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
			}
			att[idx].leading = append(att[idx].leading, c.Text)
		case roleTrailing:
			if sig && isExecutable(c.Text) {
				return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
			}
			att[idx].trailing = append(att[idx].trailing, c.Text)
		case roleInner:
			it := items[idx]
			if sig {
				if isHint(c.Text) {
					if h, ok := it.hintSlot(tokens, c); ok {
						att[idx].hints = append(att[idx].hints, h)
						continue
					}
				}
				return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
			}
			att[idx].leading = append(att[idx].leading, c.Text)
		case roleTail:
			if sig && isExecutable(c.Text) {
				return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
			}
			tail = append(tail, c.Text)
		}
	}

	var sb strings.Builder
	prevEndsInLine := false // the text written so far ends in a line comment
	si := 0                 // index into stmts
	for i, it := range items {
		a := att[i]
		var chunk strings.Builder
		endsInLine := false
		if it.empty {
			// A bare ';' with comments before it. If one of them is an
			// executable comment (/*!...*/;) the comment is the statement and
			// keeps its ';'; otherwise they are plain comments and the stray
			// ';' is dropped, as the formatter drops every empty statement.
			text := strings.Join(a.leading, "\n")
			chunk.WriteString(text)
			if hasExecutable(a.leading) {
				if strings.HasPrefix(lastComment(a.leading), "--") {
					chunk.WriteString("\n")
				}
				chunk.WriteString(";")
			} else {
				endsInLine = strings.HasPrefix(lastComment(a.leading), "--")
			}
		} else {
			for _, l := range a.leading {
				chunk.WriteString(l)
				chunk.WriteString("\n")
			}
			stmt := stmts[si]
			si++
			if len(a.hints) > 0 {
				var err error
				if stmt, err = insertHints(stmt, a.hints); err != nil {
					return "", err
				}
			}
			chunk.WriteString(stmt)
			if i < len(items)-1 {
				chunk.WriteString(layout.Terminator)
			}
		}
		for _, t := range a.trailing {
			chunk.WriteString(" ")
			chunk.WriteString(t)
		}
		if chunk.Len() == 0 {
			continue
		}
		if sb.Len() > 0 {
			gap := layout.Gap
			if (prevEndsInLine || len(a.leading) > 0) && !strings.Contains(gap, "\n") {
				gap = "\n"
			}
			sb.WriteString(gap)
		}
		sb.WriteString(chunk.String())
		if len(a.trailing) > 0 {
			endsInLine = strings.HasPrefix(lastComment(a.trailing), "--")
		}
		prevEndsInLine = endsInLine
	}
	for _, t := range tail {
		sb.WriteString("\n")
		sb.WriteString(t)
	}
	return sb.String(), nil
}

func hasExecutable(comments []string) bool {
	for _, c := range comments {
		if isExecutable(c) {
			return true
		}
	}
	return false
}

func lastComment(c []string) string {
	if len(c) == 0 {
		return ""
	}
	return c[len(c)-1]
}

// joinPlain joins statements without comments.
func joinPlain(stmts []string, layout CommentLayout) string {
	var sb strings.Builder
	for i, s := range stmts {
		if i > 0 {
			sb.WriteString(layout.Terminator)
			sb.WriteString(layout.Gap)
		}
		sb.WriteString(s)
	}
	return sb.String()
}

// joinHoisted is the fallback used when statements cannot be matched to the
// source: all comments go in front of the first statement.
func joinHoisted(stmts []string, comments []models.Comment, layout CommentLayout) (string, error) {
	var sb strings.Builder
	for _, c := range comments {
		if isSignificantComment(c.Text) {
			return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
		}
		sb.WriteString(c.Text)
		sb.WriteString("\n")
	}
	sb.WriteString(joinPlain(stmts, layout))
	return sb.String(), nil
}

// item is one ';'-terminated run of tokens: a statement, or (empty) a bare
// ';' standing where a statement would be.
type item struct {
	first, last int // token indexes of the statement (first > last for empty)
	term        int // index of the terminating ';' token, -1 when absent
	empty       bool
	// start and end bound the item in the source: start is the first token
	// (or, for an empty item, its ';'), end is just past the terminator (or
	// the last token).
	start, end models.Location
}

// splitItems splits tokens at ';'.
func splitItems(tokens []models.TokenWithSpan) []item {
	var items []item
	cur := item{first: -1, term: -1}
	flush := func() {
		if cur.first >= 0 {
			items = append(items, cur)
		}
		cur = item{first: -1, term: -1}
	}
	for i := range tokens {
		t := tokens[i]
		switch t.Token.Type {
		case models.TokenTypeEOF:
			continue
		case models.TokenTypeSemicolon:
			if cur.first < 0 {
				items = append(items, item{first: i, last: i - 1, term: i, empty: true, start: t.Start, end: t.End})
				continue
			}
			cur.term = i
			cur.end = t.End
			flush()
		default:
			if cur.first < 0 {
				cur.first = i
				cur.start = t.Start
			}
			cur.last = i
			cur.end = t.End
		}
	}
	flush()
	return items
}

// placedHint is an optimizer hint written right after a statement keyword:
// the ordinal-th occurrence (0-based) of keyword among the total occurrences
// of that word in the statement, e.g. the hint in
// "WITH c AS (SELECT /*+ MATERIALIZE */ ...) SELECT ..." is the first of two
// SELECT keywords.
type placedHint struct {
	text    string
	keyword string
	ordinal int
	total   int
}

// hintSlot reports whether c lies directly after a keyword that can carry a
// hint (SELECT, INSERT, UPDATE, DELETE, MERGE, REPLACE) of the statement, and
// where that keyword is among the statement's occurrences of the same word.
func (it item) hintSlot(tokens []models.TokenWithSpan, c models.Comment) (placedHint, bool) {
	if it.empty || it.first < 0 || it.first == it.last {
		return placedHint{}, false
	}
	for j := it.first; j < it.last; j++ {
		kw, ok := hintKeyword(tokens[j].Token)
		if !ok || before(c.Start, tokens[j].End) {
			continue
		}
		if !before(c.Start, tokens[j+1].Start) {
			continue
		}
		h := placedHint{text: c.Text, keyword: kw}
		for k := it.first; k <= it.last; k++ {
			if w, isWord := wordToken(tokens[k].Token); isWord && strings.EqualFold(w, kw) {
				if k < j {
					h.ordinal++
				}
				h.total++
			}
		}
		return h, true
	}
	return placedHint{}, false
}

// hintKeyword returns the upper-case keyword of tok when it is an unquoted
// statement keyword that can carry an optimizer hint.
func hintKeyword(tok models.Token) (string, bool) {
	w, ok := wordToken(tok)
	if !ok {
		return "", false
	}
	switch kw := strings.ToUpper(w); kw {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE":
		return kw, true
	}
	return "", false
}

// wordToken returns the text of tok when it is an unquoted word (a keyword or
// bare identifier), not a string literal or quoted name.
func wordToken(tok models.Token) (string, bool) {
	if tok.Quote != 0 || tok.Value == "" {
		return "", false
	}
	switch tok.Type {
	case models.TokenTypeString, models.TokenTypeSingleQuotedString,
		models.TokenTypeTripleSingleQuotedString, models.TokenTypeTripleDoubleQuotedString,
		models.TokenTypeDollarQuotedString, models.TokenTypeByteStringLiteral,
		models.TokenTypeNationalStringLiteral, models.TokenTypeEscapedStringLiteral,
		models.TokenTypeUnicodeStringLiteral, models.TokenTypeHexStringLiteral,
		models.TokenTypeNumber:
		return "", false
	}
	for i := 0; i < len(tok.Value); i++ {
		if !isWordByte(tok.Value[i]) {
			return "", false
		}
	}
	return tok.Value, true
}

func isWordByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_' || b == '$' || b >= 0x80
}

type commentRole int

const (
	roleLeading commentRole = iota
	roleTrailing
	roleInner
	roleTail
)

// locateComment finds the item a comment belongs to and its role there.
func locateComment(items []item, tokens []models.TokenWithSpan, c models.Comment) (int, commentRole) {
	if len(items) == 0 {
		return 0, roleTail
	}
	for i, it := range items {
		if before(c.Start, it.start) {
			// Between the previous item and this one (or before the first).
			if i > 0 && !it.empty && c.Start.Line == items[i-1].end.Line && items[i-1].term >= 0 {
				return i - 1, roleTrailing
			}
			return i, roleLeading
		}
		if before(c.Start, it.end) {
			return i, roleInner
		}
	}
	last := items[len(items)-1]
	if c.Start.Line == last.end.Line {
		return len(items) - 1, roleTrailing
	}
	return len(items) - 1, roleTail
}

// before reports whether a is strictly earlier than b.
func before(a, b models.Location) bool {
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	return a.Column < b.Column
}

// isHint reports whether text is an optimizer hint comment, /*+ ... */.
func isHint(text string) bool { return strings.HasPrefix(text, "/*+") }

// isExecutable reports whether text is a MySQL/MariaDB executable comment,
// /*! ... */ or /*M! ... */, whose content the server runs.
func isExecutable(text string) bool {
	return strings.HasPrefix(text, "/*!") || strings.HasPrefix(text, "/*M!")
}

// isLineHint reports whether text is an Oracle line hint, --+ ... . It is
// significant like /*+ */ but cannot be written inline after a keyword (it
// would swallow the rest of the line), so it is never placed, only refused
// when it sits inside a statement.
func isLineHint(text string) bool { return strings.HasPrefix(text, "--+") }

// isSignificantComment reports whether a comment affects how the database
// runs the statement.
func isSignificantComment(text string) bool {
	return isHint(text) || isLineHint(text) || isExecutable(text)
}

// insertHints writes each hint after the keyword it followed in the source:
// "SELECT a FROM t" becomes "SELECT /*+ H */ a FROM t". A hint on the first
// word of the statement needs the rendered statement to start with that word.
// A hint on a later keyword (a SELECT inside a CTE or subquery) needs the
// rendered statement to have as many occurrences of the word as the source,
// and goes after the same one; otherwise the hint has no place to go and the
// call fails with ErrUnplaceableComment.
func insertHints(stmt string, hints []placedHint) (string, error) {
	type insertion struct {
		at   int // byte offset just after the keyword
		text string
	}
	var ins []insertion
	words := map[string][]int{} // upper-case word -> end offsets in stmt
	scanned := false
	for _, h := range hints {
		if h.ordinal == 0 && h.total >= 1 {
			if end, ok := leadingWordEnd(stmt, h.keyword); ok {
				ins = append(ins, insertion{end, h.text})
				continue
			}
		}
		if !scanned {
			words = wordEnds(stmt)
			scanned = true
		}
		ends := words[h.keyword]
		if len(ends) != h.total || h.ordinal >= len(ends) {
			return "", fmt.Errorf("%w: %s (rendered statement does not keep the %s it follows)", ErrUnplaceableComment, abbreviate(h.text), h.keyword)
		}
		ins = append(ins, insertion{ends[h.ordinal], h.text})
	}
	// Insert from the end so earlier offsets stay valid; hints at one offset
	// keep their source order.
	sort.SliceStable(ins, func(a, b int) bool { return ins[a].at > ins[b].at })
	for i := 0; i < len(ins); {
		j := i
		var group []string
		for j < len(ins) && ins[j].at == ins[i].at {
			group = append(group, ins[j].text)
			j++
		}
		stmt = stmt[:ins[i].at] + " " + strings.Join(group, " ") + stmt[ins[i].at:]
		i = j
	}
	return stmt, nil
}

// leadingWordEnd returns the end offset of the first word of stmt when it is
// keyword.
func leadingWordEnd(stmt, keyword string) (int, bool) {
	i := 0
	for i < len(stmt) && (stmt[i] == ' ' || stmt[i] == '\t' || stmt[i] == '\n' || stmt[i] == '\r') {
		i++
	}
	j := i
	for j < len(stmt) && (stmt[j] >= 'A' && stmt[j] <= 'Z' || stmt[j] >= 'a' && stmt[j] <= 'z') {
		j++
	}
	return j, strings.EqualFold(stmt[i:j], keyword)
}

// wordEnds scans rendered SQL and returns, for each hint-carrying keyword, the
// end offsets of its occurrences as a bare word, skipping string literals,
// quoted names and comments, and words that follow '.', '@' or ':'.
func wordEnds(stmt string) map[string][]int {
	out := map[string][]int{}
	n := len(stmt)
	for i := 0; i < n; {
		c := stmt[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			// Quoted text; a doubled quote or a backslash escape stays inside.
			i++
			for i < n {
				if stmt[i] == '\\' && c == '\'' && i+1 < n {
					i += 2
					continue
				}
				if stmt[i] == c {
					if i+1 < n && stmt[i+1] == c {
						i += 2
						continue
					}
					break
				}
				i++
			}
			i++
		case c == '-' && i+1 < n && stmt[i+1] == '-':
			for i < n && stmt[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && stmt[i+1] == '*':
			end := strings.Index(stmt[i+2:], "*/")
			if end < 0 {
				i = n
			} else {
				i += end + 4
			}
		case isWordByte(c):
			j := i
			for j < n && isWordByte(stmt[j]) {
				j++
			}
			if i == 0 || (stmt[i-1] != '.' && stmt[i-1] != '@' && stmt[i-1] != ':') {
				w := strings.ToUpper(stmt[i:j])
				switch w {
				case "SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "REPLACE":
					out[w] = append(out[w], j)
				}
			}
			i = j
		default:
			i++
		}
	}
	return out
}

func abbreviate(s string) string {
	if len(s) > 40 {
		return s[:37] + "..."
	}
	return s
}
