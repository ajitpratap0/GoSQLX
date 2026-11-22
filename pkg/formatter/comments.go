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

	"github.com/ajitpratap0/GoSQLX/internal/batch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// ErrUnplaceableComment is returned by JoinWithComments for a comment that
// carries meaning to the database (an optimizer hint such as /*+ FULL(t) */ or
// a MySQL executable comment such as /*!40101 ... */) and cannot be put back
// where it was. Writing such a comment elsewhere, or dropping it, would change
// what the statement does, so the caller must leave the input unformatted.
var ErrUnplaceableComment = errors.New("formatter: cannot preserve comment")

// CommentLayout describes how JoinWithComments separates statements.
type CommentLayout struct {
	// Dialect selects lexical rules for rendered keywords and batch boundaries.
	Dialect string
	// Terminator is written after every statement except the last. Use ";"
	// when the rendered statements carry no terminator, "" when they already
	// end with one.
	Terminator string
	// Gap separates one statement (and its trailing comments) from the next:
	// "\n\n", "\n" or " ". It is widened to a line break whenever a line
	// comment would otherwise swallow the following text.
	Gap string
	// Batches holds the source positions of the SQL Server GO separators the
	// parser recognized (ast.BatchSeparator.Pos), so that the comment layer
	// splits the source at exactly the parser's batch boundaries. When it is
	// nil, GO lines are recognized from the tokens.
	Batches []models.Location
	// Starts holds the source position of the first token of every statement
	// the parser produced, one per rendered statement and in the same order
	// (GO separators included), as StatementStarts returns them. When it is
	// set, the source is cut into statements at exactly these positions, so a
	// ';' inside a statement (a procedure or trigger body) does not split it
	// and statements without a ';' between them (T-SQL) are told apart. When
	// it is nil, statements are found by splitting the tokens at ';'.
	Starts []models.Location
}

// JoinWithComments joins already-rendered statements and puts the comments of
// the original text back.
//
// stmts holds the rendered text of every statement in source order, tokens the
// token stream of the source (EOF is ignored) and comments the comments the
// tokenizer captured from it. Statements are matched to the source at the
// parser's statement start positions (layout.Starts) when they are given, and
// otherwise by splitting tokens at ';'.
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
//     has the same number of that keyword and the hinted one can be told
//     apart from the others by its surrounding words when the renderer
//     writes them in another order. A hint anywhere else, and a MySQL
//     executable comment (/*! ... */) inside a statement, make the call fail
//     with ErrUnplaceableComment. An executable comment followed by ';' on its
//     own is a statement of its own and is kept verbatim with its ';'.
//
// When the statements cannot be matched to the source (stmts and the runs of
// tokens differ in number, or a run does not begin at its layout.Starts
// position) every comment is put in front of the first statement, under the
// same restriction on hints. A comment is never attached to a statement it
// was not written next to.
//
// No comment is ever dropped: the comments of the result are those of the
// input.
func JoinWithComments(stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout) (string, error) {
	if len(comments) == 0 {
		return joinPlain(stmts, layout), nil
	}
	items := splitItems(tokens, layout)
	return joinWithCommentItems(stmts, tokens, comments, layout, items)
}

func joinWithCommentItems(stmts []string, tokens []models.TokenWithSpan, comments []models.Comment, layout CommentLayout, items []item) (string, error) {
	var nStmt int
	for _, it := range items {
		if !it.empty {
			nStmt++
		}
	}
	if nStmt != len(stmts) || len(stmts) == 0 || !batchesAgree(items, stmts, layout.Dialect) ||
		!startsAgree(items, layout.Starts) {
		return joinHoisted(stmts, comments, layout)
	}

	// Attach every comment to an item.
	type attach struct {
		leading  []string
		trailing []string
		hints    []placedHint
	}
	att := make([]attach, len(items))
	occs := make([]map[string]*hintOccs, len(items)) // per item, built on demand
	var tail []string
	for ci := range comments {
		c := comments[ci]
		c.Text = normalizeCommentText(c.Text)
		sig := isSignificantComment(c.Text)
		idx, role := locateComment(items, c)
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
					if occs[idx] == nil {
						occs[idx] = map[string]*hintOccs{}
					}
					if h, ok := it.hintSlot(tokens, c, occs[idx]); ok {
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
	prevBatch := false      // last emitted item, ignoring empty semicolons
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
				if stmt, err = insertHints(stmt, a.hints, layout.Dialect); err != nil {
					return "", err
				}
			}
			chunk.WriteString(stmt)
			if i < len(items)-1 && !it.batch && !items[i+1].execute {
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
			if it.batch || prevBatch {
				gap = "\n"
			} else if (prevEndsInLine || len(a.leading) > 0) && !strings.Contains(gap, "\n") {
				gap = "\n"
			}
			sb.WriteString(gap)
		}
		sb.WriteString(chunk.String())
		if len(a.trailing) > 0 {
			endsInLine = strings.HasPrefix(lastComment(a.trailing), "--")
		}
		prevEndsInLine = endsInLine
		prevBatch = it.batch
	}
	for _, t := range tail {
		sb.WriteString("\n")
		sb.WriteString(t)
	}
	return sb.String(), nil
}

// normalizeCommentText uses LF endings, including the CR a line comment can
// retain from a source CRLF terminator.
func normalizeCommentText(text string) string {
	if strings.HasPrefix(text, "--") {
		text = strings.TrimSuffix(text, "\r")
	}
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
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
			if !isBatchText(stmts[i-1], layout.Dialect) {
				sb.WriteString(layout.Terminator)
			}
			if isBatchText(s, layout.Dialect) || isBatchText(stmts[i-1], layout.Dialect) {
				sb.WriteByte('\n')
			} else {
				sb.WriteString(layout.Gap)
			}
		}
		sb.WriteString(s)
	}
	return sb.String()
}

func isBatchText(s, dialect string) bool {
	return isSQLServerDialect(dialect) && batch.IsText(s)
}

func isSQLServerDialect(d string) bool {
	switch strings.ToLower(d) {
	case "sqlserver", "mssql", "tsql":
		return true
	}
	return false
}

// joinHoisted is the fallback used when statements cannot be matched to the
// source: all comments go in front of the first statement.
func joinHoisted(stmts []string, comments []models.Comment, layout CommentLayout) (string, error) {
	var sb strings.Builder
	for _, c := range comments {
		if isSignificantComment(c.Text) {
			return "", fmt.Errorf("%w: %s", ErrUnplaceableComment, abbreviate(c.Text))
		}
		sb.WriteString(normalizeCommentText(c.Text))
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
	batch       bool
	execute     bool // SQL*Plus execute line, without a separate AST statement
	// start and end bound the item in the source: start is the first token
	// (or, for an empty item, its ';'), end is just past the terminator (or
	// the last token).
	start, end models.Location
}

// batchesAgree reports whether the GO items of the source are the rendered
// GO statements, one for one.
func batchesAgree(items []item, stmts []string, dialect string) bool {
	si := 0
	for _, it := range items {
		if it.empty {
			continue
		}
		if it.batch != (isBatchText(stmts[si], dialect) || (it.execute && stmts[si] == "/")) {
			return false
		}
		si++
	}
	return true
}

// startsAgree reports whether, when the parser's statement starts are known,
// every statement item begins at its start, one for one.
func startsAgree(items []item, starts []models.Location) bool {
	if starts == nil {
		return true
	}
	j := 0
	for _, it := range items {
		if it.empty {
			continue
		}
		if j >= len(starts) || it.start != starts[j] {
			return false
		}
		j++
	}
	return j == len(starts)
}

// splitItems splits tokens into statements and, in SQL Server, GO lines: those
// at layout.Batches, or those batch.End recognizes when it is nil. Statements
// begin at layout.Starts when it is set (see splitAtStarts) and are otherwise
// cut at every ';'.
func splitItems(tokens []models.TokenWithSpan, layout CommentLayout) []item {
	var items []item
	sqlServer := isSQLServerDialect(layout.Dialect)
	byStarts := layout.Starts != nil
	nextBatch, nextStart := 0, 0
	cur := item{first: -1, term: -1}
	// pending holds the ';' tokens seen in cur since its last other token
	// (byStarts only): the first ends the statement unless another of its
	// tokens follows, the others are stray empty statements.
	var pending []int
	flush := func() {
		if cur.first >= 0 {
			if len(pending) > 0 {
				cur.term = pending[0]
				cur.end = tokens[pending[0]].End
			}
			items = append(items, cur)
			for _, k := range pending[min(1, len(pending)):] {
				items = append(items, item{first: k, last: k - 1, term: k, empty: true, start: tokens[k].Start, end: tokens[k].End})
			}
		}
		pending = pending[:0]
		cur = item{first: -1, term: -1}
	}
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if sqlServer {
			end, ok := 0, false
			if layout.Batches == nil {
				end, ok = batch.End(tokens, i)
			} else if nextBatch < len(layout.Batches) && t.Start == layout.Batches[nextBatch] {
				nextBatch++
				end, _, ok = batch.Line(tokens, i)
				if !ok {
					end = i + 1
				}
				ok = true
			}
			if ok {
				flush()
				if byStarts && nextStart < len(layout.Starts) && t.Start == layout.Starts[nextStart] {
					nextStart++
				}
				items = append(items, item{first: i, last: end - 1, term: -1, batch: true, start: t.Start, end: tokens[end-1].End})
				i = end - 1
				continue
			}
		}
		if t.Token.Type == models.TokenTypeEOF {
			continue
		}
		if byStarts && nextStart < len(layout.Starts) && t.Start == layout.Starts[nextStart] {
			nextStart++
			flush()
			cur.first, cur.start = i, t.Start
		}
		if t.Token.Type == models.TokenTypeSemicolon {
			switch {
			case cur.first < 0:
				items = append(items, item{first: i, last: i - 1, term: i, empty: true, start: t.Start, end: t.End})
			case byStarts:
				pending = append(pending, i)
			default:
				cur.term = i
				cur.end = t.End
				flush()
			}
			continue
		}
		if cur.first < 0 {
			cur.first = i
			cur.start = t.Start
		}
		pending = pending[:0]
		cur.last = i
		cur.end = t.End
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
	// sigs holds the context signature (see occurrenceSig) of every
	// occurrence of keyword in the source statement, in source order. The
	// rendered statement must show the same occurrences, possibly reordered
	// by the renderer (Oracle START WITH before CONNECT BY), for the hint to
	// be placed. nil skips the check.
	sigs []string
}

// hintOccs lists the occurrences of one hint keyword in a source statement:
// their token indexes and context signatures (occurrenceSig), in source
// order. It is computed once per statement and keyword and shared by every
// hint on that keyword.
type hintOccs struct {
	idx  []int
	sigs []string
}

// hintSlot reports whether c lies directly after a keyword that can carry a
// hint (SELECT, INSERT, UPDATE, DELETE, MERGE, REPLACE) of the statement, and
// where that keyword is among the statement's occurrences of the same word.
// cache holds the occurrences of each keyword in the statement, filled on
// first use.
func (it item) hintSlot(tokens []models.TokenWithSpan, c models.Comment, cache map[string]*hintOccs) (placedHint, bool) {
	if it.empty || it.first < 0 || it.first == it.last {
		return placedHint{}, false
	}
	// j is the last token of the statement that starts before the comment;
	// the comment must lie between it and the next token.
	n := sort.Search(it.last-it.first+1, func(k int) bool {
		return before(c.Start, tokens[it.first+k].Start)
	})
	j := it.first + n - 1
	if j < it.first || j >= it.last || before(c.Start, tokens[j].End) || !before(c.Start, tokens[j+1].Start) {
		return placedHint{}, false
	}
	kw, ok := hintKeyword(tokens[j].Token)
	if !ok {
		return placedHint{}, false
	}
	occ := cache[kw]
	if occ == nil {
		occ = &hintOccs{}
		span := tokens[it.first : it.last+1]
		for k := it.first; k <= it.last; k++ {
			if w, isWord := wordToken(tokens[k].Token); isWord && strings.EqualFold(w, kw) {
				occ.idx = append(occ.idx, k)
				occ.sigs = append(occ.sigs, occurrenceSig(span, k-it.first))
			}
		}
		cache[kw] = occ
	}
	ordinal := sort.SearchInts(occ.idx, j)
	return placedHint{text: c.Text, keyword: kw, ordinal: ordinal, total: len(occ.idx), sigs: occ.sigs}, true
}

// occurrenceSig returns a signature of the context of the keyword at
// tokens[k]: the last few words before it and the first few words after it
// within its parenthesized scope, upper-cased, ignoring punctuation, string
// literals and the optional AS keyword. The signature tells apart nested
// SELECTs that the renderer may write in another order than the source, as
// in "CONNECT BY ... IN (SELECT 1 FROM u) START WITH ... IN (SELECT 2 ...)".
func occurrenceSig(tokens []models.TokenWithSpan, k int) string {
	const nBefore, nAfter = 3, 4
	var before, after []string
	for i := k - 1; i >= 0 && len(before) < nBefore; i-- {
		if w, ok := sigWord(tokens[i].Token); ok {
			before = append(before, w)
		}
	}
	depth := 0
	for i := k + 1; i < len(tokens) && len(after) < nAfter; i++ {
		switch tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
			continue
		case models.TokenTypeRParen:
			depth--
			continue
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			depth = -1
		}
		if depth < 0 {
			break
		}
		if w, ok := sigWord(tokens[i].Token); ok {
			after = append(after, w)
		}
	}
	var sb strings.Builder
	for i := len(before) - 1; i >= 0; i-- {
		sb.WriteString(before[i])
		sb.WriteByte(' ')
	}
	sb.WriteByte('|')
	for _, w := range after {
		sb.WriteByte(' ')
		sb.WriteString(w)
	}
	return sb.String()
}

// sigWord returns the upper-case text of a word, quoted name or number token
// for occurrenceSig. String literals (whose escaping a renderer may change),
// punctuation and AS (which a renderer may add before an alias) are skipped.
func sigWord(tok models.Token) (string, bool) {
	if tok.Type == models.TokenTypeNumber {
		return tok.Value, tok.Value != ""
	}
	if tok.Quote != 0 && tok.Value != "" && (tok.Type == models.TokenTypeIdentifier || tok.Type == models.TokenTypeDoubleQuotedString) {
		return strings.ToUpper(tok.Value), true
	}
	w, ok := wordToken(tok)
	if !ok || strings.EqualFold(w, "AS") {
		return "", false
	}
	return strings.ToUpper(w), true
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
// Items are in source order and do not overlap, so the item is found by
// binary search: the first one that ends after the comment starts.
func locateComment(items []item, c models.Comment) (int, commentRole) {
	if len(items) == 0 {
		return 0, roleTail
	}
	i := sort.Search(len(items), func(i int) bool { return before(c.Start, items[i].end) })
	if i < len(items) {
		it := items[i]
		if before(c.Start, it.start) {
			// Between the previous item and this one (or before the first).
			if i > 0 && !it.empty && c.Start.Line == items[i-1].end.Line {
				return i - 1, roleTrailing
			}
			return i, roleLeading
		}
		return i, roleInner
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
func insertHints(stmt string, hints []placedHint, dialect ...string) (string, error) {
	type insertion struct {
		at   int // byte offset just after the keyword
		text string
	}
	ins := make([]insertion, 0, len(hints))
	words := map[string][]wordOcc{} // upper-case word -> occurrences in stmt
	matchers := map[string]*occMatcher{}
	scanned := false
	for _, h := range hints {
		if h.ordinal == 0 && h.total >= 1 {
			if end, ok := leadingWordEnd(stmt, h.keyword); ok {
				ins = append(ins, insertion{end, h.text})
				continue
			}
		}
		if !scanned {
			var d string
			if len(dialect) > 0 {
				d = dialect[0]
			}
			var err error
			words, err = wordEnds(stmt, d)
			if err != nil {
				return "", fmt.Errorf("%w: rendered statement: %v", ErrUnplaceableComment, err)
			}
			scanned = true
		}
		occs := words[h.keyword]
		if len(occs) != h.total || h.ordinal >= len(occs) {
			return "", fmt.Errorf("%w: %s (rendered statement does not keep the %s it follows)", ErrUnplaceableComment, abbreviate(h.text), h.keyword)
		}
		m := matchers[h.keyword]
		if m == nil || !m.covers(h.sigs) {
			m = newOccMatcher(h.sigs, occs)
			matchers[h.keyword] = m
		}
		at, ok := m.match(h, occs)
		if !ok {
			return "", fmt.Errorf("%w: %s (rendered statement reorders the %s it follows)", ErrUnplaceableComment, abbreviate(h.text), h.keyword)
		}
		ins = append(ins, insertion{at, h.text})
	}
	// Write the statement once with every hint in place; hints at one offset
	// keep their source order.
	sort.SliceStable(ins, func(a, b int) bool { return ins[a].at < ins[b].at })
	var sb strings.Builder
	n := len(stmt)
	for _, in := range ins {
		n += len(in.text) + 1
	}
	sb.Grow(n)
	prev := 0
	for _, in := range ins {
		sb.WriteString(stmt[prev:in.at])
		sb.WriteByte(' ')
		sb.WriteString(in.text)
		prev = in.at
	}
	sb.WriteString(stmt[prev:])
	return sb.String(), nil
}

// occMatcher finds, for the hints on one keyword of one statement, the
// rendered occurrence of the keyword each hint followed in the source. When
// the rendered occurrences have the same context signatures in the same order
// as the source ones, that is the one with the same ordinal. When the renderer
// wrote them in another order, it is the one whose signature matches,
// provided that signature is unique on both sides; otherwise the keyword
// cannot be identified. The signatures are compared once per statement and
// keyword, not once per hint.
type occMatcher struct {
	sigs []string // the source signatures it was built for
	same bool     // the rendered occurrences have the same signatures in order
	// For a reordered statement: how often each signature occurs in the
	// source, and how often and (when once) where in the rendered statement.
	inSource map[string]int
	rendered map[string]int
	at       map[string]int
}

func newOccMatcher(sigs []string, occs []wordOcc) *occMatcher {
	m := &occMatcher{sigs: sigs}
	if sigs == nil || len(sigs) != len(occs) {
		return m
	}
	m.same = true
	for i := range occs {
		if occs[i].sig != sigs[i] {
			m.same = false
			break
		}
	}
	if m.same {
		return m
	}
	m.inSource = make(map[string]int, len(sigs))
	for _, s := range sigs {
		m.inSource[s]++
	}
	m.rendered = make(map[string]int, len(occs))
	m.at = make(map[string]int, len(occs))
	for _, o := range occs {
		m.rendered[o.sig]++
		m.at[o.sig] = o.end
	}
	return m
}

// covers reports whether m was built for exactly sigs (the same shared
// slice, as every hint on a keyword of one statement carries).
func (m *occMatcher) covers(sigs []string) bool {
	if len(sigs) != len(m.sigs) {
		return false
	}
	return len(sigs) == 0 || &sigs[0] == &m.sigs[0]
}

// match returns the end offset of the rendered occurrence that h followed,
// for a hint whose sigs m covers; ok is false when it cannot be identified.
func (m *occMatcher) match(h placedHint, occs []wordOcc) (at int, ok bool) {
	if h.sigs == nil {
		return occs[h.ordinal].end, true
	}
	if len(h.sigs) != len(occs) {
		return 0, false
	}
	if m.same {
		return occs[h.ordinal].end, true
	}
	want := h.sigs[h.ordinal]
	if m.inSource[want] != 1 || m.rendered[want] != 1 {
		return 0, false
	}
	return m.at[want], true
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

// wordOcc is one occurrence of a hint keyword in a rendered statement: the
// byte offset just after it and its context signature (occurrenceSig).
type wordOcc struct {
	end int
	sig string
}

// wordEnds uses the active dialect's lexer so quote, escape, and delimited
// identifier rules are identical to those used to parse the statement.
func wordEnds(stmt, dialect string) (map[string][]wordOcc, error) {
	out := map[string][]wordOcc{}
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if dialect != "" {
		tkz.SetDialect(keywords.SQLDialect(dialect))
	}
	tokens, err := tkz.TokenizeString(stmt)
	if err != nil {
		return nil, err
	}
	lineStart := []int{0}
	for i := range stmt {
		if stmt[i] == '\n' {
			lineStart = append(lineStart, i+1)
		}
	}
	for k, tok := range tokens {
		w, ok := hintKeyword(tok.Token)
		if !ok || tok.Start.Line < 1 || tok.Start.Line > len(lineStart) ||
			tok.End.Line < 1 || tok.End.Line > len(lineStart) {
			continue
		}
		start := lineStart[tok.Start.Line-1] + tok.Start.Column - 1
		end := lineStart[tok.End.Line-1] + tok.End.Column - 1
		if start < 0 || end > len(stmt) || start >= end {
			continue
		}
		if start > 0 && (stmt[start-1] == '.' || stmt[start-1] == '@' || stmt[start-1] == ':') {
			continue
		}
		out[w] = append(out[w], wordOcc{end: end, sig: occurrenceSig(tokens, k)})
	}
	return out, nil
}

func abbreviate(s string) string {
	if len(s) > 40 {
		return s[:37] + "..."
	}
	return s
}

// BatchPositions returns the source positions of the GO separators of tree
// for CommentLayout.Batches. The result is non-nil, also for a tree without
// separators, so that the comment layer follows the parser's boundaries.
func BatchPositions(tree *ast.AST) []models.Location {
	out := []models.Location{}
	if tree == nil {
		return out
	}
	for _, stmt := range tree.Statements {
		if sep, ok := stmt.(*ast.BatchSeparator); ok && sep != nil {
			out = append(out, sep.Pos)
		}
	}
	return out
}

// StatementPositions returns the source start position of every statement of
// tree (ast.AST.StatementStarts) for CommentLayout.Starts, or nil when the
// tree does not carry one per statement (it was built by hand or from tokens
// without positions), in which case the comment layer splits at ';'.
func StatementPositions(tree *ast.AST) []models.Location {
	if tree == nil || len(tree.StatementStarts) != len(tree.Statements) {
		return nil
	}
	return tree.StatementStarts
}
