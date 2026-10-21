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

package highlight

import (
	goerrors "errors"
	"strings"
	"sync"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Span is a classified byte range of the source SQL.
//
// Start is inclusive and End is exclusive, both 0-based byte offsets into the
// string passed to Spans, so src[s.Start:s.End] is the span's text. Offsets
// always fall on UTF-8 boundaries.
type Span struct {
	Start    int      `json:"start"`
	End      int      `json:"end"`
	Category Category `json:"category"`
}

// Text returns the source text covered by the span. It returns "" when the
// span does not fit within src.
func (s Span) Text(src string) string {
	if s.Start < 0 || s.End > len(src) || s.Start > s.End {
		return ""
	}
	return src[s.Start:s.End]
}

// Option configures Spans.
type Option func(*config)

type config struct {
	dialect keywords.SQLDialect
}

// WithDialect selects the SQL dialect used for tokenization and keyword
// recognition. Unknown or empty dialects fall back to the default behaviour.
func WithDialect(d keywords.SQLDialect) Option {
	return func(c *config) { c.dialect = d }
}

// maxRecoveries bounds how many times Spans re-tokenizes a shrinking prefix
// after a lexical error before giving up and marking the remainder as Error.
const maxRecoveries = 4

// Spans classifies sql for syntax highlighting.
//
// The returned spans are sorted by Start, never overlap, and never carry
// Plain; any byte not covered by a span (typically whitespace) is plain text.
// Spans never fails: when the tokenizer rejects the input, everything before
// the offending position is still classified and the rest of the input is
// covered by a single Error span. Inputs the tokenizer refuses outright (for
// example, beyond its size limit) yield no spans.
//
// Spans is safe for concurrent use.
func Spans(sql string, opts ...Option) []Span {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.dialect != "" && !keywords.IsValidDialect(string(cfg.dialect)) {
		cfg.dialect = ""
	}
	if sql == "" {
		return nil
	}

	src := []byte(sql)
	h := classifier{
		src:     sql,
		kw:      keywordsFor(cfg.dialect),
		dialect: cfg.dialect,
	}

	h.indexLines()
	limit := len(src)
	errAt := -1
	for attempt := 0; ; attempt++ {
		spans, err := h.run(src[:limit], limit)
		if err == nil {
			if errAt >= 0 {
				spans = append(spans, Span{Start: errAt, End: len(src), Category: Error})
			}
			return spans
		}
		off, ok := h.errorOffset(err, limit)
		if !ok {
			if errAt < 0 {
				// The tokenizer refused the input outright (size or token
				// limits): leave it unhighlighted rather than guess.
				return nil
			}
			off = 0
		}
		if off <= 0 || attempt >= maxRecoveries {
			// The prefix cannot be recovered; mark everything as Error.
			return []Span{{Start: 0, End: len(src), Category: Error}}
		}
		// Re-tokenize only the text before the error.
		errAt, limit = off, off
	}
}

// lexeme is a token with resolved byte offsets.
type lexeme struct {
	start, end int
	typ        models.TokenType
	value      string
}

type classifier struct {
	src        string
	lineStarts []int
	kw         *keywords.Keywords
	dialect    keywords.SQLDialect
}

// run tokenizes input (a prefix of h.src of length limit) and classifies it.
func (h *classifier) run(input []byte, limit int) ([]Span, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if h.dialect != "" {
		tkz.SetDialect(h.dialect)
	}
	toks, err := tkz.Tokenize(input)
	if err != nil {
		return nil, err
	}

	comments := make([]Span, 0, len(tkz.Comments))
	for _, c := range tkz.Comments {
		start, ok1 := h.offset(c.Start, limit)
		end, ok2 := h.offset(c.End, limit)
		if !ok1 || !ok2 {
			continue
		}
		for end > start && (h.src[end-1] == '\n' || h.src[end-1] == '\r') {
			end--
		}
		if end > start {
			comments = append(comments, Span{Start: start, End: end, Category: Comment})
		}
	}

	lexemes := h.resolve(toks, comments, limit)
	return h.classify(lexemes, comments), nil
}

// resolve computes byte ranges for tokens. Each start is derived from the
// previous token's end by skipping whitespace and comments, so classification
// depends only on token end locations and the captured comments.
func (h *classifier) resolve(toks []models.TokenWithSpan, comments []Span, limit int) []lexeme {
	out := make([]lexeme, 0, len(toks))
	cursor, ci := 0, 0
	for _, tok := range toks {
		if tok.Token.Type == models.TokenTypeEOF {
			continue
		}
		end, ok := h.offset(tok.End, limit)
		if !ok || end <= cursor {
			continue
		}
		start := cursor
		for ci < len(comments) && comments[ci].Start < end {
			if comments[ci].End > start {
				start = comments[ci].End
			}
			ci++
		}
		for start < end && isSpace(h.src[start]) {
			start++
		}
		if start >= end {
			cursor = end
			continue
		}
		out = append(out, lexeme{start: start, end: end, typ: tok.Token.Type, value: tok.Token.Value})
		cursor = end
	}
	return out
}

// offset converts a tokenizer location to a byte offset. Tokenizer columns
// are 1-based and count bytes, a tab included. Locations that do not fall on
// their line (column 0, or past the line's end) are rejected.
func (h *classifier) offset(loc models.Location, limit int) (int, bool) {
	if loc.Line < 1 || loc.Line > len(h.lineStarts) || loc.Column < 1 {
		return 0, false
	}
	off := h.lineStarts[loc.Line-1] + loc.Column - 1
	if loc.Line < len(h.lineStarts) && off >= h.lineStarts[loc.Line] {
		return 0, false
	}
	if off > limit {
		return 0, false
	}
	return off, true
}

// errorOffset returns the byte offset where the lexical error err begins
// within src[:limit]. It reports false for errors that are not lexical
// (input or token limits, recovered panics).
//
// Tokenizer error locations are not always usable: some unterminated-literal
// errors report column 0 or the end of input instead of the opening
// delimiter. The location is therefore validated, and when it does not point
// at a plausible opener the offset is recovered by scanning for the last
// unclosed string, quoted identifier or comment.
func (h *classifier) errorOffset(err error, limit int) (int, bool) {
	var loc models.Location
	var code sqlerrors.ErrorCode
	var se *sqlerrors.Error
	var te *models.TokenizerError
	switch {
	case goerrors.As(err, &se):
		loc, code = se.Location, se.Code
	case goerrors.As(err, &te):
		loc = te.Location
	default:
		return 0, false
	}
	switch code {
	case sqlerrors.ErrCodeInputTooLarge, sqlerrors.ErrCodeTokenLimitReached, sqlerrors.ErrCodeTokenizerPanic:
		return 0, false
	}

	off, ok := h.offset(loc, limit)
	ok = ok && off < limit
	unterminated := code == sqlerrors.ErrCodeUnterminatedString ||
		code == sqlerrors.ErrCodeUnterminatedBlockComment ||
		strings.Contains(err.Error(), "unterminated")
	if ok && (!unterminated || h.isOpener(off, limit)) {
		return off, true
	}
	if u := h.lastUnclosed(limit); u >= 0 {
		return u, true
	}
	if ok {
		return off, true
	}
	return 0, true
}

// isOpener reports whether src[off:] starts a string, quoted identifier or
// block comment (optionally behind a literal prefix such as N, E, X or U&).
func (h *classifier) isOpener(off, limit int) bool {
	s := h.src[off:limit]
	if strings.HasPrefix(s, "/*") {
		return true
	}
	for i := 0; i < len(s) && i < 3; i++ {
		switch s[i] {
		case '\'', '"', '`', '$', '[':
			return true
		}
		if !isWordStart(s[i]) && s[i] != '&' {
			return false
		}
	}
	return false
}

// lastUnclosed scans src[:limit] and returns the offset of an opening quote,
// dollar-quote tag or block-comment delimiter that is never closed, or -1.
// It is only used to recover error positions, so it mirrors the tokenizer's
// rules closely but not exhaustively.
func (h *classifier) lastUnclosed(limit int) int {
	s := h.src[:limit]
	backslash := h.doubleQuotedIsString() // MySQL-family and BigQuery escape with '\'
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && strings.HasPrefix(s[i:], "--"):
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return -1
			}
			i += j + 1
		case c == '/' && strings.HasPrefix(s[i:], "/*"):
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return i
			}
			i += 2 + j + 2
		case c == '\'' || c == '"' || c == '`' || (c == '[' && h.dialect == keywords.DialectSQLServer):
			closer := c
			if c == '[' {
				closer = ']'
			}
			j := i + 1
			for {
				if j >= len(s) {
					return i
				}
				switch {
				case backslash && s[j] == '\\':
					j += 2
					continue
				case s[j] == '\n' && c == '"' && !backslash:
					return i // quoted identifiers cannot span lines
				case s[j] == closer:
					if j+1 < len(s) && s[j+1] == closer && closer != ']' {
						j += 2 // doubled quote escape
						continue
					}
				default:
					j++
					continue
				}
				break
			}
			i = j + 1
		case c == '$':
			j := i + 1
			for j < len(s) && (isWordStart(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j < len(s) && s[j] == '$' && (j == i+1 || !(s[i+1] >= '0' && s[i+1] <= '9')) {
				tag := s[i : j+1]
				k := strings.Index(s[j+1:], tag)
				if k < 0 {
					return i
				}
				i = j + 1 + k + len(tag)
			} else {
				i = j
			}
		default:
			i++
		}
	}
	return -1
}

// classify assigns categories to lexemes and merges in comment spans.
func (h *classifier) classify(ls []lexeme, comments []Span) []Span {
	out := make([]Span, 0, len(ls)+len(comments)+1)
	ci := 0
	emit := func(s Span) {
		for ci < len(comments) && comments[ci].Start < s.Start {
			out = append(out, comments[ci])
			ci++
		}
		out = append(out, s)
	}

	st := state{}
	for i := 0; i < len(ls); i++ {
		cat, consumed := h.category(ls, i, &st)
		span := Span{Start: ls[i].start, End: ls[i+consumed].end, Category: cat}
		st.observe(ls, i, cat)
		i += consumed
		if cat != Plain {
			emit(span)
		}
	}
	return append(out, comments[ci:]...)
}

// state carries left-to-right context used by the classification heuristics.
type state struct {
	parens  []string // uppercased word that opened each enclosing paren ("" if none)
	ddl     bool     // inside CREATE/ALTER/DECLARE until the next semicolon
	prevCat Category // category of the previous lexeme
}

func (st *state) top() string {
	if len(st.parens) == 0 {
		return ""
	}
	return st.parens[len(st.parens)-1]
}

func (st *state) observe(ls []lexeme, i int, cat Category) {
	l := ls[i]
	switch l.typ {
	case models.TokenTypeLParen:
		opener := ""
		if i > 0 {
			opener = upper(ls[i-1].value)
		}
		st.parens = append(st.parens, opener)
	case models.TokenTypeRParen:
		if len(st.parens) > 0 {
			st.parens = st.parens[:len(st.parens)-1]
		}
	case models.TokenTypeSemicolon:
		st.ddl = false
		st.parens = st.parens[:0]
	}
	if cat == Keyword {
		switch upper(l.value) {
		case "CREATE", "ALTER", "DECLARE":
			st.ddl = true
		}
	}
	st.prevCat = cat
}

// category classifies ls[i] and reports how many following lexemes it
// absorbed (for prefixed strings, hex literals and named parameters).
func (h *classifier) category(ls []lexeme, i int, st *state) (Category, int) {
	l := ls[i]
	var prev, next *lexeme
	if i > 0 {
		prev = &ls[i-1]
	}
	if i+1 < len(ls) {
		next = &ls[i+1]
	}
	adjNext := next != nil && next.start == l.end

	switch typ := l.typ; {
	case typ == models.TokenTypeNumber:
		// 0x1F and 0b101 tokenize as NUMBER "0" + IDENTIFIER "x1F".
		if adjNext && l.value == "0" && isWordType(next.typ) && isRadixSuffix(next.value) {
			return Number, 1
		}
		return Number, 0

	case typ >= models.TokenRangeStringStart && typ < models.TokenRangeStringEnd:
		if h.src[l.start] == '"' && !h.doubleQuotedIsString() {
			return QuotedIdentifier, 0
		}
		return String, 0

	case typ == models.TokenTypeTrue, typ == models.TokenTypeFalse, typ == models.TokenTypeNull:
		if isQualified(prev, next, l) {
			return Identifier, 0
		}
		return Constant, 0

	case typ == models.TokenTypePlaceholder, typ == models.TokenTypeQuestion:
		return Placeholder, 0

	case typ == models.TokenTypeColon:
		// :name / :1 named or positional parameter, but not a[1:2] slices or
		// Snowflake col:path access.
		if adjNext && (isWordType(next.typ) || next.typ == models.TokenTypeNumber) && !isOperand(prev) {
			return Placeholder, 1
		}
		return Operator, 0

	case typ == models.TokenTypeAtAt, typ == models.TokenTypeAtSign:
		if adjNext && isWordType(next.typ) {
			return Placeholder, 1
		}
		return Operator, 0

	case isPunctuation(typ):
		return Punctuation, 0

	case typ.IsOperator():
		return Operator, 0

	case isWordType(typ):
		return h.word(ls, i, prev, next, adjNext, st)

	case typ.IsDataType():
		return DataType, 0

	case typ.IsKeyword():
		if isQualified(prev, next, l) {
			return Identifier, 0
		}
		w := upper(l.value)
		if dataTypeNames[w] && h.typeContext(prev, st) {
			return DataType, 0
		}
		if next != nil && next.typ == models.TokenTypeLParen {
			if dataTypeNames[w] && st.ddl {
				return DataType, 0
			}
			if typ.IsAggregateFunction() || functionKeywords[w] || (!h.kw.IsReserved(w) && !clauseKeywords[w]) {
				return Function, 0
			}
		}
		return Keyword, 0
	}
	// Token types outside the ranges above (e.g. ILIKE, dialect operators):
	// word-like lexemes are keywords, anything else is an operator, so no
	// significant input is ever left unclassified.
	if isWordStart(h.src[l.start]) {
		if isQualified(prev, next, l) {
			return Identifier, 0
		}
		return Keyword, 0
	}
	if l.typ == models.TokenTypeEOF {
		return Plain, 0
	}
	return Operator, 0
}

func isWordStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// word classifies an IDENTIFIER/WORD lexeme.
func (h *classifier) word(ls []lexeme, i int, prev, next *lexeme, adjNext bool, st *state) (Category, int) {
	l := ls[i]
	switch h.src[l.start] {
	case '"', '`', '[':
		return QuotedIdentifier, 0
	case '@':
		return Placeholder, 0
	}

	w := upper(l.value)
	// N'..', E'..', X'..', B'..', U&'..', R'..' split into word + string.
	if adjNext && isStringType(next.typ) && stringPrefixes[w] {
		return String, 1
	}
	if isQualified(prev, next, l) {
		if next != nil && next.typ == models.TokenTypeLParen {
			return Function, 0 // schema.func(...)
		}
		return Identifier, 0
	}
	if dataTypeNames[w] && h.typeContext(prev, st) {
		return DataType, 0
	}
	if next != nil && next.typ == models.TokenTypeLParen {
		if dataTypeNames[w] && (st.ddl || dataTypeNames[st.top()]) {
			return DataType, 0
		}
		if !blocksFunction(prev) && !clauseKeywords[w] {
			return Function, 0
		}
		return Identifier, 0
	}
	if h.kw.IsKeyword(w) || extraKeywords[w] {
		return Keyword, 0
	}
	return Identifier, 0
}

// typeContext reports whether the lexeme following prev is in type position.
func (h *classifier) typeContext(prev *lexeme, st *state) bool {
	if prev == nil {
		return false
	}
	switch prev.typ {
	case models.TokenTypeDoubleColon:
		return true
	case models.TokenTypeLParen, models.TokenTypeComma:
		// Type arguments: Nullable(String), Map(String, UInt64).
		return dataTypeNames[st.top()]
	}
	if st.prevCat == DataType {
		// Multi-word types: DOUBLE PRECISION, CHARACTER VARYING,
		// TIMESTAMP WITH TIME ZONE is left to the keyword path.
		return true
	}
	pw := upper(prev.value)
	switch pw {
	case "AS":
		switch st.top() {
		case "CAST", "TRY_CAST", "SAFE_CAST", "CONVERT":
			return true
		}
		return false
	case "RETURNS", "TYPE":
		return true
	case "COLUMN", "ADD":
		return false
	}
	if !st.ddl {
		return false
	}
	// Column definitions: CREATE TABLE t (id INT, name TEXT),
	// ALTER TABLE t ADD [COLUMN] c TEXT, DECLARE @x INT.
	return st.prevCat == Identifier || st.prevCat == QuotedIdentifier || st.prevCat == Placeholder
}

func (h *classifier) doubleQuotedIsString() bool {
	switch h.dialect {
	case keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectBigQuery:
		return true
	}
	return false
}

func isWordType(t models.TokenType) bool {
	return t == models.TokenTypeIdentifier || t == models.TokenTypeWord
}

func isStringType(t models.TokenType) bool {
	return t >= models.TokenRangeStringStart && t < models.TokenRangeStringEnd
}

func isPunctuation(t models.TokenType) bool {
	switch t {
	case models.TokenTypeComma, models.TokenTypeLParen, models.TokenTypeRParen,
		models.TokenTypePeriod, models.TokenTypeSemicolon,
		models.TokenTypeLBracket, models.TokenTypeRBracket,
		models.TokenTypeLBrace, models.TokenTypeRBrace:
		return true
	}
	return false
}

// isOperand reports whether l ends a value, making a following ':' an
// operator (slice, path access) rather than a parameter sigil.
func isOperand(l *lexeme) bool {
	if l == nil {
		return false
	}
	switch l.typ {
	case models.TokenTypeNumber, models.TokenTypeIdentifier, models.TokenTypeWord,
		models.TokenTypeRParen, models.TokenTypeRBracket, models.TokenTypePlaceholder:
		return true
	}
	return isStringType(l.typ)
}

// isQualified reports whether l is part of a dotted name (a.b.c).
func isQualified(prev, next *lexeme, l lexeme) bool {
	if prev != nil && prev.typ == models.TokenTypePeriod && prev.end == l.start {
		return true
	}
	return next != nil && next.typ == models.TokenTypePeriod && next.start == l.end
}

// blocksFunction reports whether an identifier after prev followed by '('
// is a relation or index name with a column list rather than a call:
// INSERT INTO t (a), REFERENCES t (id), WITH cte (x) AS, CREATE INDEX i (c).
func blocksFunction(prev *lexeme) bool {
	if prev == nil {
		return false
	}
	switch upper(prev.value) {
	case "INTO", "TABLE", "REFERENCES", "VIEW", "EXISTS", "ON", "INDEX", "KEY",
		"WITH", "RECURSIVE", "TRIGGER", "TYPE", "CONSTRAINT":
		return true
	}
	return false
}

func isRadixSuffix(s string) bool {
	if len(s) < 2 {
		return false
	}
	switch s[0] {
	case 'x', 'X':
		for i := 1; i < len(s); i++ {
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	case 'b', 'B':
		for i := 1; i < len(s); i++ {
			if s[i] != '0' && s[i] != '1' {
				return false
			}
		}
		return true
	}
	return false
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// upper returns s in upper case; ASCII-uppercase input is returned without
// allocating.
func upper(s string) string {
	return strings.ToUpper(s)
}

// indexLines records the byte offset of each line start.
func (h *classifier) indexLines() {
	s := h.src
	h.lineStarts = make([]int, 1, strings.Count(s, "\n")+1)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			h.lineStarts = append(h.lineStarts, i+1)
		}
	}
}

var (
	kwMu    sync.Mutex
	kwCache = map[keywords.SQLDialect]*keywords.Keywords{}
)

// keywordsFor returns a shared, read-only keyword table for the dialect.
// Construction is serialized because keywords.New resets package state.
func keywordsFor(d keywords.SQLDialect) *keywords.Keywords {
	if d == "" {
		d = keywords.DialectGeneric
	}
	kwMu.Lock()
	defer kwMu.Unlock()
	if k, ok := kwCache[d]; ok {
		return k
	}
	k := keywords.New(d, true)
	kwCache[d] = k
	return k
}

// stringPrefixes are identifier fragments that, when immediately followed by
// a string literal, form a single prefixed literal.
var stringPrefixes = map[string]bool{
	"N": true, "E": true, "X": true, "B": true, "U&": true, "R": true, "U": true,
	"BR": true, "RB": true,
}

// extraKeywords supplements the parser's deliberately conservative keyword
// table with statement and clause words that are rarely used as bare
// identifiers. Words that commonly name columns (COMMENT, OWNER, SOURCE, ...)
// are intentionally absent.
var extraKeywords = map[string]bool{
	"DECLARE": true, "BEGIN": true, "COMMIT": true, "ROLLBACK": true, "TRANSACTION": true,
	"SAVEPOINT": true, "RETURNS": true, "PROCEDURE": true, "FUNCTION": true, "TRIGGER": true,
	"EXECUTE": true, "EXEC": true, "GRANT": true, "REVOKE": true, "VACUUM": true,
	"COPY": true, "SHOW": true, "USE": true, "DESCRIBE": true, "UPSERT": true,
	"CONFLICT": true, "DO": true, "NOTHING": true, "EXCLUDED": true, "LANGUAGE": true,
	"ELSIF": true, "LOOP": true, "WHILE": true, "RETURN": true, "RAISE": true,
	"SCHEMA": true, "DATABASE": true, "SEQUENCE": true, "TEMP": true, "UNLOGGED": true,
	"MATERIALIZED": true, "ILIKE": true, "SIMILAR": true, "ESCAPE": true, "COLLATE": true,
	"NULLS": true, "GENERATED": true, "ALWAYS": true, "AUTO_INCREMENT": true,
	"UNSIGNED": true, "ZEROFILL": true, "CHARSET": true, "MODIFY": true, "AFTER": true,
	"BEFORE": true, "INSTEAD": true, "EACH": true, "STATEMENT": true, "PRINT": true,
}

// clauseKeywords are keywords that are commonly followed by '(' without being
// function calls: constraints, column lists and value lists.
var clauseKeywords = map[string]bool{
	"UNIQUE": true, "DEFAULT": true, "PRIMARY": true, "FOREIGN": true, "KEY": true,
	"CHECK": true, "VALUES": true, "IN": true, "EXISTS": true, "OVER": true,
	"FILTER": true, "WITHIN": true, "USING": true, "AS": true, "ON": true,
	"PARTITION": true, "INCLUDE": true, "REFERENCES": true, "TABLE": true,
	"RETURNS": true, "LATERAL": true,
}

// functionKeywords are reserved keywords that are functions when called.
var functionKeywords = map[string]bool{
	"CAST": true, "TRY_CAST": true, "SAFE_CAST": true, "CONVERT": true,
	"COALESCE": true, "NULLIF": true, "EXTRACT": true, "SUBSTRING": true,
	"TRIM": true, "REPLACE": true, "LEFT": true, "RIGHT": true, "POSITION": true,
	"IF": true, "IFNULL": true, "ISNULL": true, "NVL": true, "GREATEST": true,
	"LEAST": true, "OVERLAY": true, "FIRST": true, "LAST": true, "CHAR": true,
	"CURRENT_DATE": true, "CURRENT_TIME": true, "CURRENT_TIMESTAMP": true,
	"ROW": true, "ARRAY": true, "MOD": true, "UPPER": true, "LOWER": true,
	"YEAR": true, "MONTH": true, "DAY": true, "HOUR": true, "MINUTE": true, "SECOND": true,
}

// dataTypeNames are type names recognised in type position across the
// supported dialects. Membership alone never makes a word a DataType; the
// surrounding context (column definition, ::, CAST ... AS) must agree.
var dataTypeNames = map[string]bool{
	// Integers and decimals
	"INT": true, "INTEGER": true, "SMALLINT": true, "BIGINT": true, "TINYINT": true,
	"MEDIUMINT": true, "INT2": true, "INT4": true, "INT8": true, "INT16": true,
	"INT32": true, "INT64": true, "INT128": true, "INT256": true,
	"UINT8": true, "UINT16": true, "UINT32": true, "UINT64": true, "UINT128": true, "UINT256": true,
	"DECIMAL": true, "DEC": true, "NUMERIC": true, "NUMBER": true, "BIGNUMERIC": true,
	"DECIMAL32": true, "DECIMAL64": true, "DECIMAL128": true, "DECIMAL256": true,
	"MONEY": true, "SMALLMONEY": true, "SERIAL": true, "SMALLSERIAL": true, "BIGSERIAL": true,
	// Floating point
	"FLOAT": true, "FLOAT4": true, "FLOAT8": true, "FLOAT32": true, "FLOAT64": true,
	"REAL": true, "DOUBLE": true, "PRECISION": true, "BINARY_FLOAT": true, "BINARY_DOUBLE": true,
	// Boolean and bits
	"BOOLEAN": true, "BOOL": true, "BIT": true, "VARBIT": true,
	// Character
	"CHAR": true, "CHARACTER": true, "VARYING": true, "VARCHAR": true, "VARCHAR2": true,
	"NCHAR": true, "NVARCHAR": true, "NVARCHAR2": true, "TEXT": true, "TINYTEXT": true,
	"MEDIUMTEXT": true, "LONGTEXT": true, "NTEXT": true, "CLOB": true, "NCLOB": true,
	"STRING": true, "FIXEDSTRING": true, "CITEXT": true,
	// Binary
	"BLOB": true, "TINYBLOB": true, "MEDIUMBLOB": true, "LONGBLOB": true, "BYTEA": true,
	"BINARY": true, "VARBINARY": true, "IMAGE": true, "BYTES": true, "RAW": true,
	// Temporal
	"DATE": true, "DATE32": true, "TIME": true, "TIMETZ": true, "TIMESTAMP": true,
	"TIMESTAMPTZ": true, "TIMESTAMP_NTZ": true, "TIMESTAMP_LTZ": true, "TIMESTAMP_TZ": true,
	"DATETIME": true, "DATETIME2": true, "DATETIME64": true, "DATETIMEOFFSET": true,
	"SMALLDATETIME": true, "INTERVAL": true, "YEAR": true,
	// Structured and other
	"UUID": true, "UNIQUEIDENTIFIER": true, "JSON": true, "JSONB": true, "XML": true,
	"VARIANT": true, "OBJECT": true, "ARRAY": true, "MAP": true, "TUPLE": true, "STRUCT": true,
	"NULLABLE": true, "LOWCARDINALITY": true, "NESTED": true, "ENUM": true,
	"GEOGRAPHY": true, "GEOMETRY": true, "INET": true, "CIDR": true, "MACADDR": true,
	"TSVECTOR": true, "TSQUERY": true, "IPV4": true, "IPV6": true,
	"ROWID": true, "UROWID": true, "ROWVERSION": true, "SQL_VARIANT": true, "HIERARCHYID": true,
}
