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

package gosqlx

import "strings"

// This file holds the procedural-script half of SplitStatements: block
// nesting (BEGIN … END and friends) and the client-tool batch separators
// (T-SQL GO, MySQL DELIMITER, SQL*Plus "/"). The state machine in splitter.go
// calls into it once per identifier-like word, so everything here is
// allocation-free.

// Word kinds the block tracker cares about.
const (
	kwOther uint8 = iota
	kwBegin
	kwEnd
	kwCase
	kwIf
	kwLoop
	kwWhile
	kwFor
	kwRepeat
	kwThen
	kwElse
	kwDo
	kwDeclare
	kwCreate
	kwRoutine // PROCEDURE, FUNCTION, PACKAGE
	kwTrigger
	kwIsAs
)

// procState tracks BEGIN/CASE/IF/LOOP nesting for one split. depth is the
// number of open blocks; declMask marks (for levels 1..64) the Oracle
// declaration sections that are still waiting for their BEGIN.
type procState struct {
	on, tsql, oracle bool
	depth            int
	declMask         uint64
	// stmtStart is true while the next word begins a statement (after ';',
	// BEGIN, THEN, ELSE, LOOP, a label, …). IF/WHILE/FOR/REPEAT only open a
	// block there, which keeps "DROP TABLE IF EXISTS" and IF() calls out.
	stmtStart  bool
	loopHeader bool // WHILE/FOR seen, its LOOP/DO opener not yet
	createN    int  // >0 while within the first words of an Oracle CREATE
	routineHdr bool // Oracle PROCEDURE/FUNCTION/PACKAGE header awaiting IS/AS
	trigHdr    bool // inside an Oracle CREATE TRIGGER header (DECLARE may follow)
}

func (s *procState) init(p dialectProfile) {
	s.on = !p.noBlocks
	s.tsql = p.tsql
	s.oracle = p.oracle
	s.stmtStart = true
}

// reset discards any open block (a batch separator ends them all).
func (s *procState) reset() {
	*s = procState{on: s.on, tsql: s.tsql, oracle: s.oracle, stmtStart: true}
}

func (s *procState) semicolon() {
	s.stmtStart = true
	s.routineHdr = false
	s.loopHeader = false
	if s.depth == 0 {
		s.createN = 0
		s.trigHdr = false
	}
}

func (s *procState) push(decl bool) {
	s.depth++
	if decl && s.depth <= 64 {
		s.declMask |= 1 << uint(s.depth-1)
	}
}

func (s *procState) pop() {
	if s.depth == 0 {
		return
	}
	if s.depth <= 64 {
		s.declMask &^= 1 << uint(s.depth-1)
	}
	s.depth--
}

// absorbBegin consumes the BEGIN that follows an Oracle declaration section:
// the section and its body are one level.
func (s *procState) absorbBegin() bool {
	if s.depth == 0 || s.depth > 64 {
		return false
	}
	bit := uint64(1) << uint(s.depth-1)
	if s.declMask&bit == 0 {
		return false
	}
	s.declMask &^= bit
	return true
}

// punct handles the few non-word tokens that start a statement: a label's
// ':' (MySQL) and the closing '>>' of a <<label>> (PL/SQL, PL/pgSQL).
func (s *procState) punct(src string, i int) {
	if s.depth == 0 {
		return
	}
	switch src[i] {
	case ':':
		if i+1 < len(src) && (src[i+1] == ':' || src[i+1] == '=') {
			return
		}
		if i > 0 && src[i-1] == ':' {
			return
		}
		s.stmtStart = true
	case '>':
		if i > 0 && src[i-1] == '>' {
			s.stmtStart = true
		}
	}
}

// word processes the identifier-like word src[i:j] and returns the index
// scanning should resume at (j, or later when a trailing END keyword was
// consumed together with it).
func (s *procState) word(src string, i, j int) int {
	k := procKind(src[i:j])
	was := s.stmtStart
	s.stmtStart = false
	if s.createN > 0 && k != kwCreate {
		s.createN++
		if s.createN > 6 {
			s.createN = 0
		}
	}
	switch k {
	case kwBegin:
		s.routineHdr = false
		s.createN = 0
		s.trigHdr = false
		if s.absorbBegin() {
			s.stmtStart = true
			return j
		}
		if beginNamesColumn(src, i) || !beginIsBlock(src, j) {
			return j
		}
		s.push(false)
		s.stmtStart = true

	case kwEnd:
		s.pop()
		w, _, end := peekWord(src, j)
		var b [12]byte
		switch string(foldWord(&b, w)) {
		case "try", "catch":
			return end
		case "if", "loop", "while", "repeat", "case", "for":
			if !s.tsql {
				return end
			}
		}

	case kwCase:
		if s.depth > 0 {
			s.push(false)
		}

	case kwIf:
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
		}

	case kwWhile, kwFor:
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
			s.loopHeader = true
		}

	case kwRepeat:
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
			s.stmtStart = true
		}

	case kwLoop:
		if s.depth > 0 && !s.tsql {
			if s.loopHeader {
				s.loopHeader = false
			} else {
				s.push(false)
			}
			s.stmtStart = true
		}

	case kwDo:
		s.loopHeader = false
		s.stmtStart = true

	case kwThen, kwElse:
		s.stmtStart = true

	case kwDeclare:
		if s.oracle && (was || s.trigHdr) {
			s.routineHdr = false
			s.createN = 0
			s.trigHdr = false
			s.push(true)
			s.stmtStart = true
		}

	case kwCreate:
		if s.oracle && was && s.depth == 0 {
			s.createN = 1
		}

	case kwTrigger:
		if s.oracle && s.createN > 0 {
			s.trigHdr = true
		}
		s.createN = 0

	case kwRoutine:
		if s.oracle {
			if s.createN > 0 {
				s.routineHdr = true
				s.createN = 0
			} else if s.depth > 0 && was {
				s.routineHdr = true
			}
		}

	case kwIsAs:
		if s.oracle && s.routineHdr {
			s.routineHdr = false
			w, _, _ := peekWord(src, j)
			var b [12]byte
			switch string(foldWord(&b, w)) {
			case "language", "external":
				// Call specification: no PL/SQL body follows.
			default:
				s.push(true)
				s.stmtStart = true
			}
		}
	}
	return j
}

// procKind classifies a word case-insensitively without allocating.
func procKind(w string) uint8 {
	if len(w) < 2 || len(w) > 9 {
		return kwOther
	}
	var b [12]byte
	switch string(foldWord(&b, w)) {
	case "begin":
		return kwBegin
	case "end":
		return kwEnd
	case "case":
		return kwCase
	case "if":
		return kwIf
	case "loop":
		return kwLoop
	case "while":
		return kwWhile
	case "for":
		return kwFor
	case "repeat":
		return kwRepeat
	case "then":
		return kwThen
	case "else":
		return kwElse
	case "do":
		return kwDo
	case "declare":
		return kwDeclare
	case "create":
		return kwCreate
	case "procedure", "function", "package":
		return kwRoutine
	case "trigger":
		return kwTrigger
	case "is", "as":
		return kwIsAs
	}
	return kwOther
}

// foldWord lower-cases an ASCII word into buf. Words longer than the buffer
// come back empty (they match no keyword).
func foldWord(buf *[12]byte, w string) []byte {
	if len(w) > len(buf) {
		return nil
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return buf[:len(w)]
}

// beginIsBlock reports whether the BEGIN ending at j opens a block rather
// than starting a transaction (BEGIN; BEGIN TRANSACTION; BEGIN IMMEDIATE …)
// or being a column or alias that happens to be called begin.
func beginIsBlock(src string, j int) bool {
	w, _, end := peekWord(src, j)
	if w == "" {
		return false
	}
	var b [12]byte
	switch string(foldWord(&b, w)) {
	case "transaction", "tran", "work", "deferred", "immediate", "exclusive",
		"isolation", "read", "distributed", "deferrable", "from", "as", "and",
		"or", "in", "is", "where", "on", "using", "asc", "desc", "limit",
		"offset", "group", "order", "having", "union", "intersect", "except",
		"join", "inner", "left", "right", "outer", "cross", "natural",
		"between", "like", "ilike", "then", "when", "else", "collate", "over",
		"isnull", "notnull", "to", "by":
		return false
	case "not":
		// BEGIN NOT ATOMIC (MariaDB) is a block; BEGIN NOT DEFERRABLE (PG)
		// is a transaction.
		w2, _, _ := peekWord(src, end)
		var b2 [12]byte
		return string(foldWord(&b2, w2)) == "atomic"
	}
	return true
}

// beginNamesColumn reports whether the BEGIN starting at i is a column name
// rather than a block opener because of what precedes it: a column list
// ("(begin INT", ", begin DATE") or an ALTER TABLE column clause ("ADD
// COLUMN begin INT", "MODIFY begin TIME"). Treating such a BEGIN as a block
// would merge the following statements up to the next unrelated END.
func beginNamesColumn(src string, i int) bool {
	k := i
	for k > 0 && (src[k-1] == ' ' || src[k-1] == '\t' || src[k-1] == '\n' || src[k-1] == '\r') {
		k--
	}
	if k == 0 {
		return false
	}
	if c := src[k-1]; c == ',' || c == '(' {
		return true
	}
	e := k
	for k > 0 && isWordByte(src[k-1]) {
		k--
	}
	var b [12]byte
	switch string(foldWord(&b, src[k:e])) {
	case "column", "add", "modify", "change", "alter", "drop", "rename":
		return true
	}
	return false
}

// peekWord skips whitespace and comments from j and returns the word that
// follows (empty when the next token is not a word), the byte found there
// (0 at end of input) and the index just past the word.
func peekWord(src string, j int) (w string, c byte, end int) {
	for j < len(src) {
		c = src[j]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			j++
			continue
		case c == '-' && j+1 < len(src) && src[j+1] == '-':
			for j < len(src) && src[j] != '\n' {
				j++
			}
			continue
		case c == '/' && j+1 < len(src) && src[j+1] == '*':
			e := strings.Index(src[j+2:], "*/")
			if e < 0 {
				return "", 0, len(src)
			}
			j += e + 4
			continue
		}
		if isWordByte(c) {
			k := j + 1
			for k < len(src) && isWordByte(src[k]) {
				k++
			}
			return src[j:k], c, k
		}
		return "", c, j
	}
	return "", 0, j
}

// commentsOnly reports whether seg holds nothing but whitespace and comments.
func commentsOnly(seg string) bool {
	_, c, end := peekWord(seg, 0)
	return c == 0 && end >= len(seg)
}

// isWordByte reports whether c can be part of an identifier-like word.
func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' ||
		c >= 'A' && c <= 'Z' || c >= 0x80
}

// prevIsQualifier reports whether the byte before i marks the word at i as
// part of a qualified name, variable or temp-table name (x.end, @begin,
// #case), which is never a keyword.
func prevIsQualifier(src string, i int) bool {
	if i == 0 {
		return false
	}
	switch src[i-1] {
	case '.', '@', '#', '$':
		return true
	}
	return false
}

func asciiFold(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// equalFoldASCII compares s with the lower-case ASCII word lower.
func equalFoldASCII(s, lower string) bool {
	if len(s) != len(lower) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if asciiFold(s[i]) != lower[i] {
			return false
		}
	}
	return true
}

// lineStartOK reports whether only blanks precede index i on its line, and
// returns the index where that line starts.
func lineStartOK(src string, i int) (ls int, ok bool) {
	ls = i
	for ls > 0 {
		c := src[ls-1]
		if c == '\n' {
			return ls, true
		}
		if c != ' ' && c != '\t' && c != '\r' {
			// A byte order mark in front of the first line is not content.
			if ls == 3 && src[:3] == "\xef\xbb\xbf" {
				return 0, true
			}
			return 0, false
		}
		ls--
	}
	return 0, true
}

// skipBlanks advances over spaces, tabs and carriage returns.
func skipBlanks(src string, j int) int {
	for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r') {
		j++
	}
	return j
}

// afterLine returns the index just past the line break at j (or len(src))
// and whether j is at a line end.
func afterLine(src string, j int) (int, bool) {
	if j >= len(src) {
		return len(src), true
	}
	if src[j] == '\n' {
		return j + 1, true
	}
	return 0, false
}

// lineOnly reports whether src[i:j] is the only thing on its line. It
// returns the line start and the index just past the line break.
func lineOnly(src string, i, j int) (ls, le int, ok bool) {
	ls, ok = lineStartOK(src, i)
	if !ok {
		return 0, 0, false
	}
	le, ok = afterLine(src, skipBlanks(src, j))
	if !ok {
		return 0, 0, false
	}
	return ls, le, true
}

// goLine recognises a T-SQL batch separator: the word GO at src[i:j], alone
// on its line, optionally followed by a repeat count and a -- comment.
func goLine(src string, i, j int) (ls, le int, ok bool) {
	ls, ok = lineStartOK(src, i)
	if !ok {
		return 0, 0, false
	}
	k := skipBlanks(src, j)
	for k < len(src) && src[k] >= '0' && src[k] <= '9' {
		k++
	}
	k = skipBlanks(src, k)
	if k+1 < len(src) && src[k] == '-' && src[k+1] == '-' {
		for k < len(src) && src[k] != '\n' {
			k++
		}
	}
	le, ok = afterLine(src, k)
	if !ok {
		return 0, 0, false
	}
	return ls, le, true
}

// delimiterLine recognises the mysql client's "DELIMITER <token>" directive
// at src[i:j] and returns the new delimiter ("" for the default ';').
func delimiterLine(src string, i, j int) (ls, le int, delim string, ok bool) {
	ls, ok = lineStartOK(src, i)
	if !ok || j >= len(src) || (src[j] != ' ' && src[j] != '\t') {
		return 0, 0, "", false
	}
	k := skipBlanks(src, j)
	e := k
	for e < len(src) && src[e] != ' ' && src[e] != '\t' && src[e] != '\r' && src[e] != '\n' {
		e++
	}
	if e == k {
		return 0, 0, "", false
	}
	tok := src[k:e]
	le, ok = afterLine(src, skipBlanks(src, e))
	if !ok {
		// Trailing text after the token: ignore it like the client does.
		for e < len(src) && src[e] != '\n' {
			e++
		}
		le, _ = afterLine(src, e)
	}
	if tok == ";" {
		tok = ""
	}
	return ls, le, tok, true
}

// appendNonBlank appends seg unless it is empty or whitespace-only.
func appendNonBlank(out []string, seg string) []string {
	for i := 0; i < len(seg); i++ {
		switch seg[i] {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			continue
		}
		return append(out, seg)
	}
	return out
}
