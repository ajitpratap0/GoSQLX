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

// statement_blocks.go keeps compound statements whole. A routine or trigger
// body (BEGIN ... END), a PL/SQL anonymous block (DECLARE ... BEGIN ... END)
// or a T-SQL control-flow block contains ';' that do not end the statement.
// blockScan tracks BEGIN / CASE / IF / LOOP ... END nesting over the tokens
// of a statement kept verbatim, following the same rules as the block
// tracker of gosqlx.SplitStatements (pkg/gosqlx/splitter_proc.go), so that
// every piece the splitter returns parses as exactly one statement.

package parser

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// blockScan is the nesting state of one statement. depth counts open
// blocks; declMask marks (for levels 1..64) the Oracle declaration
// sections still waiting for their BEGIN.
type blockScan struct {
	tsql, oracle bool
	depth        int
	declMask     uint64
	// stmtStart is true while the next word begins a statement (after ';',
	// BEGIN, THEN, ELSE, LOOP, a label, ...). IF / WHILE / FOR / REPEAT only
	// open a block there, which keeps "DROP TABLE IF EXISTS" and IF() out.
	stmtStart  bool
	loopHeader bool // WHILE / FOR seen, its LOOP / DO opener not yet
	createN    int  // >0 while within the first words of an Oracle CREATE
	routineHdr bool // Oracle PROCEDURE / FUNCTION / PACKAGE header awaiting IS / AS
	trigHdr    bool // inside an Oracle CREATE TRIGGER header (DECLARE may follow)
	// closed is set when a block closes at the top level and cleared by a
	// top-level ELSE: a T-SQL IF / WHILE / BEGIN statement may end there.
	closed bool
}

func (p *Parser) newBlockScan() blockScan {
	return blockScan{tsql: p.IsSQLServer(), oracle: p.IsOracle(), stmtStart: true}
}

func (s *blockScan) push(decl bool) {
	s.depth++
	if decl && s.depth <= 64 {
		s.declMask |= 1 << uint(s.depth-1)
	}
}

func (s *blockScan) pop() {
	if s.depth == 0 {
		return
	}
	if s.depth <= 64 {
		s.declMask &^= 1 << uint(s.depth-1)
	}
	s.depth--
	if s.depth == 0 {
		s.closed = true
	}
}

// absorbBegin consumes the BEGIN that follows an Oracle declaration
// section: the section and its body are one level.
func (s *blockScan) absorbBegin() bool {
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

func (s *blockScan) semicolon() {
	s.stmtStart = true
	s.routineHdr = false
	s.loopHeader = false
	if s.depth == 0 {
		s.createN = 0
		s.trigHdr = false
	}
}

// token processes the token at index i and returns the index of the last
// token it consumed (i, or i+1 when END took its trailing keyword).
func (s *blockScan) token(p *Parser, i int) int {
	tok := &p.tokens[i]
	switch tok.Token.Type {
	case models.TokenTypeSemicolon:
		s.semicolon()
		return i
	case models.TokenTypeColon:
		// A label (lbl: LOOP) starts a statement inside a block.
		if s.depth > 0 {
			s.stmtStart = true
		}
		return i
	case models.TokenTypeShiftRight:
		// The closing >> of a <<label>>.
		if s.depth > 0 {
			s.stmtStart = true
		}
		return i
	}
	w := p.utilityWord(i)
	if w == "" {
		s.stmtStart = false
		return i
	}
	if i > 0 && p.tokens[i-1].Token.Type == models.TokenTypePeriod {
		// t.end, x.begin: a name, never a keyword.
		s.stmtStart = false
		return i
	}
	was := s.stmtStart
	s.stmtStart = false
	if s.createN > 0 && w != "CREATE" {
		s.createN++
		if s.createN > 6 {
			s.createN = 0
		}
	}
	switch w {
	case "BEGIN":
		s.routineHdr = false
		s.createN = 0
		s.trigHdr = false
		if s.absorbBegin() {
			s.stmtStart = true
			return i
		}
		if p.beginNamesColumnAt(i) || !p.beginOpensBlockAt(i) {
			return i
		}
		s.push(false)
		s.stmtStart = true
	case "END":
		s.pop()
		switch p.utilityWord(i + 1) {
		case "TRY", "CATCH":
			return i + 1
		case "IF", "LOOP", "WHILE", "REPEAT", "CASE", "FOR":
			if !s.tsql {
				return i + 1
			}
		}
	case "CASE":
		if s.depth > 0 {
			s.push(false)
		}
	case "IF":
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
		}
	case "WHILE", "FOR":
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
			s.loopHeader = true
		}
	case "REPEAT":
		if was && s.depth > 0 && !s.tsql {
			s.push(false)
			s.stmtStart = true
		}
	case "LOOP":
		if s.depth > 0 && !s.tsql {
			if s.loopHeader {
				s.loopHeader = false
			} else {
				s.push(false)
			}
			s.stmtStart = true
		}
	case "DO":
		s.loopHeader = false
		s.stmtStart = true
	case "THEN":
		s.stmtStart = true
	case "ELSE":
		s.stmtStart = true
		if s.depth == 0 {
			s.closed = false
		}
	case "DECLARE":
		if s.oracle && (was || s.trigHdr) {
			s.routineHdr = false
			s.createN = 0
			s.trigHdr = false
			s.push(true)
			s.stmtStart = true
		}
	case "CREATE":
		if s.oracle && was && s.depth == 0 {
			s.createN = 1
		}
	case "TRIGGER":
		if s.oracle && s.createN > 0 {
			s.trigHdr = true
		}
		s.createN = 0
	case "PROCEDURE", "FUNCTION", "PACKAGE":
		if s.oracle {
			if s.createN > 0 {
				s.routineHdr = true
				s.createN = 0
			} else if s.depth > 0 && was {
				s.routineHdr = true
			}
		}
	case "IS", "AS":
		if s.oracle && s.routineHdr {
			s.routineHdr = false
			switch p.utilityWord(i + 1) {
			case "LANGUAGE", "EXTERNAL":
				// Call specification: no PL/SQL body follows.
			default:
				s.push(true)
				s.stmtStart = true
			}
		}
	}
	return i
}

// beginOpensBlockAt reports whether the BEGIN at index i opens a block
// rather than starting a transaction (BEGIN; BEGIN TRANSACTION; BEGIN
// IMMEDIATE ...) or being a column or alias that happens to be called begin.
// It mirrors beginIsBlock in pkg/gosqlx/splitter_proc.go.
func (p *Parser) beginOpensBlockAt(i int) bool {
	next := p.utilityWord(i + 1)
	if next == "" {
		// BEGIN :NEW.x := ..., BEGIN <<label>>, BEGIN "x" := ...
		if i+1 >= len(p.tokens) {
			return false
		}
		t := &p.tokens[i+1]
		switch t.Token.Type {
		case models.TokenTypeShiftLeft, models.TokenTypeDoubleQuotedString:
			return true
		case models.TokenTypePlaceholder:
			return len(t.Token.Value) > 0 && t.Token.Value[0] == ':'
		}
		return false
	}
	switch next {
	case "TRANSACTION", "TRAN", "WORK", "DEFERRED", "IMMEDIATE", "EXCLUSIVE",
		"ISOLATION", "READ", "DISTRIBUTED", "DEFERRABLE", "FROM", "AS", "AND",
		"OR", "IN", "IS", "WHERE", "ON", "USING", "ASC", "DESC", "LIMIT",
		"OFFSET", "GROUP", "ORDER", "HAVING", "UNION", "INTERSECT", "EXCEPT",
		"JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "CROSS", "NATURAL",
		"BETWEEN", "LIKE", "ILIKE", "THEN", "WHEN", "ELSE", "COLLATE", "OVER",
		"ISNULL", "NOTNULL", "TO", "BY":
		return false
	case "NOT":
		// BEGIN NOT ATOMIC (MariaDB) is a block; BEGIN NOT DEFERRABLE (PG)
		// is a transaction.
		return p.utilityWord(i+2) == "ATOMIC"
	}
	return true
}

// beginNamesColumnAt reports whether the BEGIN at index i is a column name
// rather than a block opener because of what precedes it: a column list
// ("(begin INT", ", begin DATE") or an ALTER TABLE column clause.
func (p *Parser) beginNamesColumnAt(i int) bool {
	if i == 0 {
		return false
	}
	switch p.tokens[i-1].Token.Type {
	case models.TokenTypeComma, models.TokenTypeLParen:
		return true
	}
	switch p.utilityWord(i - 1) {
	case "COLUMN", "ADD", "MODIFY", "CHANGE", "ALTER", "DROP", "RENAME":
		return true
	}
	return false
}
