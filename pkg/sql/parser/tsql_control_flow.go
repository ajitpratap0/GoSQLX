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

// tsql_control_flow.go finds where a T-SQL IF or WHILE statement ends. Its
// body is a single statement (or a BEGIN ... END block), and in scripts
// written without semicolons the statement after the body follows directly:
//
//	IF OBJECT_ID(N'dbo.t') IS NOT NULL DROP TABLE dbo.t
//	CREATE TABLE dbo.t (a INT)
//
// The body statements are parsed to find their end; the IF / WHILE itself is
// kept verbatim as a UtilityStatement, as before.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseTSQLConditional parses a T-SQL IF cond stmt [[;] ELSE stmt] or
// WHILE cond stmt starting at the current token. When the condition or a
// body cannot be delimited by parsing, it falls back to the verbatim scan of
// parseVerbatimArgs, which runs to the next ';' (or the end of a top-level
// BEGIN ... END body).
func (p *Parser) parseTSQLConditional(kind string) (ast.Statement, bool, error) {
	if err := p.enterRecursion(); err != nil {
		p.leaveRecursion()
		return nil, true, err
	}
	defer p.leaveRecursion()

	start := p.currentPos
	pos := p.currentLocation()
	saved := p.snapshotState()
	end, ok := p.tsqlConditionalEnd(start, kind == "IF")
	if !ok {
		p.restoreState(saved)
		p.seek(start)
		return p.parseVerbatimArgs(kind)
	}
	text := p.renderTokenRange(start, end)
	p.restoreState(saved)
	p.seek(end)
	return &ast.UtilityStatement{Kind: kind, Text: text, Pos: pos}, true, nil
}

// tsqlConditionalEnd returns the index of the token after the IF / WHILE
// statement that begins at start.
func (p *Parser) tsqlConditionalEnd(start int, isIf bool) (int, bool) {
	body, ok := p.tsqlConditionEnd(start)
	if !ok {
		return 0, false
	}
	end, ok := p.tsqlBodyEnd(body, isIf)
	if !ok || !isIf {
		return end, ok
	}
	// IF cond stmt; ELSE stmt: a ';' may close the first branch.
	j := end
	if j < len(p.tokens) && p.tokens[j].Token.Type == models.TokenTypeSemicolon &&
		p.utilityWord(j+1) == "ELSE" {
		j++
	}
	if p.utilityWord(j) != "ELSE" {
		return end, true
	}
	return p.tsqlBodyEnd(j+1, false)
}

// tsqlConditionEnd returns the index of the first token of the body of the
// IF / WHILE at start: the first word outside parentheses that starts a
// statement. The condition never ends at ';' or the end of the input.
func (p *Parser) tsqlConditionEnd(start int) (int, bool) {
	depth := 0
	for i := start + 1; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
			continue
		case models.TokenTypeRParen:
			depth--
			if depth < 0 {
				return 0, false
			}
			continue
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return 0, false
		}
		if depth != 0 {
			continue
		}
		if _, ok := p.batchSeparatorEnd(i); ok {
			return 0, false
		}
		if i > start+1 && p.startsNewStatement(i, start) {
			return i, true
		}
	}
	return 0, false
}

// tsqlBodyEnd parses the body statement starting at index i and returns
// the index of the token after it. The body must be followed by the end of
// the input, a ';', a GO line, ELSE (when elseOK) or the start of another
// statement; anything else means the parser read the body differently from
// SQL Server, and the caller falls back to the verbatim scan.
func (p *Parser) tsqlBodyEnd(i int, elseOK bool) (int, bool) {
	if i >= len(p.tokens) {
		return 0, false
	}
	switch p.tokens[i].Token.Type {
	case models.TokenTypeSemicolon, models.TokenTypeEOF:
		return 0, false
	}
	p.seek(i)
	p.markImplicitEnd(i)
	if _, err := p.parseStatement(); err != nil {
		return 0, false
	}
	end := p.currentPos
	if end <= i {
		return 0, false
	}
	switch {
	case end >= len(p.tokens),
		p.tokens[end].Token.Type == models.TokenTypeSemicolon,
		p.tokens[end].Token.Type == models.TokenTypeEOF,
		elseOK && p.utilityWord(end) == "ELSE",
		p.implicitStartAt(end):
		return end, true
	}
	return 0, false
}

// parserState is the part of the parser state that a speculative parse
// may change.
type parserState struct {
	depth                     int
	implicitEnd               int
	dmlReturning, inConnectBy bool
}

func (p *Parser) snapshotState() parserState {
	return parserState{
		depth: p.depth, implicitEnd: p.implicitEnd,
		dmlReturning: p.dmlReturning, inConnectBy: p.inConnectBy,
	}
}

func (p *Parser) restoreState(s parserState) {
	p.depth, p.implicitEnd = s.depth, s.implicitEnd
	p.dmlReturning, p.inConnectBy = s.dmlReturning, s.inConnectBy
}
