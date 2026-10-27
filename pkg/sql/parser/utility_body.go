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

// utility_body.go ends the verbatim statements whose definition holds
// another statement (PREPARE name AS <stmt>, DECLARE c CURSOR FOR <query>,
// CREATE RULE ... DO <stmt>, a MySQL trigger, event or routine with a
// single-statement body, ...) where that statement ends. Outside SQL Server
// such a statement used to run to the next ';', so a missing ';' folded the
// statement after it into its text:
//
//	PREPARE s AS SELECT 1
//	DROP TABLE t
//
// The body is parsed structurally (a statement, an expression after RETURN,
// or a BEGIN ... END block), and what follows it must end the statement
// exactly as after any other statement (see lineStatementEnd).

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// bodyKind says what holds the definition of a verbatim statement.
type bodyKind uint8

const (
	// bodyNone: no nested statement was found; the statement ends as its
	// fallback policy says.
	bodyNone bodyKind = iota
	// bodyStatement: a statement starts at the body index.
	bodyStatement
	// bodyBlock: a BEGIN ... END block (optionally labelled) starts there.
	bodyBlock
	// bodyReturn: RETURN expr (a MySQL function, a PostgreSQL SQL-standard
	// function body); the body index is the RETURN.
	bodyReturn
	// bodyRuleAction: the action of a PostgreSQL rule: NOTHING, a
	// parenthesized list of commands or a single command.
	bodyRuleAction
	// bodyTriggerCall: EXECUTE FUNCTION | PROCEDURE name(args) of a
	// PostgreSQL trigger; the body index is the EXECUTE.
	bodyTriggerCall
)

// lineBody describes where the definition of a verbatim statement starts.
type lineBody struct {
	at   int
	kind bodyKind
	// view is set for a view, whose query may be followed by
	// WITH [CASCADED | LOCAL] CHECK OPTION.
	view bool
	// fallback is the policy used when kind is bodyNone.
	fallback implicitPolicy
}

// lineBodyObjects are the objects of CREATE / ALTER whose definition may
// hold a statement outside SQL Server.
var lineBodyObjects = map[string]bool{
	"FUNCTION": true, "PROCEDURE": true, "TRIGGER": true, "EVENT": true,
	"RULE": true, "TASK": true, "VIEW": true,
}

// createObjectAt returns the index of the object word of the CREATE or
// ALTER statement starting at token index start, past OR REPLACE, the
// modifiers of createModifierWords and MySQL's DEFINER = user, ALGORITHM =
// x and SQL SECURITY x options; -1 when there is none.
func (p *Parser) createObjectAt(start int) int {
	i := start + 1
	for n := 0; n < 24 && i < len(p.tokens); n++ {
		switch w := p.utilityWord(i); {
		case w == "DEFINER" || w == "ALGORITHM":
			j := i + 1
			for ; j < i+8 && j < len(p.tokens) && !isCreateOptionFollower(p.utilityWord(j)); j++ {
				if t := p.tokens[j].Token.Type; t == models.TokenTypeEOF || t == models.TokenTypeSemicolon {
					return -1
				}
			}
			if j == i+8 || j >= len(p.tokens) {
				return -1
			}
			i = j
		case w == "SQL" && p.utilityWord(i+1) == "SECURITY":
			i += 3
		case createModifierWords[w] || w == "MATERIALIZED" || w == "CONSTRAINT":
			i++
		case w == "":
			return -1
		default:
			return i
		}
	}
	return -1
}

// lineBodyPolicy reports whether the CREATE / ALTER statement starting at
// token index start, outside SQL Server, defines an object whose definition
// may hold a statement.
func (p *Parser) lineBodyPolicy(start int) bool {
	obj := p.createObjectAt(start)
	if obj < 0 || !lineBodyObjects[p.utilityWord(obj)] {
		return false
	}
	if p.IsOracle() {
		// PL/SQL routines and triggers end with their block (and a '/'
		// line); only a view holds a plain query.
		return p.utilityWord(obj) == "VIEW"
	}
	return true
}

// groupEnd returns the index after the parenthesized group that opens at
// token index i, or -1 when i is not '(' or the group does not close
// before a ';' or the end of the input.
func (p *Parser) groupEnd(i int) int {
	if i >= len(p.tokens) || p.tokens[i].Token.Type != models.TokenTypeLParen {
		return -1
	}
	depth := 0
	for ; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
			if depth == 0 {
				return i + 1
			}
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return -1
		}
	}
	return -1
}

// isNamePartAt reports whether the token at index i can be part of an
// object name: an identifier, a delimited identifier or a bare word.
func (p *Parser) isNamePartAt(i int) bool {
	return p.isIdentifierAt(i) || p.utilityWord(i) != ""
}

// nameEnd returns the index after the possibly qualified name starting at
// token index i (i itself when no name starts there).
func (p *Parser) nameEnd(i int) int {
	if !p.isNamePartAt(i) {
		return i
	}
	i++
	for i+1 < len(p.tokens) && p.tokens[i].Token.Type == models.TokenTypePeriod && p.isNamePartAt(i+1) {
		i += 2
	}
	return i
}

// topLevelWord returns the index of the first word w after token index
// from that is outside parentheses, before the statement's ';' or the end
// of the input; -1 when there is none.
func (p *Parser) topLevelWord(from int, w string) int {
	depth := 0
	for i := from; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
			continue
		case models.TokenTypeRParen:
			depth--
			continue
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			if depth <= 0 {
				return -1
			}
			continue
		}
		if depth == 0 && p.utilityWord(i) == w {
			return i
		}
	}
	return -1
}

// lineBodyStart finds the definition of the verbatim statement starting at
// token index start.
func (p *Parser) lineBodyStart(start int) lineBody {
	none := lineBody{fallback: implicitNone}
	switch p.utilityWord(start) {
	case "PREPARE":
		// PREPARE name [(type, ...)] AS statement (PostgreSQL); MySQL's
		// PREPARE name FROM {'text' | @var} holds no statement.
		i := p.nameEnd(start + 1)
		if e := p.groupEnd(i); e > 0 {
			i = e
		}
		if p.utilityWord(i) == "AS" {
			return p.bodyAt(i+1, false)
		}
		return lineBody{fallback: implicitLine}
	case "DECLARE":
		// DECLARE name [BINARY] [ASENSITIVE | INSENSITIVE] [[NO] SCROLL]
		// CURSOR [{WITH | WITHOUT} HOLD] FOR query (PostgreSQL).
		i := start + 2
		for {
			switch p.utilityWord(i) {
			case "BINARY", "ASENSITIVE", "INSENSITIVE", "NO", "SCROLL":
				i++
				continue
			}
			break
		}
		if p.utilityWord(i) != "CURSOR" {
			return none
		}
		i++
		if w := p.utilityWord(i); (w == "WITH" || w == "WITHOUT") && p.utilityWord(i+1) == "HOLD" {
			i += 2
		}
		if p.utilityWord(i) != "FOR" {
			return none
		}
		return p.bodyAt(i+1, false)
	}
	obj := p.createObjectAt(start)
	switch p.utilityWord(obj) {
	case "RULE":
		// CREATE RULE name AS ON event TO table [WHERE cond] DO [ALSO |
		// INSTEAD] {NOTHING | command | (command; ...)}
		do := p.topLevelWord(obj+1, "DO")
		if do < 0 {
			return none
		}
		do++
		if w := p.utilityWord(do); w == "ALSO" || w == "INSTEAD" {
			do++
		}
		return lineBody{at: do, kind: bodyRuleAction}
	case "TASK":
		// CREATE TASK name [options] AS statement (Snowflake).
		as := p.topLevelWord(obj+1, "AS")
		if as < 0 {
			return lineBody{fallback: implicitLineDDL}
		}
		return p.bodyAt(as+1, false)
	case "EVENT":
		// CREATE / ALTER EVENT name ... DO body (MySQL).
		do := p.topLevelWord(obj+1, "DO")
		if do < 0 {
			return lineBody{fallback: implicitLineDDL}
		}
		return p.bodyAt(do+1, false)
	case "VIEW":
		// CREATE VIEW name [(cols)] [options] AS query.
		as := p.topLevelWord(obj+1, "AS")
		if as < 0 {
			return lineBody{fallback: implicitLineDDL}
		}
		b := p.bodyAt(as+1, true)
		b.view = true
		return b
	case "TRIGGER":
		if p.utilityWord(start) == "ALTER" {
			return lineBody{fallback: implicitLineDDL}
		}
		return p.triggerBodyStart(obj + 1)
	case "FUNCTION", "PROCEDURE":
		if p.utilityWord(start) == "ALTER" {
			return lineBody{fallback: implicitLineDDL}
		}
		return p.routineBodyStart(obj + 1)
	}
	return none
}

// bodyAt classifies the definition starting at token index i. query is set
// where only a query may follow (a view).
func (p *Parser) bodyAt(i int, query bool) lineBody {
	if i >= len(p.tokens) {
		return lineBody{fallback: implicitNone}
	}
	switch p.tokens[i].Token.Type {
	case models.TokenTypeSemicolon, models.TokenTypeEOF:
		return lineBody{fallback: implicitNone}
	}
	if !query && p.opensBlockAt(i) {
		return lineBody{at: i, kind: bodyBlock}
	}
	if compoundStatementWords[p.utilityWord(i)] {
		// A procedural statement (IF ... END IF, a loop, SIGNAL) that the
		// parser does not model: run to the next ';' as before.
		return lineBody{fallback: implicitNone}
	}
	return lineBody{at: i, kind: bodyStatement}
}

// compoundStatementWords start the procedural statements of a routine body
// that only blockScan follows.
var compoundStatementWords = map[string]bool{
	"IF": true, "CASE": true, "LOOP": true, "WHILE": true, "REPEAT": true,
	"LEAVE": true, "ITERATE": true, "SIGNAL": true, "RESIGNAL": true,
	"OPEN": true, "CLOSE": true, "FETCH": true, "DECLARE": true, "FOR": true,
	"GET": true,
}

// opensBlockAt reports whether a BEGIN ... END block starts at token index
// i: BEGIN (BEGIN ATOMIC, BEGIN NOT ATOMIC) or a label followed by ':' and
// BEGIN.
func (p *Parser) opensBlockAt(i int) bool {
	if p.utilityWord(i) == "BEGIN" {
		return p.beginOpensBlockAt(i)
	}
	return p.isNamePartAt(i) && i+2 < len(p.tokens) &&
		p.tokens[i+1].Token.Type == models.TokenTypeColon && p.utilityWord(i+2) == "BEGIN"
}

// triggerBodyStart finds the body of a CREATE TRIGGER outside SQL Server
// and Oracle; from is the index after TRIGGER. A PostgreSQL trigger ends
// with EXECUTE FUNCTION f(args), a SQLite trigger with its BEGIN ... END
// block, a MySQL trigger with the statement or block after FOR EACH ROW
// [{FOLLOWS | PRECEDES} other].
func (p *Parser) triggerBodyStart(from int) lineBody {
	depth := 0
	for i := from; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
			continue
		case models.TokenTypeRParen:
			depth--
			continue
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return lineBody{fallback: implicitNone}
		}
		if depth != 0 {
			continue
		}
		switch p.utilityWord(i) {
		case "EXECUTE":
			if w := p.utilityWord(i + 1); w == "FUNCTION" || w == "PROCEDURE" {
				return lineBody{at: i, kind: bodyTriggerCall}
			}
		case "BEGIN":
			if p.beginOpensBlockAt(i) {
				return lineBody{at: i, kind: bodyBlock}
			}
		case "FOR":
			if !p.isMySQLFamily() && p.alterMask() != dialectAll {
				continue
			}
			if p.utilityWord(i+1) != "EACH" || p.utilityWord(i+2) != "ROW" {
				continue
			}
			j := i + 3
			if w := p.utilityWord(j); w == "FOLLOWS" || w == "PRECEDES" {
				j = p.nameEnd(j + 1)
			}
			switch p.utilityWord(j) {
			case "EXECUTE", "WHEN", "BEGIN":
				// PostgreSQL / SQLite forms, found by the loop.
				i = j - 1
				continue
			}
			return p.bodyAt(j, false)
		}
	}
	return lineBody{fallback: implicitNone}
}

// routineBodyStart finds the body of a CREATE FUNCTION / PROCEDURE outside
// SQL Server and Oracle; from is the index after FUNCTION / PROCEDURE. The
// header (name, parameters, RETURNS type, characteristics or options) is
// skipped up to the first word that starts a body: BEGIN, RETURN or a
// statement (MySQL's single-statement routine body). A quoted body (AS
// $$ ... $$, AS '...') is followed only by options, so the statement then
// ends at the next statement on a line of its own.
func (p *Parser) routineBodyStart(from int) lineBody {
	i := from
	if p.utilityWord(i) == "IF" && p.utilityWord(i+1) == "NOT" && p.utilityWord(i+2) == "EXISTS" {
		i += 3
	}
	i = p.nameEnd(i)
	mysql := p.isMySQLFamily()
	for ; i < len(p.tokens); i++ {
		tok := &p.tokens[i]
		switch tok.Token.Type {
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return lineBody{fallback: implicitNone}
		case models.TokenTypeLParen:
			if e := p.groupEnd(i); e > 0 {
				i = e - 1
				continue
			}
			return lineBody{fallback: implicitNone}
		case models.TokenTypeString, models.TokenTypeSingleQuotedString,
			models.TokenTypeDollarQuotedString:
			if p.utilityWord(i-1) == "AS" {
				return lineBody{fallback: implicitLineDDL}
			}
			continue
		}
		if p.utilityWord(i-1) == "RETURNS" {
			continue // the return type: RETURNS SET('a'), RETURNS TABLE (...)
		}
		if p.opensBlockAt(i) {
			return lineBody{at: i, kind: bodyBlock}
		}
		switch w := p.utilityWord(i); w {
		case "RETURN":
			return lineBody{at: i, kind: bodyReturn}
		case "SET":
			// PostgreSQL's SET configuration_parameter option; a statement
			// only in MySQL.
			if mysql {
				return p.bodyAt(i, false)
			}
		case "WITH":
			if p.startsStatementInContext(i, w) {
				return p.bodyAt(i, false)
			}
		case "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "CALL", "VALUES":
			return p.bodyAt(i, false)
		default:
			if compoundStatementWords[w] && w != "DECLARE" && w != "FOR" {
				return lineBody{fallback: implicitNone}
			}
		}
	}
	return lineBody{fallback: implicitNone}
}

// lineBodyEnd returns the end of the verbatim statement starting at token
// index start whose definition holds a statement (see lineBodyStart),
// outside SQL Server. ok is false when no such definition was found; the
// statement then ends as fallback says.
func (p *Parser) lineBodyEnd(start int) (end int, fallback implicitPolicy, ok bool, err error) {
	b := p.lineBodyStart(start)
	switch b.kind {
	case bodyNone:
		return 0, b.fallback, false, nil
	case bodyBlock:
		e, closed := p.blockBodyEnd(b.at)
		if !closed {
			// An unclosed block: plain ';' boundaries, as for any other
			// statement (see utilityStatementEnd).
			return 0, implicitNone, false, nil
		}
		end = e
	case bodyReturn:
		end, err = p.subParse(b.at+1, true)
	case bodyRuleAction:
		switch {
		case p.utilityWord(b.at) == "NOTHING":
			end = b.at + 1
		case b.at < len(p.tokens) && p.tokens[b.at].Token.Type == models.TokenTypeLParen:
			if end = p.groupEnd(b.at); end < 0 {
				return 0, implicitNone, false, nil
			}
		default:
			end, err = p.subParse(b.at, false)
		}
	case bodyTriggerCall:
		end, err = p.triggerCallEnd(b.at)
	default:
		end, err = p.subParse(b.at, false)
	}
	if err != nil {
		return 0, 0, true, err
	}
	if b.view {
		end = p.checkOptionEnd(end)
	}
	if end >= len(p.tokens) {
		return end, 0, true, nil
	}
	switch p.tokens[end].Token.Type {
	case models.TokenTypeSemicolon, models.TokenTypeEOF:
		return end, 0, true, nil
	}
	return end, 0, true, p.lineStatementEnd(end)
}

// subParse parses the statement (or, with expr, the expression) starting at
// token index i to find where it ends, and returns the index after it. The
// parser state is restored.
func (p *Parser) subParse(i int, expr bool) (int, error) {
	if err := p.enterRecursion(); err != nil {
		p.leaveRecursion()
		return 0, err
	}
	defer p.leaveRecursion()
	saved := p.snapshotState()
	savedPos, savedTok := p.currentPos, p.currentToken
	p.seek(i)
	var err error
	if expr {
		_, err = p.parseExpression()
	} else {
		p.markImplicitEnd(i)
		_, err = p.parseStatement()
	}
	end := p.currentPos
	p.restoreState(saved)
	if err != nil {
		return 0, err
	}
	p.currentPos, p.currentToken = savedPos, savedTok
	if end <= i {
		p.seek(i)
		return 0, p.expectedError("statement")
	}
	return end, nil
}

// blockBodyEnd returns the index after the BEGIN ... END block (optionally
// labelled: lbl: BEGIN ... END lbl) starting at token index i. closed is
// false when the input ends inside it.
func (p *Parser) blockBodyEnd(i int) (end int, closed bool) {
	label := ""
	if p.utilityWord(i) != "BEGIN" {
		label = p.tokens[i].Token.Value
	}
	blk := p.newBlockScan()
	depth := 0
	for ; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
		case models.TokenTypeEOF:
			return 0, false
		}
		i = blk.token(p, i)
		if depth == 0 && blk.depth == 0 && blk.closed {
			end = i + 1
			if label != "" && end < len(p.tokens) && p.isNamePartAt(end) &&
				strings.EqualFold(p.tokens[end].Token.Value, label) {
				end++
			}
			return end, true
		}
	}
	return 0, false
}

// triggerCallEnd returns the index after EXECUTE {FUNCTION | PROCEDURE}
// name(args) starting at token index i.
func (p *Parser) triggerCallEnd(i int) (int, error) {
	j := p.nameEnd(i + 2)
	if j == i+2 {
		p.seek(j)
		return 0, p.expectedError("function name")
	}
	end := p.groupEnd(j)
	if end < 0 {
		p.seek(j)
		return 0, p.expectedError("(")
	}
	return end, nil
}

// checkOptionEnd skips a view's WITH [CASCADED | LOCAL] CHECK OPTION at
// token index i.
func (p *Parser) checkOptionEnd(i int) int {
	if p.utilityWord(i) != "WITH" {
		return i
	}
	j := i + 1
	if w := p.utilityWord(j); w == "CASCADED" || w == "LOCAL" {
		j++
	}
	if p.utilityWord(j) == "CHECK" && p.utilityWord(j+1) == "OPTION" {
		return j + 2
	}
	return i
}
