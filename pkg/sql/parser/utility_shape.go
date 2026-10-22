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

// utility_shape.go holds the minimal shape checks for utility statements
// that are kept verbatim. The parser does not model their grammar, so it
// cannot prove them valid, but it can refuse the plainly truncated forms
// (SET GLOBAL, SHOW, SHOW TABLES LIKE, GRANT ... TO) so that validation does
// not report them as correct.

package parser

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// danglingWords lists the words that cannot end a statement: each is
// followed by an operand in every dialect. ON, OFF and DEFAULT are absent on
// purpose (SET NOCOUNT ON, SET x TO DEFAULT).
var danglingWords = map[string]bool{
	"LIKE": true, "ILIKE": true, "RLIKE": true, "REGEXP": true, "WHERE": true,
	"FROM": true, "IN": true, "FOR": true, "TO": true, "BY": true, "AND": true,
	"OR": true, "NOT": true, "AS": true, "INTO": true, "USING": true, "IS": true,
	"BETWEEN": true,
}

// verbatimTailError returns an error when the verbatim statement made of
// tokens [start, end) stops where an operand is required: after a comma, an
// assignment operator or one of danglingWords. The parser is left at end.
func (p *Parser) verbatimTailError(start, end int) error {
	if end-1 <= start || end > len(p.tokens) {
		return nil
	}
	last := &p.tokens[end-1]
	dangling := false
	switch last.Token.Type {
	case models.TokenTypeComma, models.TokenTypeEq, models.TokenTypeAssignment:
		dangling = true
	default:
		dangling = danglingWords[p.utilityWord(end-1)]
	}
	if !dangling {
		return nil
	}
	p.seek(end)
	return p.expectedError("operand after " + last.Token.Value)
}

// setValueError returns an error when a SET statement ends right after its
// variable name: every dialect needs a value, an operator or an option after
// it (SET x = 1, SET NOCOUNT ON, SET search_path TO a). The name occupies
// tokens [nameStart, ...) up to the first assignment operator or separated
// token; the statement spans [start, end).
func (p *Parser) setValueError(name string, nameStart, start, end int) error {
	j := nameStart + 1
	for j < end && !isAssignmentToken(p.tokens[j].Token.Type) &&
		p.tokens[j].Token.Type != models.TokenTypeComma &&
		tokensAdjacent(&p.tokens[j-1], &p.tokens[j]) {
		j++
	}
	if j < end {
		return p.verbatimTailError(start, end)
	}
	p.seek(end)
	return p.expectedError("value after SET " + name)
}

// showTailMissing reports whether the generic SHOW form has nothing to show:
// SHOW at the end of the statement, or a lone modifier (FULL, GLOBAL, ...)
// that is only meaningful in front of an object word.
func (p *Parser) showTailMissing() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeEOF, models.TokenTypeSemicolon:
		return true
	}
	switch p.utilityWord(p.currentPos) {
	case "FULL", "GLOBAL", "SESSION", "LOCAL", "EXTENDED", "STORAGE":
		switch p.peekToken().Token.Type {
		case models.TokenTypeEOF, models.TokenTypeSemicolon:
			return true
		}
	}
	return false
}
