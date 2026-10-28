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

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// This file records how names were delimited in the source (ast.NameQuote),
// so renderers can keep the quotes a name needs: "CreatedAt" quoted for its
// case, "table" quoted because it is a keyword, a MySQL `exists` alias with
// its backticks, and an Oracle bare emp# without any.

// identifierCaseFolding returns how the dialect matches the case of unquoted
// identifiers (see ast.IdentifierCaseFolding). Generic SQL folds to lower
// case like PostgreSQL.
func (p *Parser) identifierCaseFolding() ast.IdentifierCaseFolding {
	switch keywords.SQLDialect(p.dialect) {
	case keywords.DialectOracle, keywords.DialectSnowflake:
		return ast.FoldUpper
	case keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer,
		keywords.DialectSQLite, keywords.DialectClickHouse, keywords.DialectBigQuery:
		return ast.FoldNone
	}
	return ast.FoldLower
}

// delimitedNameMustStayQuoted reports whether name, written delimited with
// quote in the source, must keep delimiters to mean the same name: see
// ast.DelimitedNameMustStayQuoted, plus any word the tokenizer reads as a
// keyword when bare.
func (p *Parser) delimitedNameMustStayQuoted(name string, quote rune) bool {
	if quote == 0 {
		return false
	}
	// TOP is a dialect keyword, absent from the tokenizer's global keyword map.
	return (p.IsSQLServer() && equalsUpper(name, "TOP")) ||
		ast.DelimitedNameMustStayQuoted(name, p.identifierCaseFolding()) || tokenizer.IsKeyword(name) ||
		isContextualKeywordName(name)
}

// contextualKeywordNames lists, in upper case, words the tokenizer reads as
// plain identifiers but that the databases (or the parser, in context) treat
// as niladic functions, pseudo-columns or operators when written bare:
// "user" is a column, user is the current user; "PRIOR" is a column, PRIOR
// in CONNECT BY is the operator. A delimited name equal to one of them keeps
// its delimiters.
var contextualKeywordNames = map[string]bool{
	"PRIOR": true, "CONNECT_BY_ROOT": true,
	"USER": true, "CURRENT_USER": true, "SESSION_USER": true, "SYSTEM_USER": true,
	"CURRENT_ROLE": true, "CURRENT_CATALOG": true, "CURRENT_SCHEMA": true,
	"CURRENT_DATE": true, "CURRENT_TIME": true, "CURRENT_TIMESTAMP": true,
	"LOCALTIME": true, "LOCALTIMESTAMP": true,
	"SYSDATE": true, "SYSTIMESTAMP": true, "ROWNUM": true, "ROWID": true, "LEVEL": true,
}

// maxContextualKeywordLen is the length of the longest
// contextualKeywordNames word.
const maxContextualKeywordLen = len("CURRENT_TIMESTAMP")

// isContextualKeywordName reports whether name is in contextualKeywordNames,
// ignoring ASCII case, without allocating.
func isContextualKeywordName(name string) bool {
	if len(name) < 4 || len(name) > maxContextualKeywordLen {
		return false
	}
	var up [maxContextualKeywordLen]byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		up[i] = c
	}
	return contextualKeywordNames[string(up[:len(name)])]
}

// isOracleBareHashName reports whether the current token is a bare Oracle
// identifier containing '#' after its first character (emp#, s.serial#).
func (p *Parser) isOracleBareHashName() bool {
	return p.dialect == string(keywords.DialectOracle) &&
		strings.IndexByte(p.currentToken.Token.Value, '#') > 0
}

// currentNameQuote returns the NameQuote of the current token read as a
// single-part name: the part is marked when the token is a delimited
// identifier that must stay delimited (see delimitedNameMustStayQuoted).
func (p *Parser) currentNameQuote() ast.NameQuote {
	return p.appendNamePart(0)
}

// appendNamePart returns q extended by the current token as the next part of
// a dotted name (see ast.NameQuote.AppendPart).
func (p *Parser) appendNamePart(q ast.NameQuote) ast.NameQuote {
	return p.appendNamePartQuoted(q, p.currentIdentQuote())
}

// nameQuoteRelevant reports whether a name part with delimiter quote (0 for
// a bare part) can record anything in a NameQuote: it is delimited, or it is
// an Oracle name that may carry a bare '#'. Hot paths check it inline before
// calling appendNamePartQuoted, since appending an unmarked part to a zero
// NameQuote leaves it zero.
func (p *Parser) nameQuoteRelevant(quote rune) bool {
	return quote != 0 || p.dialect == string(keywords.DialectOracle)
}

// appendNamePartQuoted is appendNamePart for a caller that already has the
// current token's delimiter (p.currentIdentQuote()).
func (p *Parser) appendNamePartQuoted(q ast.NameQuote, quote rune) ast.NameQuote {
	if quote == 0 {
		q = q.AppendPart(false)
		if p.isOracleBareHashName() {
			q = q.WithBareHash(true)
		}
		return q
	}
	keep := p.delimitedNameMustStayQuoted(p.currentToken.Token.Value, quote)
	q = q.AppendPart(keep)
	if keep && !q.HasStyle() {
		q = q.WithStyle(quote)
	}
	return q
}

// parseQualifiedNameQuoted parses a possibly qualified object name like
// parseQualifiedName and also returns how its parts were delimited.
func (p *Parser) parseQualifiedNameQuoted() (string, ast.NameQuote, error) {
	return p.parseQualifiedNameWithTableRules(false)
}

// isReservedTopName checks the dialect before inspecting the token text.
func (p *Parser) isReservedTopName() bool {
	return p.IsSQLServer() && p.isUnquotedWord("TOP")
}

func (p *Parser) parseQualifiedNameWithTableRules(table bool) (string, ast.NameQuote, error) {
	if table && p.isReservedTopName() {
		return "", 0, p.expectedError("table name (TOP is reserved in SQL Server; quote it as [top])")
	}
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return "", 0, p.expectedError("identifier")
	}
	first := p.currentToken.Token.Value
	var q ast.NameQuote
	if quote := p.currentIdentQuote(); p.nameQuoteRelevant(quote) {
		q = p.appendNamePartQuoted(0, quote)
	}
	p.advance()
	if !p.isType(models.TokenTypePeriod) {
		return first, q, nil // a one-part name
	}
	var parts [maxQualifiedNameParts]string
	parts[0] = first
	n := 1

	// Check for schema.table or db.schema.table
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if p.isEmptyNamePart() && n < maxQualifiedNameParts {
			// SQL Server db..t: the default schema, written as an empty part.
			if q != 0 {
				q = q.AppendPart(false)
			}
			n++
			continue
		}
		if n == maxQualifiedNameParts {
			return "", 0, goerrors.InvalidSyntaxError(
				fmt.Sprintf("qualified name has more than %d parts", maxQualifiedNameParts),
				p.currentLocation(),
				"",
			).WithCause(errQualifiedNameTooLong)
		}
		if (table && p.isReservedTopName()) || (!p.isIdentifier() && !p.isNonReservedKeyword()) {
			return "", 0, p.expectedError("identifier after .")
		}
		parts[n] = p.currentToken.Token.Value
		if quote := p.currentIdentQuote(); q != 0 || p.nameQuoteRelevant(quote) {
			q = p.appendNamePartQuoted(q, quote)
		}
		n++
		p.advance()
	}

	if n == 1 {
		return parts[0], q, nil
	}
	return strings.Join(parts[:n], "."), q, nil
}

// nameQuoteList returns qs with q appended at index i, allocating the slice
// only once some name in the list records a NameQuote.
func nameQuoteList(qs []ast.NameQuote, i int, q ast.NameQuote) []ast.NameQuote {
	if q == 0 && qs == nil {
		return nil
	}
	for len(qs) < i {
		qs = append(qs, 0)
	}
	return append(qs, q)
}

// nameQuoteAt returns qs[i], or the zero NameQuote when qs is too short.
func nameQuoteAt(qs []ast.NameQuote, i int) ast.NameQuote {
	if i < len(qs) {
		return qs[i]
	}
	return 0
}

// currentColumnIdent returns the current token as a single-part column name
// (an INSERT column, a JOIN USING column, an ON CONFLICT target), recording
// how it was delimited. It does not advance.
func (p *Parser) currentColumnIdent() *ast.Identifier {
	q := p.currentIdentQuote()
	return &ast.Identifier{
		Name:       p.currentToken.Token.Value,
		Pos:        p.currentLocation(),
		Quoted:     q == '"',
		QuoteStyle: q,
		Quotes:     p.appendNamePartQuoted(0, q),
	}
}
