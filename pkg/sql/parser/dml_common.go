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

// Package parser - dml_common.go
// Clauses shared by INSERT, UPDATE, DELETE and MERGE: statement modifiers,
// UPDATE/DELETE targets, SET assignments, OUTPUT, RETURNING and the
// single-table ORDER BY ... LIMIT row limit.

package parser

import (
	"fmt"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// dmlVerb selects the modifier set accepted by parseDMLModifiers.
type dmlVerb int

const (
	dmlInsert dmlVerb = iota
	dmlUpdate
	dmlDelete
)

// mysqlDMLModifiers lists the MySQL/MariaDB modifiers per statement verb.
var mysqlDMLModifiers = [...][]string{
	dmlInsert: {"LOW_PRIORITY", "HIGH_PRIORITY", "DELAYED", "IGNORE"},
	dmlUpdate: {"LOW_PRIORITY", "IGNORE"},
	dmlDelete: {"LOW_PRIORITY", "QUICK", "IGNORE"},
}

// sqliteConflictModifiers maps the SQLite OR <resolution> keyword to the
// stored modifier.
var sqliteConflictModifiers = [...][2]string{
	{"ROLLBACK", "OR ROLLBACK"},
	{"ABORT", "OR ABORT"},
	{"REPLACE", "OR REPLACE"},
	{"FAIL", "OR FAIL"},
	{"IGNORE", "OR IGNORE"},
}

// isMySQLFamily reports whether the dialect is MySQL or MariaDB.
func (p *Parser) isMySQLFamily() bool {
	return p.dialect == string(keywords.DialectMySQL) || p.isMariaDB()
}

// parseDMLModifiers consumes the dialect's statement modifiers written
// between INSERT/UPDATE/DELETE and the target (or INTO / FROM) and returns
// them upper-cased in source order.
func (p *Parser) parseDMLModifiers(verb dmlVerb) []string {
	var mods []string
	for {
		m := p.dmlModifierAt(verb)
		if m == "" {
			return mods
		}
		mods = append(mods, m)
	}
}

// dmlModifierAt consumes and returns one modifier at the current token, or
// returns "" without consuming anything.
func (p *Parser) dmlModifierAt(verb dmlVerb) string {
	switch {
	case p.isMySQLFamily():
		if !p.isType(models.TokenTypeIdentifier) && !p.isType(models.TokenTypeKeyword) {
			return ""
		}
		// A modifier is never followed by '.', ',' or AS; those make the
		// word a table name (UPDATE ignore SET ..., DELETE quick.t ...).
		switch p.peekToken().Token.Type {
		case models.TokenTypePeriod, models.TokenTypeComma, models.TokenTypeAs, models.TokenTypeSet:
			return ""
		}
		for _, m := range mysqlDMLModifiers[verb] {
			if equalsUpper(p.currentToken.Token.Value, m) {
				p.advance()
				return m
			}
		}
	case p.dialect == string(keywords.DialectSQLite):
		if verb == dmlDelete || !p.isType(models.TokenTypeOr) {
			return ""
		}
		next := p.peekToken().Token.Value
		for _, m := range sqliteConflictModifiers {
			if equalsUpper(next, m[0]) {
				p.advance() // OR
				p.advance() // resolution
				return m[1]
			}
		}
	case p.dialect == string(keywords.DialectSnowflake):
		if verb == dmlInsert && equalsUpper(p.currentToken.Token.Value, "OVERWRITE") &&
			p.peekToken().Token.Type == models.TokenTypeInto {
			p.advance()
			return "OVERWRITE"
		}
	}
	return ""
}

// isDMLOnly reports whether the current token is the PostgreSQL ONLY
// modifier before an UPDATE/DELETE target.
func (p *Parser) isDMLOnly() bool {
	if p.dialect != "" && p.dialect != string(keywords.DialectPostgreSQL) {
		return false
	}
	if !equalsUpper(p.currentToken.Token.Value, "ONLY") || p.isStringLiteral() {
		return false
	}
	next := p.peekToken().Token.Type
	return next == models.TokenTypeIdentifier || next == models.TokenTypeDoubleQuotedString
}

// isDMLOutputKeyword reports whether the current token is an unquoted SQL
// Server OUTPUT keyword.
func (p *Parser) isDMLOutputKeyword() bool {
	return p.dialect == string(keywords.DialectSQLServer) &&
		p.isType(models.TokenTypeIdentifier) &&
		equalsUpper(p.currentToken.Token.Value, "OUTPUT") &&
		!p.isQuotedIdentifierToken()
}

// isDMLTargetAlias reports whether the current token is a bare alias after
// an UPDATE/DELETE target name rather than the clause that follows it.
func (p *Parser) isDMLTargetAlias() bool {
	if !p.isIdentifier() {
		return false
	}
	return !p.isReturningKeyword() && !p.isDMLOutputKeyword()
}

// parseDMLTargetRef parses one UPDATE/DELETE target: a possibly qualified
// table name with an optional alias, or a derived table (Oracle
// UPDATE (SELECT ...) SET, DELETE FROM (SELECT ...)).
func (p *Parser) parseDMLTargetRef() (ast.TableReference, error) {
	if p.isType(models.TokenTypeLParen) {
		return p.parseFromTableReference()
	}
	name, nameQuote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return ast.TableReference{}, p.qualifiedNameError(err, "table name")
	}
	ref := ast.TableReference{Name: name, NameQuote: nameQuote}
	if p.isType(models.TokenTypeAs) {
		p.advance() // Consume AS
		if !p.isIdentifier() {
			return ref, p.expectedError("alias after AS")
		}
		ref.Alias = p.currentToken.Token.Value
		ref.AliasQuote = p.currentNameQuote()
		p.advance()
	} else if p.isDMLTargetAlias() {
		ref.Alias = p.currentToken.Token.Value
		ref.AliasQuote = p.currentNameQuote()
		p.advance()
	}
	return ref, nil
}

// parseDMLTargets parses the target list of UPDATE/DELETE. The first target
// is stored in *name / *alias when it is a plain table name and in d.Tables
// otherwise; further comma-separated targets (multi=true, MySQL multi-table
// forms) go to d.Tables.
func (p *Parser) parseDMLTargets(name, alias *string, d *ast.DMLTargetFields, multi bool) (ast.TableReference, error) {
	first, err := p.parseDMLTargetRef()
	if err != nil {
		return first, err
	}
	if first.Subquery == nil && first.SetSubquery == nil && first.TableFunc == nil {
		*name, *alias = first.Name, first.Alias
		d.TableNameQuote, d.AliasQuote = first.NameQuote, first.AliasQuote
	} else {
		d.Tables = append(d.Tables, first)
	}
	for multi && p.isType(models.TokenTypeComma) {
		p.advance() // Consume ,
		ref, err := p.parseDMLTargetRef()
		if err != nil {
			return first, err
		}
		d.Tables = append(d.Tables, ref)
	}
	return first, nil
}

// isWordToken reports whether the current token is a bare word (identifier
// or keyword), as opposed to a literal, operator or punctuation.
func (p *Parser) isWordToken() bool {
	if p.isIdentifier() {
		return true
	}
	if p.isStringLiteral() || p.isType(models.TokenTypeNumber) {
		return false
	}
	v := p.currentToken.Token.Value
	if v == "" {
		return false
	}
	c := v[0]
	return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z')
}

// parseAssignmentTarget parses the left side of a SET assignment: a column,
// a qualified column (t.c), a column tuple ((a, b)) or a variable (@v).
func (p *Parser) parseAssignmentTarget() (ast.Expression, error) {
	if p.isType(models.TokenTypeLParen) {
		p.advance() // Consume (
		tuple := &ast.TupleExpression{}
		for {
			col, err := p.parseAssignmentColumn()
			if err != nil {
				return nil, err
			}
			tuple.Expressions = append(tuple.Expressions, col)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance() // Consume ,
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance() // Consume )
		return tuple, nil
	}
	if p.isType(models.TokenTypePlaceholder) {
		// SQL Server / MySQL variable target: SET @v = expr.
		return p.parsePrimaryExpression()
	}
	return p.parseAssignmentColumn()
}

// parseAssignmentColumn parses a possibly qualified column name. Keyword
// words are accepted as names here (SET key = ..., SET status = ...) since an
// assignment target can only be a column.
func (p *Parser) parseAssignmentColumn() (ast.Expression, error) {
	if !p.isWordToken() {
		return nil, p.expectedError("column name")
	}
	q := p.currentIdentQuote()
	ident := &ast.Identifier{
		Name:       p.currentToken.Token.Value,
		Pos:        p.currentLocation(),
		Quoted:     q == '"',
		QuoteStyle: q,
		Quotes:     p.appendNamePartQuoted(0, q),
	}
	p.advance()
	for p.isType(models.TokenTypePeriod) {
		p.advance() // Consume .
		if !p.isWordToken() {
			return nil, p.expectedError("column name after .")
		}
		if ident.Table == "" {
			ident.Table = ident.Name
		} else {
			ident.Table += "." + ident.Name
		}
		ident.Name = p.currentToken.Token.Value
		q = p.currentIdentQuote()
		ident.Quoted = q == '"'
		if q != 0 {
			ident.QuoteStyle = q
		}
		ident.Quotes = p.appendNamePartQuoted(ident.Quotes, q)
		p.advance()
	}
	return ident, nil
}

// parseDMLValue parses a value in a SET assignment or VALUES row, accepting
// the DEFAULT keyword.
func (p *Parser) parseDMLValue() (ast.Expression, error) {
	if p.isType(models.TokenTypeDefault) {
		switch p.peekToken().Token.Type {
		case models.TokenTypeLParen, models.TokenTypePeriod:
			// DEFAULT(col) or a column named default: an expression.
		default:
			p.advance() // Consume DEFAULT
			return &ast.DefaultExpr{}, nil
		}
	}
	return p.parseExpression()
}

// parseAssignments parses "target = value [, ...]" (the SET list of UPDATE,
// ON CONFLICT DO UPDATE and ON DUPLICATE KEY UPDATE). context names the
// clause in errors.
func (p *Parser) parseAssignments(context string) ([]ast.UpdateExpression, error) {
	var updates []ast.UpdateExpression
	for {
		col, err := p.parseAssignmentTarget()
		if err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance() // Consume =
		value, err := p.parseDMLValue()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse %s value: %v", context, err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}
		updates = append(updates, ast.UpdateExpression{Column: col, Value: value})
		if !p.isType(models.TokenTypeComma) {
			return updates, nil
		}
		p.advance() // Consume ,
	}
}

// parseDMLOutputClause parses the SQL Server OUTPUT clause; the current token
// must be OUTPUT. Items may carry aliases; an INTO target with an optional
// column list may follow.
func (p *Parser) parseDMLOutputClause() ([]ast.Expression, *ast.OutputInto, error) {
	p.advance() // Consume OUTPUT
	items, err := p.parseSelectColumnList()
	if err != nil {
		return nil, nil, err
	}
	if !p.isType(models.TokenTypeInto) {
		return items, nil, nil
	}
	p.advance() // Consume INTO
	into := &ast.OutputInto{}
	if p.isType(models.TokenTypePlaceholder) {
		into.Target = p.currentToken.Token.Value
		p.advance()
	} else {
		name, err := p.parseQualifiedName()
		if err != nil {
			return nil, nil, p.qualifiedNameError(err, "OUTPUT INTO target")
		}
		into.Target = name
	}
	if p.isType(models.TokenTypeLParen) && p.peekToken().Token.Type != models.TokenTypeSelect {
		cols, err := p.parseInsertColumnList()
		if err != nil {
			return nil, nil, err
		}
		into.Columns = cols
	}
	return items, into, nil
}

// parseReturningClause parses "RETURNING items [INTO targets]"; the current
// token must be RETURNING. Items may carry aliases (RETURNING id AS new_id).
func (p *Parser) parseReturningClause() ([]ast.Expression, []ast.Expression, error) {
	p.advance() // Consume RETURNING
	items, err := p.parseSelectColumnList()
	if err != nil {
		return nil, nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("failed to parse RETURNING column: %v", err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}
	if !p.isType(models.TokenTypeInto) {
		return items, nil, nil
	}
	p.advance() // Consume INTO
	var into []ast.Expression
	for {
		target, err := p.parsePrimaryExpression()
		if err != nil {
			return nil, nil, err
		}
		into = append(into, target)
		if !p.isType(models.TokenTypeComma) {
			return items, into, nil
		}
		p.advance() // Consume ,
	}
}

// parseDMLOrderLimit parses the single-table row limit of UPDATE / DELETE:
// [ORDER BY ...] [LIMIT n] (MySQL, MariaDB, SQLite). LIMIT is accepted in
// every dialect, as before; ORDER BY only where the dialect has it.
func (p *Parser) parseDMLOrderLimit(d *ast.DMLTargetFields) error {
	if p.isType(models.TokenTypeOrder) &&
		(p.isMySQLFamily() || p.dialect == string(keywords.DialectSQLite)) {
		orderBy, err := p.parseOrderByClause()
		if err != nil {
			return err
		}
		d.OrderBy = orderBy
	}
	if p.isType(models.TokenTypeLimit) {
		p.advance() // Consume LIMIT
		limit, err := p.parsePrimaryExpression()
		if err != nil {
			return goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse LIMIT value: %v", err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}
		d.Limit = limit
	}
	return nil
}
