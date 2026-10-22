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

// Package parser - ddl_table_constraints.go
// Table-level constraints and index elements of CREATE TABLE: PRIMARY KEY
// [CLUSTERED], UNIQUE [KEY|INDEX] [name], FOREIGN KEY, CHECK, MySQL
// KEY / INDEX / FULLTEXT / SPATIAL (including functional key parts),
// ClickHouse INDEX ... TYPE ... GRANULARITY / PROJECTION / ASSUME and the
// PostgreSQL LIKE source INCLUDING ... element.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// isTableConstraintStart reports whether the current token starts a table
// constraint or index element rather than a column definition.
func (p *Parser) isTableConstraintStart() bool {
	if p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign,
		models.TokenTypeUnique, models.TokenTypeCheck, models.TokenTypeConstraint) {
		return true
	}
	return p.isTableElementStart()
}

// isTableElementStart reports whether the current token starts an element
// that is not a CONSTRAINT: a MySQL KEY / INDEX / FULLTEXT / SPATIAL index, a
// ClickHouse INDEX or PROJECTION, or LIKE source_table. They are gated by
// dialect because several are legal column names elsewhere (SQLite
// "key TEXT").
func (p *Parser) isTableElementStart() bool {
	if p.isQuotedIdentifierToken() {
		return false
	}
	switch p.dialectTyped {
	case dialect.MySQL, dialect.MariaDB:
		switch {
		case p.isAnyType(models.TokenTypeKey, models.TokenTypeIndex):
			// KEY (cols), KEY name (cols), KEY name USING m (cols). A KEY or
			// INDEX followed by a type and no "(" is an old-style column
			// that happens to be called key.
			next := p.peekToken().Token
			return next.Type == models.TokenTypeLParen ||
				(next.Value != "" && (p.peekAt(2).Token.Type == models.TokenTypeLParen || p.peekValueIs(2, "USING")))
		case p.isUnquotedWord("FULLTEXT") || p.isUnquotedWord("SPATIAL"):
			next := p.peekToken().Token
			return next.Type == models.TokenTypeKey || next.Type == models.TokenTypeIndex ||
				next.Type == models.TokenTypeLParen || p.peekAt(2).Token.Type == models.TokenTypeLParen
		}
	case dialect.ClickHouse:
		switch {
		case p.isType(models.TokenTypeIndex) || p.isUnquotedWord("INDEX"):
			return p.clickHouseIndexAhead()
		case p.isUnquotedWord("PROJECTION"):
			return p.peekAt(2).Token.Type == models.TokenTypeLParen
		}
	}
	return p.isType(models.TokenTypeLike) &&
		p.dialectAllows(dialect.PostgreSQL, dialect.Redshift, dialect.MySQL, dialect.MariaDB)
}

// clickHouseIndexAhead reports whether the INDEX at the current token is a
// ClickHouse data-skipping index (INDEX name expr TYPE t ...) rather than a
// column called "index": a TYPE word appears before the next top-level comma
// or the closing parenthesis.
func (p *Parser) clickHouseIndexAhead() bool {
	depth := 0
	for i := 1; ; i++ {
		t := p.peekAt(i)
		switch t.Token.Type {
		case models.TokenTypeEOF, models.TokenTypeSemicolon:
			return false
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			if depth == 0 {
				return false
			}
			depth--
		case models.TokenTypeComma:
			if depth == 0 {
				return false
			}
		}
		if t.Token.Type == models.TokenTypeUnknown && t.Token.Value == "" {
			return false
		}
		if depth == 0 && equalsUpper(t.Token.Value, "TYPE") && i >= 2 {
			return true
		}
	}
}

// parseTableConstraint parses a table constraint (PRIMARY KEY, FOREIGN KEY,
// UNIQUE, CHECK) or one of the index elements listed above.
func (p *Parser) parseTableConstraint() (*ast.TableConstraint, error) {
	constraint := &ast.TableConstraint{}

	// Check for optional CONSTRAINT keyword (may already be consumed by caller)
	named := false
	if p.isType(models.TokenTypeConstraint) {
		p.advance() // Consume CONSTRAINT
		named = true
	}

	if !named && p.isTableElementStart() {
		return p.parseTableElement(constraint)
	}

	// Check for optional constraint name (identifier that isn't a constraint type keyword)
	// Constraint name comes before the constraint type (PRIMARY, FOREIGN, UNIQUE, CHECK).
	// A double-quoted name is accepted too: SQL Server keeps "x y" as a
	// DOUBLE_QUOTED_STRING token, and the renderer writes such names quoted.
	if p.isIdentifier() &&
		!p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign, models.TokenTypeUnique, models.TokenTypeCheck) {
		constraint.Name = p.currentToken.Token.Value
		p.advance()
	}

	// PRIMARY KEY [CLUSTERED] (column_list)
	if p.isType(models.TokenTypePrimary) {
		p.advance() // Consume PRIMARY
		if !p.isType(models.TokenTypeKey) {
			return nil, p.expectedError("KEY after PRIMARY")
		}
		p.advance() // Consume KEY
		constraint.Type = "PRIMARY KEY"
		constraint.Cluster = p.parseClusterKeyword()
		p.parseIndexMethod(constraint)
		if err := p.parseKeyParts(constraint); err != nil {
			return nil, err
		}
		p.parseIndexMethod(constraint)
		constraint.Deferrable = p.parseDeferrableClause()
		return constraint, nil
	}

	// FOREIGN KEY (column_list) REFERENCES table(column_list)
	if p.isType(models.TokenTypeForeign) {
		p.advance() // Consume FOREIGN
		if !p.isType(models.TokenTypeKey) {
			return nil, p.expectedError("KEY after FOREIGN")
		}
		p.advance() // Consume KEY
		constraint.Type = "FOREIGN KEY"

		// Parse column list
		columns, err := p.parseConstraintColumnList()
		if err != nil {
			return nil, err
		}
		constraint.Columns = columns

		// Expect REFERENCES
		if !p.isType(models.TokenTypeReferences) {
			return nil, p.expectedError("REFERENCES after FOREIGN KEY columns")
		}
		p.advance() // Consume REFERENCES

		// Parse referenced table (supports double-quoted identifiers)
		if !p.isIdentifier() {
			return nil, p.expectedError("table name after REFERENCES")
		}
		refDef := &ast.ReferenceDefinition{
			Table: p.currentToken.Token.Value,
		}
		p.advance()

		// Parse optional referenced column list
		if p.isType(models.TokenTypeLParen) {
			refColumns, err := p.parseConstraintColumnList()
			if err != nil {
				return nil, err
			}
			refDef.Columns = refColumns
		}

		// Parse optional ON DELETE/UPDATE
		refDef.OnDelete, refDef.OnUpdate = p.parseReferentialActions()
		constraint.References = refDef
		constraint.Deferrable = p.parseDeferrableClause()
		return constraint, nil
	}

	// UNIQUE [KEY | INDEX] [index_name] [CLUSTERED] (column_list)
	if p.isType(models.TokenTypeUnique) {
		p.advance() // Consume UNIQUE
		constraint.Type = "UNIQUE"
		p.parseIndexHead(constraint)
		constraint.Cluster = p.parseClusterKeyword()
		if err := p.parseKeyParts(constraint); err != nil {
			return nil, err
		}
		p.parseIndexMethod(constraint)
		constraint.Deferrable = p.parseDeferrableClause()
		return constraint, nil
	}

	// CHECK (expression); ClickHouse also accepts CHECK expression
	if p.isType(models.TokenTypeCheck) {
		p.advance() // Consume CHECK
		constraint.Type = "CHECK"

		if p.dialectTyped == dialect.ClickHouse {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			// The renderer writes CHECK (expr): drop one level of source
			// parentheses so the output does not grow on every pass.
			if paren, ok := expr.(*ast.ParenthesizedExpression); ok && paren.Expr != nil {
				expr = paren.Expr
			}
			constraint.Check = expr
			return constraint, nil
		}

		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after CHECK")
		}
		p.advance() // Consume (

		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		constraint.Check = expr

		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after CHECK expression")
		}
		p.advance() // Consume )
		constraint.Deferrable = p.parseDeferrableClause()
		return constraint, nil
	}

	// ClickHouse: CONSTRAINT name ASSUME expression
	if p.dialectTyped == dialect.ClickHouse && p.isUnquotedWord("ASSUME") {
		p.advance() // Consume ASSUME
		constraint.Type = "ASSUME"
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		constraint.Check = expr
		return constraint, nil
	}

	return nil, p.expectedError("constraint name or constraint type (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK)")
}

// parseIndexMethod consumes an optional USING BTREE | HASH | RTREE.
func (p *Parser) parseIndexMethod(tc *ast.TableConstraint) {
	if !p.isUnquotedWord("USING") || !p.dialectAllows(dialect.MySQL, dialect.MariaDB) {
		return
	}
	next := p.peekToken().Token.Value
	for _, m := range [...]string{"BTREE", "HASH", "RTREE"} {
		if equalsUpper(next, m) {
			p.advance() // Consume USING
			tc.Using = m
			p.advance()
			return
		}
	}
}

// parseIndexHead consumes the optional KEY / INDEX word, the index name and
// the index method that precede the key parts of UNIQUE and MySQL index
// elements.
func (p *Parser) parseIndexHead(tc *ast.TableConstraint) {
	if p.isAnyType(models.TokenTypeKey, models.TokenTypeIndex) && p.dialectAllows(dialect.MySQL, dialect.MariaDB) {
		tc.Keyword = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
	}
	if tc.Keyword != "" && p.isWordToken() && !p.isType(models.TokenTypeLParen) &&
		!p.isUnquotedWord("USING") {
		tc.IndexName = p.currentToken.Token.Value
		p.advance()
	}
	p.parseIndexMethod(tc)
}

// parseKeyParts parses the parenthesised key part list of PRIMARY KEY,
// UNIQUE and the index elements. A part is a column name with an optional
// prefix length and ASC / DESC, or "(expression)" for a functional key part.
func (p *Parser) parseKeyParts(tc *ast.TableConstraint) error {
	if !p.isType(models.TokenTypeLParen) {
		return p.expectedError("( for column list")
	}
	p.advance() // Consume (

	var (
		names      []string
		suffixes   []string
		exprs      []ast.Expression
		functional bool
		anySuffix  bool
	)
	for {
		var (
			name   string
			suffix string
			expr   ast.Expression
		)
		if p.isType(models.TokenTypeLParen) && p.dialectAllows(dialect.MySQL, dialect.MariaDB) {
			p.advance() // Consume (
			e, err := p.parseExpression()
			if err != nil {
				return err
			}
			if !p.isType(models.TokenTypeRParen) {
				return p.expectedError(") after functional key part")
			}
			p.advance() // Consume )
			expr, functional = e, true
		} else {
			if !p.isIdentifier() && !p.isWordToken() {
				return p.expectedError("column name")
			}
			name = p.currentToken.Token.Value
			p.advance()
			if p.isType(models.TokenTypeLParen) && p.peekTypeAt(1) == models.TokenTypeNumber &&
				p.peekTypeAt(2) == models.TokenTypeRParen {
				suffix = "(" + p.peekAt(1).Token.Value + ")"
				p.advance()
				p.advance()
				p.advance()
			}
			if p.isUnquotedWord("ASC") || p.isUnquotedWord("DESC") || p.isType(models.TokenTypeAsc) || p.isType(models.TokenTypeDesc) {
				if suffix != "" {
					suffix += " "
				}
				suffix += strings.ToUpper(p.currentToken.Token.Value)
				p.advance()
			}
			if suffix != "" {
				anySuffix = true
			}
		}
		names = append(names, name)
		suffixes = append(suffixes, suffix)
		exprs = append(exprs, expr)
		if p.isType(models.TokenTypeComma) {
			p.advance()
			continue
		}
		break
	}
	if !p.isType(models.TokenTypeRParen) {
		return p.expectedError(") after column list")
	}
	p.advance() // Consume )

	if !functional {
		tc.Columns = names
		if anySuffix {
			tc.ColumnSuffix = suffixes
		}
		return nil
	}
	// A functional index keeps every part, in order, as an expression: the
	// plain columns as identifiers. A prefix length or sort order on a plain
	// column of such an index has no place to go.
	for i, e := range exprs {
		if e != nil {
			continue
		}
		if suffixes[i] != "" {
			return p.expectedError("a functional key part list without column prefix lengths or sort orders")
		}
		exprs[i] = &ast.Identifier{Name: names[i]}
	}
	tc.Exprs = exprs
	return nil
}

// parseTableElement parses an index element that is not a CONSTRAINT; the
// current token is the one isTableElementStart recognised.
func (p *Parser) parseTableElement(tc *ast.TableConstraint) (*ast.TableConstraint, error) {
	switch {
	case p.isType(models.TokenTypeLike):
		return p.parseLikeElement(tc)

	case p.dialectTyped == dialect.ClickHouse && p.isUnquotedWord("PROJECTION"):
		p.advance() // Consume PROJECTION
		tc.Type = "PROJECTION"
		tc.IndexName = p.currentToken.Token.Value
		p.advance()
		body, err := p.parseTypeArgsString()
		if err != nil {
			return nil, err
		}
		tc.Text = body
		return tc, nil

	case p.dialectTyped == dialect.ClickHouse:
		return p.parseClickHouseIndex(tc)

	case p.isUnquotedWord("FULLTEXT") || p.isUnquotedWord("SPATIAL"):
		tc.Type = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		p.parseIndexHead(tc)
		if tc.Keyword == "" && p.isWordToken() && !p.isType(models.TokenTypeLParen) {
			tc.IndexName = p.currentToken.Token.Value
			p.advance()
		}

	default: // MySQL KEY / INDEX
		tc.Type = strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		p.parseIndexMethod(tc)
		if p.isWordToken() && !p.isType(models.TokenTypeLParen) && !p.isUnquotedWord("USING") {
			tc.IndexName = p.currentToken.Token.Value
			p.advance()
		}
		p.parseIndexMethod(tc)
	}
	if err := p.parseKeyParts(tc); err != nil {
		return nil, err
	}
	p.parseIndexMethod(tc)
	return tc, nil
}

// parseClickHouseIndex parses INDEX name expr TYPE type[(args)] [GRANULARITY n].
func (p *Parser) parseClickHouseIndex(tc *ast.TableConstraint) (*ast.TableConstraint, error) {
	p.advance() // Consume INDEX
	tc.Type = "INDEX"
	if !p.isIdentifier() && !p.isWordToken() {
		return nil, p.expectedError("index name")
	}
	tc.IndexName = p.currentToken.Token.Value
	p.advance()
	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	tc.Exprs = []ast.Expression{expr}
	if !p.isUnquotedWord("TYPE") {
		return nil, p.expectedError("TYPE after index expression")
	}
	p.advance() // Consume TYPE
	if !p.isWordToken() {
		return nil, p.expectedError("index type")
	}
	text := p.currentToken.Token.Value
	p.advance()
	if p.isType(models.TokenTypeLParen) {
		args, err := p.parseTypeArgsString()
		if err != nil {
			return nil, err
		}
		text += args
	}
	tc.Text = text
	if p.isUnquotedWord("GRANULARITY") {
		p.advance() // Consume GRANULARITY
		if !p.isType(models.TokenTypeNumber) {
			return nil, p.expectedError("number after GRANULARITY")
		}
		tc.Granularity = p.currentToken.Token.Value
		p.advance()
	}
	return tc, nil
}

// parseLikeElement parses LIKE source_table [{INCLUDING | EXCLUDING} option]...
func (p *Parser) parseLikeElement(tc *ast.TableConstraint) (*ast.TableConstraint, error) {
	p.advance() // Consume LIKE
	tc.Type = "LIKE"
	var sb strings.Builder
	for {
		if !p.isIdentifier() && !p.isWordToken() {
			return nil, p.expectedError("table name after LIKE")
		}
		sb.WriteString(p.currentToken.Token.Value)
		p.advance()
		if !p.isType(models.TokenTypePeriod) {
			break
		}
		sb.WriteByte('.')
		p.advance()
	}
	tc.LikeTable = sb.String()
	for p.isUnquotedWord("INCLUDING") || p.isUnquotedWord("EXCLUDING") {
		verb := strings.ToUpper(p.currentToken.Token.Value)
		p.advance()
		if !p.isWordToken() {
			return nil, p.expectedError("option after " + verb)
		}
		tc.LikeOptions = append(tc.LikeOptions, verb+" "+strings.ToUpper(p.currentToken.Token.Value))
		p.advance()
	}
	return tc, nil
}
