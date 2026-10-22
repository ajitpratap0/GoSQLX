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
)

// parseMatchAgainst parses MySQL MATCH(...) AGAINST('text' [IN NATURAL LANGUAGE MODE | IN BOOLEAN MODE | WITH QUERY EXPANSION])
// into an *ast.MatchAgainstExpression. matchFunc holds the already parsed
// MATCH(col, ...) column list; the current token is AGAINST.
func (p *Parser) parseMatchAgainst(matchFunc *ast.FunctionCall) (ast.Expression, error) {
	p.advance() // Consume AGAINST
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse the search expression below the comparison level so that the
	// IN of IN BOOLEAN MODE is not read as an IN predicate.
	searchExpr, err := p.parseStringConcatExpression()
	if err != nil {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("failed to parse AGAINST expression: %v", err),
			p.currentLocation(),
			"",
		).WithCause(err)
	}

	// Optional search modifier words up to the closing parenthesis.
	var words []string
	for !p.isType(models.TokenTypeRParen) && !p.isType(models.TokenTypeEOF) {
		if p.currentToken.Token.Quote != 0 || !isBareWord(p.currentToken.Token.Value) {
			return nil, p.expectedError("search modifier or )")
		}
		words = append(words, strings.ToUpper(p.currentToken.Token.Value))
		p.advance()
	}
	modifier := strings.Join(words, " ")
	if modifier != "" && ast.MatchModifierText(modifier) == "" {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("unknown MATCH ... AGAINST search modifier %q", modifier),
			p.currentLocation(),
			"",
		).WithHint("Use IN NATURAL LANGUAGE MODE, IN BOOLEAN MODE or WITH QUERY EXPANSION")
	}

	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return &ast.MatchAgainstExpression{
		Columns:  matchFunc.Arguments,
		Query:    searchExpr,
		Modifier: modifier,
		Pos:      matchFunc.Pos,
	}, nil
}

// parseShowStatement parses MySQL SHOW commands:
//   - SHOW TABLES
//   - SHOW DATABASES
//   - SHOW CREATE TABLE name
//   - SHOW COLUMNS FROM name
//   - SHOW INDEX FROM name
func (p *Parser) parseShowStatement() (ast.Statement, error) {
	show := ast.GetShowStatement()

	upper := strings.ToUpper(p.currentToken.Token.Value)

	switch upper {
	case "TABLES":
		show.ShowType = "TABLES"
		p.advance()
		// Optional FROM database
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			show.From = p.currentToken.Token.Value
			p.advance()
		}
	case "DATABASES":
		show.ShowType = "DATABASES"
		p.advance()
	case "CREATE":
		p.advance() // Consume CREATE
		if p.isType(models.TokenTypeTable) {
			show.ShowType = "CREATE TABLE"
			p.advance() // Consume TABLE
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.qualifiedNameError(err, "table name")
			}
			show.ObjectName = name
		} else {
			show.ShowType = "CREATE " + strings.ToUpper(p.currentToken.Token.Value)
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.qualifiedNameError(err, "object name")
			}
			show.ObjectName = name
		}
	case "COLUMNS":
		show.ShowType = "COLUMNS"
		p.advance()
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.qualifiedNameError(err, "table name")
			}
			show.ObjectName = name
		}
	case "INDEX", "INDEXES", "KEYS":
		show.ShowType = upper
		p.advance()
		if p.isType(models.TokenTypeFrom) {
			p.advance()
			name, err := p.parseQualifiedName()
			if err != nil {
				return nil, p.qualifiedNameError(err, "table name")
			}
			show.ObjectName = name
		}
	case "STATUS", "VARIABLES":
		show.ShowType = upper
		p.advance()
	default:
		// Generic: SHOW <whatever>
		show.ShowType = upper
		p.advance()
	}

	return show, nil
}

// parseDescribeStatement parses DESCRIBE/DESC/EXPLAIN. When a statement
// follows (optionally after options such as ANALYZE, "(FORMAT JSON)",
// "QUERY PLAN" or "PLAN FOR") it returns an ExplainStatement wrapping it;
// otherwise it parses DESCRIBE [object kind] table_name.
func (p *Parser) parseDescribeStatement(keyword string) (ast.Statement, error) {
	if n := p.explainOptionTokens(); n >= 0 {
		explain := &ast.ExplainStatement{Keyword: keyword}
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, explainTokenText(p.currentToken.Token))
			p.advance()
		}
		explain.Options = joinExplainOptions(parts)
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		explain.Statement = stmt
		return explain, nil
	}

	// Snowflake: DESCRIBE TABLE <name>, DESCRIBE VIEW <name>, DESCRIBE STAGE
	// <name>, etc. Also MySQL's DESCRIBE <db>.<table>. Accept and consume a
	// leading object-kind keyword (TABLE, VIEW, DATABASE, SCHEMA) before the
	// name so we don't fail on "DESCRIBE TABLE users".
	if p.isType(models.TokenTypeTable) || p.isType(models.TokenTypeView) ||
		p.isType(models.TokenTypeDatabase) ||
		strings.EqualFold(p.currentToken.Token.Value, "SCHEMA") ||
		strings.EqualFold(p.currentToken.Token.Value, "STAGE") ||
		strings.EqualFold(p.currentToken.Token.Value, "STREAM") ||
		strings.EqualFold(p.currentToken.Token.Value, "TASK") ||
		strings.EqualFold(p.currentToken.Token.Value, "PIPE") ||
		strings.EqualFold(p.currentToken.Token.Value, "FUNCTION") ||
		strings.EqualFold(p.currentToken.Token.Value, "PROCEDURE") ||
		strings.EqualFold(p.currentToken.Token.Value, "WAREHOUSE") {
		p.advance()
	}

	name, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}
	desc := ast.GetDescribeStatement()
	desc.TableName = name
	return desc, nil
}

// maxExplainOptionTokens bounds the lookahead for an explained statement.
const maxExplainOptionTokens = 64

// explainOptionTokens reports how many option tokens sit between EXPLAIN /
// DESCRIBE and the statement being explained, or -1 if no statement follows
// (DESCRIBE table_name). Parenthesised option lists are skipped as a unit.
func (p *Parser) explainOptionTokens() int {
	depth := 0
	for i := 0; i < maxExplainOptionTokens && p.currentPos+i < len(p.tokens); i++ {
		switch p.tokens[p.currentPos+i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return -1
		case models.TokenTypeSelect, models.TokenTypeWith, models.TokenTypeInsert,
			models.TokenTypeUpdate, models.TokenTypeDelete, models.TokenTypeMerge,
			models.TokenTypeReplace:
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// explainTokenText renders an EXPLAIN option token back to SQL text; option
// words are keywords, so they are upper-cased.
func explainTokenText(tok models.Token) string {
	switch tok.Type {
	case models.TokenTypeSingleQuotedString, models.TokenTypeString:
		return "'" + strings.ReplaceAll(tok.Value, "'", "''") + "'"
	}
	return strings.ToUpper(tok.Value)
}

// joinExplainOptions joins option tokens with single spaces, except inside
// parentheses and before commas: "(FORMAT JSON, ANALYZE)".
func joinExplainOptions(parts []string) string {
	var sb strings.Builder
	for i, part := range parts {
		if i > 0 && part != ")" && part != "," && parts[i-1] != "(" {
			sb.WriteByte(' ')
		}
		sb.WriteString(part)
	}
	return sb.String()
}

// parseReplaceStatement parses MySQL REPLACE INTO statement
func (p *Parser) parseReplaceStatement() (ast.Statement, error) {
	// Expect INTO
	if !p.isType(models.TokenTypeInto) {
		return nil, p.expectedError("INTO")
	}
	p.advance()

	// Parse table name
	tableName, err := p.parseQualifiedName()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}

	// Parse column list if present
	columns := make([]ast.Expression, 0)
	if p.isType(models.TokenTypeLParen) {
		p.advance()
		for {
			if !p.isIdentifier() {
				return nil, p.expectedError("column name")
			}
			columns = append(columns, &ast.Identifier{Name: p.currentToken.Token.Value})
			p.advance()
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
	}

	// Parse VALUES
	if !p.isType(models.TokenTypeValues) {
		return nil, p.expectedError("VALUES")
	}
	p.advance()

	values := make([][]ast.Expression, 0)
	for {
		if !p.isType(models.TokenTypeLParen) {
			if len(values) == 0 {
				return nil, p.expectedError("(")
			}
			break
		}
		p.advance()

		row := make([]ast.Expression, 0)
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, goerrors.InvalidSyntaxError(
					fmt.Sprintf("failed to parse value in REPLACE: %v", err),
					p.currentLocation(),
					"",
				).WithCause(err)
			}
			row = append(row, expr)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
		values = append(values, row)

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}

	replStmt := ast.GetReplaceStatement()
	replStmt.TableName = tableName
	replStmt.Columns = append(replStmt.Columns, columns...)
	replStmt.Values = append(replStmt.Values, values...)
	return replStmt, nil
}
