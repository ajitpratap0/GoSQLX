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

// Package parser - window.go
// Window function parsing for the SQL parser.
// Includes OVER clause, PARTITION BY, ORDER BY, and frame specifications.

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// SUM(salary) OVER (PARTITION BY dept ORDER BY date ROWS UNBOUNDED PRECEDING) -> window function with frame
func (p *Parser) parseFunctionCall(funcName string) (*ast.FunctionCall, error) {
	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse function arguments
	var arguments []ast.Expression
	var distinct bool
	var distinctPos models.Location

	// Check for DISTINCT keyword
	if p.isType(models.TokenTypeDistinct) {
		distinct = true
		distinctPos = p.currentLocation()
		p.advance()
	}

	// Parse arguments if not empty
	var separator *ast.LiteralValue
	if form := specialFormOf(funcName); form != formNone && !p.isType(models.TokenTypeRParen) {
		// Keyword-introduced arguments: SUBSTRING(s FROM 1 FOR 2), TRIM(BOTH ' ' FROM s), ...
		args, err := p.parseSpecialFormArgs(form)
		if err != nil {
			return nil, err
		}
		arguments = args
	} else if !p.isType(models.TokenTypeRParen) {
		// A few functions take arguments with their own syntax (CURSOR(SELECT
		// ...), JSON_OBJECT(k VALUE v), XMLTABLE(... COLUMNS ...)); every other
		// call skips those checks.
		quirky := hasQuirkyArgs(funcName)
		for !p.isType(models.TokenTypeOrder) {
			// Named argument form: `name => expr` (Snowflake FLATTEN,
			// BigQuery, Oracle, PostgreSQL procedural calls). Detect by a
			// bare identifier or keyword (FLATTEN's outer => / recursive =>)
			// immediately followed by =>.
			if (p.isIdentifier() || p.isWordToken()) &&
				p.peekToken().Token.Type == models.TokenTypeRArrow {
				namePos := p.currentLocation()
				argName := p.currentToken.Token.Value
				p.advance() // name
				p.advance() // =>
				value, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				arguments = append(arguments, &ast.NamedArgument{
					Name:  argName,
					Value: value,
					Pos:   namePos,
				})
				if p.isType(models.TokenTypeComma) {
					p.advance()
					continue
				}
				if p.isType(models.TokenTypeRParen) {
					break
				}
				return nil, p.expectedError(", or )")
			}

			var arg ast.Expression
			var err error
			if quirky && p.isBareSubqueryArg(funcName) {
				// Oracle CURSOR(SELECT ...) / MULTISET(SELECT ...): the query is
				// the argument, with no parentheses of its own.
				pos := p.currentLocation()
				sub, err := p.parseSubquery()
				if err != nil {
					return nil, err
				}
				arguments = append(arguments, &ast.SubqueryExpression{Subquery: sub, Pos: pos, Bare: true})
				if p.isType(models.TokenTypeRParen) {
					break
				}
				return nil, p.expectedError(")")
			}
			if quirky && p.isJSONObjectFunc(funcName) {
				if arg, err = p.parseJSONObjectArg(); err != nil {
					return nil, err
				}
			} else if quirky && p.isOpenRowsetBulk(funcName) {
				// SQL Server OPENROWSET(BULK 'path', options): BULK introduces
				// the file name.
				ka := &ast.KeywordArgument{Keyword: "BULK", Pos: p.currentLocation()}
				p.advance() // Consume BULK
				if ka.Value, err = p.parseExpression(); err != nil {
					return nil, err
				}
				arg = ka
			} else if arg, err = p.parseExpression(); err != nil {
				return nil, err
			}
			if quirky && p.isType(models.TokenTypeAs) && isXMLNamedArgFunc(funcName) {
				// XMLATTRIBUTES(col AS "name") / XMLFOREST(col AS name)
				p.advance() // Consume AS
				if !p.isAliasAfterAS() {
					return nil, p.expectedError("name after AS")
				}
				arg = &ast.AliasedExpression{Expr: arg, Alias: p.currentToken.Token.Value, AliasQuote: p.currentNameQuote()}
				p.advance()
			}
			arguments = append(arguments, arg)

			// Check for comma or end of arguments
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else if p.isType(models.TokenTypeRParen) || p.isType(models.TokenTypeOrder) {
				break
			} else if p.isWord("SEPARATOR") {
				// MySQL GROUP_CONCAT SEPARATOR clause; parsed below.
				break
			} else if quirky && p.isClauseArgument(funcName) {
				// JSON_TABLE(doc, path COLUMNS (...)), XMLTABLE(xpath PASSING x
				// COLUMNS ...): the argument and its clause words are one
				// argument.
				last, err := p.parseClauseArgument(funcName, arg)
				if err != nil {
					return nil, err
				}
				arguments[len(arguments)-1] = last
				break
			} else {
				return nil, p.expectedError(", or )")
			}
		}
	}

	// Parse ORDER BY clause inside aggregate functions (STRING_AGG, ARRAY_AGG, etc.)
	// Syntax: STRING_AGG(name, ', ' ORDER BY name ASC)
	var orderByExprs []ast.OrderByExpression
	if p.isType(models.TokenTypeOrder) {
		p.advance() // Consume ORDER

		// Expect BY keyword
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after ORDER")
		}
		p.advance() // Consume BY

		// Parse order expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create OrderByExpression with defaults
			orderByExpr := ast.OrderByExpression{
				Expression: expr,
				Ascending:  true, // Default to ASC
				NullsFirst: nil,  // Default behavior (database-specific)
			}

			// Check for ASC/DESC after the expression
			if p.isType(models.TokenTypeAsc) {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.isType(models.TokenTypeDesc) {
				orderByExpr.Ascending = false
				p.advance() // Consume DESC
			}

			// Check for NULLS FIRST/LAST
			nullsFirst, err := p.parseNullsClause()
			if err != nil {
				return nil, err
			}
			orderByExpr.NullsFirst = nullsFirst

			orderByExprs = append(orderByExprs, orderByExpr)

			// Check for comma (multiple order columns) or end
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else if p.isType(models.TokenTypeRParen) {
				break
			} else if p.isWord("SEPARATOR") {
				break // Let SEPARATOR be handled below
			} else {
				return nil, p.expectedError(", or )")
			}
		}
	}

	// Handle MySQL SEPARATOR clause (GROUP_CONCAT). It is kept apart from the
	// arguments: GROUP_CONCAT(a SEPARATOR '|') is not GROUP_CONCAT(a, '|').
	if p.isWord("SEPARATOR") {
		p.advance() // Consume SEPARATOR
		sep, err := p.parseSeparatorLiteral()
		if err != nil {
			return nil, err
		}
		separator = sep
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Create function call
	funcCall := &ast.FunctionCall{
		Name:      funcName,
		Arguments: arguments,
		Distinct:  distinct,
		OrderBy:   orderByExprs,
	}
	if separator != nil {
		funcCall.EnsureExtras().Separator = separator
	}

	// ClickHouse parametric aggregates: funcName(params)(args).
	// e.g. quantileTDigest(0.95)(value), topK(10)(name).
	// What we just parsed becomes Parameters; the next paren group is the
	// real arguments. Gated to ClickHouse to avoid false positives.
	// DISTINCT belongs to the argument group only: fn(p)(DISTINCT a) (#605).
	if p.dialect == string(keywords.DialectClickHouse) && p.isType(models.TokenTypeLParen) {
		if err := p.parseClickHouseParametricArgs(funcCall, distinctPos); err != nil {
			return nil, err
		}
	}

	// Oracle KEEP (DENSE_RANK FIRST|LAST ORDER BY ...) aggregate modifier.
	if p.isKeepClause() {
		keep, err := p.parseKeepClause()
		if err != nil {
			return nil, err
		}
		funcCall.EnsureExtras().Keep = keep
	}

	// Check for IGNORE NULLS / RESPECT NULLS (SQL:2016 null treatment).
	// Used by LAG, LEAD, FIRST_VALUE, LAST_VALUE, NTH_VALUE in Snowflake,
	// Oracle, BigQuery, etc. IGNORE arrives as TokenTypeKeyword; RESPECT is
	// not in any keyword list and arrives as TokenTypeIdentifier. NULLS has
	// its own token type.
	if p.currentToken.Token.Type == models.TokenTypeKeyword ||
		p.currentToken.Token.Type == models.TokenTypeIdentifier {
		upper := strings.ToUpper(p.currentToken.Token.Value)
		if (upper == "IGNORE" || upper == "RESPECT") &&
			p.peekToken().Token.Type == models.TokenTypeNulls {
			funcCall.NullTreatment = upper + " NULLS"
			p.advance() // IGNORE / RESPECT
			p.advance() // NULLS
		}
	}

	// Check for WITHIN GROUP clause (SQL:2003 ordered-set aggregates)
	// Syntax: WITHIN GROUP (ORDER BY expression [ASC|DESC] [NULLS FIRST|LAST])
	// Used with: PERCENTILE_CONT, PERCENTILE_DISC, MODE, LISTAGG, etc.
	if p.isType(models.TokenTypeWithin) {
		p.advance() // Consume WITHIN

		// Expect GROUP keyword
		if !p.isType(models.TokenTypeGroup) {
			return nil, p.expectedError("GROUP after WITHIN")
		}
		p.advance() // Consume GROUP

		// Expect opening parenthesis
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after WITHIN GROUP")
		}
		p.advance() // Consume (

		// Expect ORDER BY clause
		if !p.isType(models.TokenTypeOrder) {
			return nil, p.expectedError("ORDER BY in WITHIN GROUP")
		}
		p.advance() // Consume ORDER

		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after ORDER")
		}
		p.advance() // Consume BY

		// Parse order expressions
		var withinGroupOrderBy []ast.OrderByExpression
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create OrderByExpression with defaults
			orderByExpr := ast.OrderByExpression{
				Expression: expr,
				Ascending:  true, // Default to ASC
				NullsFirst: nil,  // Default behavior (database-specific)
			}

			// Check for ASC/DESC after the expression
			if p.isType(models.TokenTypeAsc) {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.isType(models.TokenTypeDesc) {
				orderByExpr.Ascending = false
				p.advance() // Consume DESC
			}

			// Check for NULLS FIRST/LAST
			nullsFirst, err := p.parseNullsClause()
			if err != nil {
				return nil, err
			}
			orderByExpr.NullsFirst = nullsFirst

			withinGroupOrderBy = append(withinGroupOrderBy, orderByExpr)

			// Check for comma (multiple order columns) or end
			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else if p.isType(models.TokenTypeRParen) {
				break
			} else {
				return nil, p.expectedError(", or )")
			}
		}

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after WITHIN GROUP ORDER BY")
		}
		p.advance() // Consume )

		funcCall.WithinGroup = withinGroupOrderBy
	}

	// Check for FILTER clause (SQL:2003 T612)
	// Syntax: FILTER (WHERE condition)
	if p.isType(models.TokenTypeFilter) {
		p.advance() // Consume FILTER

		// Expect opening parenthesis
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("( after FILTER")
		}
		p.advance() // Consume (

		// Expect WHERE keyword
		if !p.isType(models.TokenTypeWhere) {
			return nil, p.expectedError("WHERE after FILTER (")
		}
		p.advance() // Consume WHERE

		// Parse filter condition expression
		filterExpr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		funcCall.Filter = filterExpr

		// Expect closing parenthesis
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(") after FILTER condition")
		}
		p.advance() // Consume )
	}

	// Check for OVER clause (window function)
	if p.isType(models.TokenTypeOver) {
		p.advance() // Consume OVER

		windowSpec, err := p.parseWindowSpec()
		if err != nil {
			return nil, err
		}
		funcCall.Over = windowSpec
	}

	return funcCall, nil
}

// parseWindowSpec parses a window specification (PARTITION BY, ORDER BY, frame clause).
// Supports both inline specs OVER (...) and named window references OVER w (SQL:2003 §7.11).
func (p *Parser) parseWindowSpec() (*ast.WindowSpec, error) {
	// Named window reference: OVER w - bare identifier, no parentheses.
	// This must be checked before the '(' path so that e.g. OVER w is not
	// mistakenly rejected.
	if p.isIdentifier() {
		spec := &ast.WindowSpec{Name: p.currentToken.Token.Value, NameQuote: p.currentNameQuote()}
		p.advance()
		return spec, nil
	}

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	windowSpec := &ast.WindowSpec{}

	// Existing window name refined by this spec: OVER (w ORDER BY z)
	// (SQL:2003 §7.11 <existing window name>). PARTITION, ORDER, ROWS and RANGE
	// have dedicated token types, so a leading identifier can only be a name.
	if p.isIdentifier() {
		windowSpec.BaseWindow = p.currentToken.Token.Value
		windowSpec.BaseWindowQuote = p.currentNameQuote()
		p.advance()
	}

	// Parse PARTITION BY clause
	if p.isType(models.TokenTypePartition) {
		p.advance() // Consume PARTITION
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after PARTITION")
		}
		p.advance() // Consume BY

		// Parse partition expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			windowSpec.PartitionBy = append(windowSpec.PartitionBy, expr)

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse ORDER BY clause
	if p.isType(models.TokenTypeOrder) {
		p.advance() // Consume ORDER
		if !p.isType(models.TokenTypeBy) {
			return nil, p.expectedError("BY after ORDER")
		}
		p.advance() // Consume BY

		// Parse order expressions
		for {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}

			// Create OrderByExpression with defaults
			orderByExpr := ast.OrderByExpression{
				Expression: expr,
				Ascending:  true, // Default to ASC
				NullsFirst: nil,  // Default behavior (database-specific)
			}

			// Check for ASC/DESC after the expression
			if p.isType(models.TokenTypeAsc) {
				orderByExpr.Ascending = true
				p.advance() // Consume ASC
			} else if p.isType(models.TokenTypeDesc) {
				orderByExpr.Ascending = false
				p.advance() // Consume DESC
			}

			// Check for NULLS FIRST/LAST
			nullsFirst, err := p.parseNullsClause()
			if err != nil {
				return nil, err
			}
			orderByExpr.NullsFirst = nullsFirst

			windowSpec.OrderBy = append(windowSpec.OrderBy, orderByExpr)

			if p.isType(models.TokenTypeComma) {
				p.advance() // Consume comma
			} else {
				break
			}
		}
	}

	// Parse frame clause (ROWS/RANGE/GROUPS with bounds)
	if p.isAnyType(models.TokenTypeRows, models.TokenTypeRange, models.TokenTypeGroups) {
		frameType := p.currentToken.Token.Value
		p.advance() // Consume ROWS/RANGE/GROUPS

		frameClause, err := p.parseWindowFrame(frameType)
		if err != nil {
			return nil, err
		}
		windowSpec.FrameClause = frameClause
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	return windowSpec, nil
}

// parseWindowFrame parses a window frame clause
func (p *Parser) parseWindowFrame(frameType string) (*ast.WindowFrame, error) {
	frame := &ast.WindowFrame{
		Type: frameType,
	}

	// Parse frame bounds
	if p.isType(models.TokenTypeBetween) {
		p.advance() // Consume BETWEEN

		// Parse start bound
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound

		// Expect AND
		if !p.isType(models.TokenTypeAnd) {
			return nil, p.expectedError("AND")
		}
		p.advance() // Consume AND

		// Parse end bound
		endBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.End = endBound
	} else {
		// Single bound (implies CURRENT ROW as end)
		startBound, err := p.parseFrameBound()
		if err != nil {
			return nil, err
		}
		frame.Start = *startBound
		// End is nil for single bound
	}

	// Optional frame exclusion (SQL:2011)
	if p.isType(models.TokenTypeExclude) {
		excl, err := p.parseFrameExclusion()
		if err != nil {
			return nil, err
		}
		frame.Exclude = excl
	}

	return frame, nil
}

// parseFrameExclusion parses the SQL:2011 frame exclusion that may follow the
// frame bounds and returns its canonical upper-case text:
//
//	EXCLUDE CURRENT ROW | EXCLUDE GROUP | EXCLUDE TIES | EXCLUDE NO OTHERS
//
// The current token must be EXCLUDE.
func (p *Parser) parseFrameExclusion() (string, error) {
	p.advance() // Consume EXCLUDE

	switch {
	case p.isType(models.TokenTypeCurrent):
		p.advance() // Consume CURRENT
		if !p.isType(models.TokenTypeRow) {
			return "", p.expectedError("ROW after EXCLUDE CURRENT")
		}
		p.advance() // Consume ROW
		return "CURRENT ROW", nil
	case p.isType(models.TokenTypeGroup):
		p.advance() // Consume GROUP
		return "GROUP", nil
	case p.isType(models.TokenTypeTies):
		p.advance() // Consume TIES
		return "TIES", nil
	case p.isType(models.TokenTypeIdentifier) && equalsUpper(p.currentToken.Token.Value, "NO"):
		p.advance() // Consume NO
		if !p.isType(models.TokenTypeIdentifier) || !equalsUpper(p.currentToken.Token.Value, "OTHERS") {
			return "", p.expectedError("OTHERS after EXCLUDE NO")
		}
		p.advance() // Consume OTHERS
		return "NO OTHERS", nil
	default:
		return "", p.expectedError("CURRENT ROW, GROUP, TIES or NO OTHERS after EXCLUDE")
	}
}

// parseFrameBound parses a window frame bound
func (p *Parser) parseFrameBound() (*ast.WindowFrameBound, error) {
	bound := &ast.WindowFrameBound{}

	if p.isType(models.TokenTypeUnbounded) {
		p.advance() // Consume UNBOUNDED
		if p.isType(models.TokenTypePreceding) {
			bound.Type = "UNBOUNDED PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.isType(models.TokenTypeFollowing) {
			bound.Type = "UNBOUNDED FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after UNBOUNDED")
		}
	} else if p.isType(models.TokenTypeCurrent) {
		p.advance() // Consume CURRENT
		if !p.isType(models.TokenTypeRow) {
			return nil, p.expectedError("ROW after CURRENT")
		}
		bound.Type = "CURRENT ROW"
		p.advance() // Consume ROW
	} else {
		// Numeric bound
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		bound.Value = expr

		if p.isType(models.TokenTypePreceding) {
			bound.Type = "PRECEDING"
			p.advance() // Consume PRECEDING
		} else if p.isType(models.TokenTypeFollowing) {
			bound.Type = "FOLLOWING"
			p.advance() // Consume FOLLOWING
		} else {
			return nil, p.expectedError("PRECEDING or FOLLOWING after numeric value")
		}
	}

	return bound, nil
}

// parseNullsClause parses the optional NULLS FIRST/LAST clause in ORDER BY expressions.
// Returns a pointer to bool indicating null ordering: true for NULLS FIRST, false for NULLS LAST, nil if not specified.
func (p *Parser) parseNullsClause() (*bool, error) {
	if p.isType(models.TokenTypeNulls) {
		p.advance() // Consume NULLS
		if p.isType(models.TokenTypeFirst) {
			t := true
			p.advance() // Consume FIRST
			return &t, nil
		} else if p.isType(models.TokenTypeLast) {
			f := false
			p.advance() // Consume LAST
			return &f, nil
		} else {
			return nil, p.expectedError("FIRST or LAST after NULLS")
		}
	}
	return nil, nil
}

// parseGroupingExpressionList parses a parenthesized, comma-separated list of expressions

// isOpenRowsetBulk reports whether the current tokens are the BULK 'file' that
// starts the arguments of a SQL Server OPENROWSET call named funcName.
func (p *Parser) isOpenRowsetBulk(funcName string) bool {
	if !p.IsSQLServer() || !p.isUnquotedWord("BULK") || !equalsUpper(funcName, "OPENROWSET") {
		return false
	}
	t := p.peekToken().Token.Type
	return t == models.TokenTypeString || t == models.TokenTypeSingleQuotedString
}

// isBareSubqueryArg reports whether the current token starts the query that
// is the argument of an Oracle CURSOR(...) or MULTISET(...) call.
func (p *Parser) isBareSubqueryArg(funcName string) bool {
	if !p.IsOracle() || !p.isAnyType(models.TokenTypeSelect, models.TokenTypeWith) {
		return false
	}
	return equalsUpper(funcName, "CURSOR") || equalsUpper(funcName, "MULTISET")
}

// isJSONObjectFunc reports whether funcName is a JSON_OBJECT / JSON_OBJECTAGG
// call whose arguments may use the KEY ... VALUE ... and name: value forms.
func (p *Parser) isJSONObjectFunc(funcName string) bool {
	if !p.dialectAllows(dialect.Oracle, dialect.SQLServer, dialect.PostgreSQL) {
		return false
	}
	return equalsUpper(funcName, "JSON_OBJECT") || equalsUpper(funcName, "JSON_OBJECTAGG")
}

// parseJSONObjectArg parses one argument of JSON_OBJECT: a plain expression,
// or a pair written [KEY] name VALUE value or name : value.
func (p *Parser) parseJSONObjectArg() (ast.Expression, error) {
	pos := p.currentLocation()
	keyword := false
	if p.isUnquotedWord("KEY") {
		switch p.peekToken().Token.Type {
		case models.TokenTypeComma, models.TokenTypeRParen, models.TokenTypeColon, models.TokenTypePeriod, models.TokenTypeLParen:
		default:
			keyword = !p.peekValueIs(1, "VALUE")
		}
	}
	if keyword {
		p.advance() // Consume KEY
	}
	key, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	colon := false
	switch {
	case p.isUnquotedWord("VALUE"):
		p.advance() // Consume VALUE
	case p.isType(models.TokenTypeColon):
		colon = true
		p.advance() // Consume :
	default:
		if keyword {
			return nil, p.expectedError("VALUE or : after the JSON_OBJECT key")
		}
		return key, nil
	}
	value, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	return &ast.JSONObjectEntry{Key: key, Value: value, KeyKeyword: keyword, Colon: colon, Pos: pos}, nil
}

// isXMLNamedArgFunc reports whether funcName is an SQL/XML constructor whose
// arguments are named with AS: XMLATTRIBUTES(a AS "x"), XMLFOREST(a AS x).
func isXMLNamedArgFunc(funcName string) bool {
	return equalsUpper(funcName, "XMLATTRIBUTES") || equalsUpper(funcName, "XMLFOREST")
}

// hasQuirkyArgs reports whether funcName is one of the functions whose
// arguments have syntax of their own: CURSOR, MULTISET, XMLTABLE, XMLFOREST,
// OPENROWSET, JSON_TABLE, JSON_OBJECT, XMLATTRIBUTES and JSON_OBJECTAGG. It
// looks at the name length first so ordinary calls pay almost nothing.
func hasQuirkyArgs(funcName string) bool {
	switch len(funcName) {
	case 6:
		return equalsUpper(funcName, "CURSOR")
	case 8:
		return equalsUpper(funcName, "MULTISET") || equalsUpper(funcName, "XMLTABLE")
	case 9:
		return equalsUpper(funcName, "XMLFOREST")
	case 10:
		return equalsUpper(funcName, "OPENROWSET") || equalsUpper(funcName, "JSON_TABLE")
	case 11:
		return equalsUpper(funcName, "JSON_OBJECT")
	case 13:
		return equalsUpper(funcName, "XMLATTRIBUTES")
	case 14:
		return equalsUpper(funcName, "JSON_OBJECTAGG")
	}
	return false
}
