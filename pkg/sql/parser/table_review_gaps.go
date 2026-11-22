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
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func (p *Parser) parsePivotDefault(clause *ast.PivotClause) error {
	if !p.IsSnowflake() || !p.isType(models.TokenTypeDefault) {
		return nil
	}
	p.advance()
	if !p.isType(models.TokenTypeOn) {
		return p.expectedError("ON after DEFAULT")
	}
	p.advance()
	if !p.isType(models.TokenTypeNull) {
		return p.expectedError("NULL after DEFAULT ON")
	}
	p.advance()
	if !p.isType(models.TokenTypeLParen) {
		return p.expectedError("( after DEFAULT ON NULL")
	}
	p.advance()
	value, err := p.parseExpression()
	if err != nil {
		return err
	}
	clause.DefaultOnNull = value
	if !p.isType(models.TokenTypeRParen) {
		return p.expectedError(") after DEFAULT ON NULL expression")
	}
	p.advance()
	return nil
}

func (p *Parser) isRowsFromStart() bool {
	return p.IsPostgreSQL() && p.isType(models.TokenTypeRows) && p.peekToken().Token.Type == models.TokenTypeFrom
}

func (p *Parser) parseRowsFrom() (ast.TableReference, error) {
	ref := ast.TableReference{Modifiers: &ast.TableModifiers{}}
	p.advance()
	p.advance() // ROWS FROM
	if !p.isType(models.TokenTypeLParen) {
		return ref, p.expectedError("( after ROWS FROM")
	}
	p.advance()
	for {
		name, quote, err := p.parseTableNameQuoted()
		if err != nil {
			return ref, err
		}
		if !p.isType(models.TokenTypeLParen) {
			return ref, p.expectedError("function call in ROWS FROM")
		}
		function, err := p.parseFunctionCall(name)
		if err != nil {
			return ref, err
		}
		function.NameQuote = quote
		item := ast.RowsFromItem{Function: function}
		if p.isType(models.TokenTypeAs) {
			p.advance()
			if !p.isType(models.TokenTypeLParen) {
				return ref, p.expectedError("column definitions after AS in ROWS FROM")
			}
			temp := ast.TableReference{TableFunc: function}
			if err := p.parseTableColumnAliases(&temp); err != nil {
				return ref, err
			}
			if temp.ColumnAliases == nil || len(temp.ColumnAliases.Types) != len(temp.ColumnAliases.Names) {
				return ref, p.expectedError("typed column definitions in ROWS FROM")
			}
			for _, typ := range temp.ColumnAliases.Types {
				if typ == "" {
					return ref, p.expectedError("column type in ROWS FROM")
				}
			}
			item.Columns = temp.ColumnAliases
		}
		ref.Modifiers.RowsFrom = append(ref.Modifiers.RowsFrom, item)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return ref, p.expectedError(") after ROWS FROM")
	}
	p.advance()
	if p.isType(models.TokenTypeWith) && strings.EqualFold(p.peekToken().Token.Value, "ORDINALITY") && p.peekToken().Token.Quote == 0 && (p.peekToken().Token.Word == nil || p.peekToken().Token.Word.QuoteStyle == 0) {
		p.advance()
		p.advance()
		ref.WithOrdinality = true
	}
	return ref, nil
}
