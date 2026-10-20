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
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseCompositeIndirection consumes field selections and array subscripts
// after a parenthesized value: (f(x)).a, (row).*, (row).items[1].name.
// Qualified identifiers keep their existing representation and parse path.
func (p *Parser) parseCompositeIndirection(expr ast.Expression) (ast.Expression, error) {
	fields := 0
	for {
		switch {
		case p.isType(models.TokenTypePeriod):
			fields++
			if p.depth+fields > MaxRecursionDepth {
				return nil, goerrors.RecursionDepthLimitError(
					p.depth+fields, MaxRecursionDepth, p.currentLocation(), "",
				)
			}
			pos := p.currentLocation()
			p.advance() // Consume .
			wildcard := p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul)
			if !wildcard && !p.isIdentifier() && !p.isNonReservedKeyword() {
				return nil, p.expectedError("field name or * after .")
			}
			expr = &ast.FieldAccessExpression{
				Expr: expr, Field: p.currentToken.Token.Value,
				Quoted: p.isType(models.TokenTypeDoubleQuotedString), Pos: pos,
			}
			p.advance()
			if wildcard {
				if p.isType(models.TokenTypePeriod) || p.isType(models.TokenTypeLBracket) {
					return nil, p.expectedError("end of field selection after *")
				}
				return expr, nil
			}
		case p.isType(models.TokenTypeLBracket):
			var err error
			expr, err = p.parseArrayAccessExpression(expr)
			if err != nil {
				return nil, err
			}
		default:
			return expr, nil
		}
	}
}
