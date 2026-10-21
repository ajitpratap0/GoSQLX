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

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseCompositeIndirection consumes field selections and array subscripts
// after a parenthesized value: (f(x)).a, (row).*, (row).items[1].name.
// Qualified identifiers keep their existing representation and parse path.
//
// Field selection is gated by Capabilities.SupportsCompositeFieldAccess
// (PostgreSQL, BigQuery, Generic and the default dialect); array subscripts
// are accepted in every dialect, as before field selection existed.
func (p *Parser) parseCompositeIndirection(expr ast.Expression) (ast.Expression, error) {
	fields := 0
	for {
		switch {
		case p.isType(models.TokenTypePeriod):
			if !p.Capabilities().SupportsCompositeFieldAccess {
				return nil, goerrors.UnsupportedFeatureError(
					fmt.Sprintf("composite field access (expr).field is not supported in %s", p.dialect),
					p.currentLocation(), "",
				)
			}
			fields++
			if p.depth+fields > MaxRecursionDepth {
				return nil, goerrors.RecursionDepthLimitError(
					p.depth+fields, MaxRecursionDepth, p.currentLocation(), "",
				)
			}
			pos := p.currentLocation()
			p.advance() // Consume .
			wildcard := p.isType(models.TokenTypeAsterisk) || p.isType(models.TokenTypeMul)
			if !wildcard && !p.isIdentifier() && !p.isFieldLabelWord() {
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

// isFieldLabelWord reports whether the current token is a bare word that may
// name a field after "." in (expr).field. Like PostgreSQL's ColLabel, this
// includes every keyword, reserved ones too: (a).order and (t).select are
// valid, because nothing but a field name can follow the dot. String, number
// and other literal tokens are excluded even when their text looks like a
// word ('abc' arrives with its quotes stripped).
func (p *Parser) isFieldLabelWord() bool {
	t := p.currentToken.Token.Type
	if t == models.TokenTypeNumber || t == models.TokenTypeEOF ||
		(t >= models.TokenRangeStringStart && t < models.TokenRangeStringEnd) {
		return false
	}
	return isBareWord(p.currentToken.Token.Value)
}

// isBareWord reports whether s has the shape of an unquoted SQL word: an
// ASCII letter or '_' followed by ASCII letters, digits or '_'. Keywords are
// ASCII, and a non-ASCII bare identifier already arrives as an identifier
// token, so the ASCII check is sufficient here.
func isBareWord(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_', c|0x20 >= 'a' && c|0x20 <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
