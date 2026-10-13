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

// parseClickHouseParametricArgs parses the argument group of a ClickHouse
// parametric aggregate, fn(params)(args), e.g. quantile(0.5)(x) or
// topK(10)(name). On entry funcCall holds the first paren group, which becomes
// Parameters, and the current token is the second '('.
//
// DISTINCT and ORDER BY are only valid in the argument group: ClickHouse
// writes quantile(0.5)(DISTINCT x), and FunctionCall.Distinct then applies
// to Arguments. A DISTINCT or ORDER BY parsed in the parameter group is
// rejected rather than silently moved to the arguments, and a third paren
// group is rejected because ClickHouse allows at most two (#605).
func (p *Parser) parseClickHouseParametricArgs(funcCall *ast.FunctionCall, distinctPos models.Location) error {
	if funcCall.Distinct {
		return goerrors.InvalidSyntaxError(fmt.Sprintf(
			"DISTINCT is not allowed in the parameter list of ClickHouse parametric function %s; write %s(params)(DISTINCT args)",
			funcCall.Name, funcCall.Name), distinctPos, "")
	}
	if len(funcCall.OrderBy) > 0 {
		return goerrors.InvalidSyntaxError(fmt.Sprintf(
			"ORDER BY is not allowed in the parameter list of ClickHouse parametric function %s", funcCall.Name),
			p.currentLocation(), "")
	}
	funcCall.Parameters = funcCall.Arguments
	funcCall.Arguments = nil
	p.advance() // Consume second (
	if p.isType(models.TokenTypeDistinct) {
		funcCall.Distinct = true
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		for {
			arg, err := p.parseExpression()
			if err != nil {
				return err
			}
			funcCall.Arguments = append(funcCall.Arguments, arg)
			if p.isType(models.TokenTypeComma) {
				p.advance()
			} else if p.isType(models.TokenTypeRParen) {
				break
			} else {
				return p.expectedError(", or )")
			}
		}
	} else if funcCall.Distinct {
		return p.expectedError("expression after DISTINCT")
	}
	if !p.isType(models.TokenTypeRParen) {
		return p.expectedError(")")
	}
	p.advance() // Consume second )
	if p.isType(models.TokenTypeLParen) {
		return goerrors.InvalidSyntaxError(fmt.Sprintf(
			"ClickHouse parametric function %s takes at most two parenthesized lists: %s(params)(args)",
			funcCall.Name, funcCall.Name), p.currentLocation(), "")
	}
	return nil
}
