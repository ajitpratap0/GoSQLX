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

package transpiler

import (
	"fmt"
	"strconv"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// rowLimitRule normalizes TOP before target rendering, including nested
// queries. Percentage, tied rows and dynamic TOP expressions are refused
// rather than given different semantics in the target dialect.
func rowLimitRule(to keywords.SQLDialect) RewriteRule {
	return func(stmt ast.Statement) error {
		var rewriteErr error
		ast.Inspect(stmt, func(n ast.Node) bool {
			if rewriteErr != nil {
				return false
			}
			// SELECT TOP is consumed below before visiting its children.
			// A remaining TOP belongs to DML, which has no portable LIMIT rewrite.
			if _, ok := n.(*ast.TopClause); ok && to != keywords.DialectSQLServer {
				rewriteErr = fmt.Errorf("DML TOP cannot be transpiled to %s", to)
				return false
			}
			if set, ok := n.(*ast.SetOperation); ok && to != keywords.DialectSQLServer {
				for _, right := range []bool{false, true} {
					operand := set.Left
					if right {
						operand = set.Right
					}
					selectOperand, ok := operand.(*ast.SelectStatement)
					if !ok || selectOperand.Top == nil {
						continue
					}
					if to == keywords.DialectSQLite {
						rewriteErr = fmt.Errorf("TOP on a set-operation operand cannot be transpiled to SQLite")
						return false
					}
					if right {
						set.RightParenthesized = true
					} else {
						if !set.LeftParenthesized && selectOperand.With != nil {
							set.LeftWithHoisted = true
						}
						set.LeftParenthesized = true
					}
				}
			}
			s, ok := n.(*ast.SelectStatement)
			if !ok {
				return true
			}
			if to == keywords.DialectSQLServer && s.DialectExtras().LimitWithTies {
				rewriteErr = fmt.Errorf("LIMIT WITH TIES cannot be transpiled to SQL Server")
				return false
			}
			if s.Top != nil && to != keywords.DialectSQLServer {
				top := s.Top
				if top.IsPercent || top.WithTies {
					rewriteErr = fmt.Errorf("TOP PERCENT or WITH TIES cannot be transpiled to %s", to)
					return false
				}
				if s.HasLimit() || s.HasOffset() || s.Fetch != nil {
					rewriteErr = fmt.Errorf("TOP combined with LIMIT, OFFSET or FETCH cannot be transpiled to %s", to)
					return false
				}
				count, ok := top.Count.(*ast.LiteralValue)
				if !ok || count == nil || (count.Type != "INTEGER" && count.Type != "int" && count.Type != "NUMBER") {
					rewriteErr = fmt.Errorf("non-integer TOP count cannot be transpiled to %s", to)
					return false
				}
				limit, err := strconv.Atoi(fmt.Sprint(count.Value))
				if err != nil || limit < 0 {
					rewriteErr = fmt.Errorf("non-integer TOP count cannot be transpiled to %s", to)
					return false
				}
				s.Limit = &limit
				s.Top = nil
				ast.PutLiteralValue(count)
				if to == keywords.DialectGeneric || to == "" {
					value := int64(limit)
					s.Fetch = &ast.FetchClause{FetchType: "FIRST", FetchValue: &value}
					s.Limit = nil
				}
			}
			// With an offset, SQL Server requires OFFSET/FETCH; leave that case
			// to the formatter. ORDER BY alone does not prevent use of TOP.
			if to == keywords.DialectSQLServer && s.Top == nil && s.Limit != nil && !s.HasOffset() && s.Fetch == nil {
				s.Top = &ast.TopClause{Count: &ast.LiteralValue{Value: *s.Limit, Type: "int"}}
				s.Limit = nil
			}
			return true
		})
		return rewriteErr
	}
}
