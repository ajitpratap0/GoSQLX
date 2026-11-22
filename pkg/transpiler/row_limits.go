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
// rather than given different semantics in the target dialect. Set-level limits
// require ORDER BY for SQL Server OFFSET/FETCH: TOP would limit one branch,
// and RewriteRule cannot replace a root set operation with a wrapping SELECT.
func rowLimitRule(to keywords.SQLDialect) RewriteRule {
	return func(stmt ast.Statement) error {
		var rewriteErr error
		var setLevel map[*ast.SelectStatement]bool
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
			if tail, ok := n.(*ast.QueryTail); ok {
				view := tail.Select()
				if rewriteErr = normalizeTies(view, to); rewriteErr != nil {
					return false
				}
				*tail = *ast.QueryTailFrom(view)
			}
			if set, ok := n.(*ast.SetOperation); ok && to == keywords.DialectSQLServer {
				if right, ok := set.Right.(*ast.SelectStatement); ok && !set.RightParenthesized {
					if setLevel == nil {
						setLevel = make(map[*ast.SelectStatement]bool)
					}
					setLevel[right] = true
				}
				if set.Tail != nil {
					view := set.Tail.Select()
					if rewriteErr = normalizeTies(view, to); rewriteErr != nil {
						return false
					}
					if rewriteErr = sqlServerSetLimit(view); rewriteErr != nil {
						return false
					}
					set.Tail = ast.QueryTailFrom(view)
				}
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
						if !set.RightParenthesized && len(selectOperand.OrderBy) > 0 {
							if set.Tail == nil {
								set.Tail = &ast.QueryTail{}
							}
							if len(set.Tail.OrderBy) > 0 {
								rewriteErr = fmt.Errorf("TOP set-operation operand has conflicting set-level ORDER BY")
								return false
							}
							set.Tail.OrderBy = selectOperand.OrderBy
							selectOperand.OrderBy = nil
						}
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
			if rewriteErr = normalizeTies(s, to); rewriteErr != nil {
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
			if to == keywords.DialectSQLServer && setLevel[s] {
				rewriteErr = sqlServerSetLimit(s)
				return rewriteErr == nil
			}
			// With an offset, SQL Server requires OFFSET/FETCH and ORDER BY.
			// ORDER BY alone does not prevent use of TOP.
			if to == keywords.DialectSQLServer && s.Top == nil && s.Limit != nil && !s.HasOffset() && s.Fetch == nil {
				s.Top = &ast.TopClause{Count: &ast.LiteralValue{Value: *s.Limit, Type: "int"}}
				s.Limit = nil
			}
			if to == keywords.DialectSQLServer && (s.HasOffset() || s.Fetch != nil) {
				if len(s.OrderBy) == 0 {
					unspecifiedOrder := &ast.SubqueryExpression{Subquery: &ast.SelectStatement{
						Columns: []ast.Expression{&ast.LiteralValue{Type: "NULL"}},
					}}
					s.OrderBy = []ast.OrderByExpression{{Ascending: true, Expression: unspecifiedOrder}}
				}
				sqlServerOffset(s)
			}
			return true
		})
		return rewriteErr
	}
}

// sqlServerSetLimit keeps a set operation's row limit in its trailing clauses.
// Both unparenthesized right SELECTs and explicit QueryTail views use this path.
func sqlServerSetLimit(s *ast.SelectStatement) error {
	if !s.HasLimit() && !s.HasOffset() && s.Fetch == nil {
		return nil
	}
	if len(s.OrderBy) == 0 {
		return fmt.Errorf("LIMIT/OFFSET on a set operation without ORDER BY cannot be transpiled to SQL Server")
	}
	if s.Limit != nil || s.DialectExtras().LimitExpr != nil {
		fetch := &ast.FetchClause{FetchType: "NEXT"}
		if s.Limit != nil {
			value := int64(*s.Limit)
			fetch.FetchValue = &value
		} else {
			fetch.FetchExpr = s.DialectExtras().LimitExpr
		}
		if !s.HasOffset() {
			zero := 0
			s.Offset = &zero
		}
		s.Fetch = fetch
		s.Limit = nil
	}
	if s.Extras != nil {
		s.Extras.LimitExpr = nil
		s.Extras.LimitAll = false
	}
	sqlServerOffset(s)
	return nil
}

// sqlServerOffset supplies the mandatory offset before FETCH and spells bare
// OFFSET using SQL Server's required ROWS suffix.
func sqlServerOffset(s *ast.SelectStatement) {
	if s.Fetch != nil && s.Fetch.OffsetValue == nil && !s.HasOffset() {
		zero := 0
		s.Offset = &zero
	}
	if s.HasOffset() {
		s.EnsureExtras().OffsetRows = true
	}
}

// normalizeTies preserves tied-row semantics, refusing targets without an
// equivalent FETCH WITH TIES clause rather than silently lowering to ONLY.
func normalizeTies(s *ast.SelectStatement, to keywords.SQLDialect) error {
	limitTies := s.DialectExtras().LimitWithTies
	fetchTies := s.Fetch != nil && s.Fetch.WithTies
	if !limitTies && !fetchTies {
		return nil
	}
	if limitTies && to == keywords.DialectClickHouse {
		return nil
	}
	switch to {
	case keywords.DialectPostgreSQL, keywords.DialectOracle, keywords.DialectGeneric, "":
		if limitTies {
			fetch := &ast.FetchClause{FetchType: "FIRST", WithTies: true}
			if s.Limit != nil {
				value := int64(*s.Limit)
				fetch.FetchValue = &value
			} else {
				fetch.FetchExpr = s.DialectExtras().LimitExpr
			}
			s.Fetch = fetch
			s.Limit = nil
			s.EnsureExtras().LimitExpr = nil
			s.Extras.LimitWithTies = false
		}
		return nil
	default:
		return fmt.Errorf("WITH TIES cannot be transpiled to %s", to)
	}
}
