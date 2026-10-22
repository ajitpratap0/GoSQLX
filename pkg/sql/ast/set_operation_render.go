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

package ast

import "strings"

// setOperatorPrecedence returns the binding strength of a set operator:
// INTERSECT binds tighter than UNION and EXCEPT (SQL standard, PostgreSQL,
// MySQL, MariaDB, SQL Server, Snowflake, ClickHouse).
func setOperatorPrecedence(op string) int {
	if len(op) >= 9 && strings.EqualFold(op[:9], "INTERSECT") {
		return 2
	}
	return 1
}

// SetOperatorsEqualPrecedence reports whether dialect gives every set
// operator the same precedence and groups them left to right (SQLite,
// Oracle), instead of letting INTERSECT bind tighter.
func SetOperatorsEqualPrecedence(dialect string) bool {
	return dialect == "sqlite" || dialect == "oracle"
}

// SetOperandNeedsParens reports whether the left (right == false) or right
// operand of s must be written in parentheses. An operand written in
// parentheses keeps them. A right operand that is itself a set operation
// needs them unless the precedence of the target dialect already groups it
// that way (A UNION B INTERSECT C); dialect "" means standard precedence,
// under which INTERSECT binds tighter than UNION and EXCEPT.
//
// A left operand that is a set operation is written without parentheses
// unless they were in the source, or unless it binds looser than s under
// the precedence of the target dialect, as for a tree parsed with
// equal-precedence rules (Oracle, SQLite: (A UNION B) INTERSECT C) and
// written for another dialect. The parser builds left-deep trees for
// operators of equal precedence. A WITH clause on the first SELECT would end
// up inside those parentheses and narrow its scope, so renderers write it
// before the whole chain instead (see HoistLeadingWith).
func SetOperandNeedsParens(s *SetOperation, right bool, dialect string) bool {
	if s == nil {
		return false
	}
	if !right {
		if s.LeftParenthesized {
			return true
		}
		child, ok := s.Left.(*SetOperation)
		if !ok || child == nil {
			return false
		}
		if child.Tail != nil {
			return true // its ORDER BY / LIMIT belongs inside the parentheses
		}
		if SetOperatorsEqualPrecedence(dialect) {
			return false
		}
		return setOperatorPrecedence(child.Operator) < setOperatorPrecedence(s.Operator)
	}
	if s.RightParenthesized {
		return true
	}
	child, ok := s.Right.(*SetOperation)
	if !ok || child == nil {
		return false
	}
	if child.Tail != nil {
		return true
	}
	if SetOperatorsEqualPrecedence(dialect) {
		return true
	}
	// a UNION b INTERSECT c already reads as a UNION (b INTERSECT c).
	return setOperatorPrecedence(child.Operator) <= setOperatorPrecedence(s.Operator)
}

// HoistLeadingWith returns the WITH clause of the first SELECT of s together
// with a copy of s whose first SELECT has no WITH clause, when renderers must
// write the clause before the whole set operation: some left operand of s is
// written in parentheses (it was written as "WITH c ... (A UNION B) INTERSECT
// C" and recorded in LeftWithHoisted, or it needs them under the precedence
// of dialect, as for a tree parsed with the equal-precedence rules of Oracle
// and SQLite), and the clause scopes over the whole set operation. Writing
// it inside the parentheses would hide its CTEs from the other operands.
//
// A WITH clause that was written inside parentheses in the source
// ("(WITH c ... A) UNION B"), or a set operation without a WITH clause or
// without a parenthesized left operand, yields (nil, s). The copy shares all
// other nodes with s; s is not modified.
func HoistLeadingWith(s *SetOperation, dialect string) (*WithClause, *SetOperation) {
	if s == nil {
		return nil, s
	}
	var first Statement = s
	for {
		op, ok := first.(*SetOperation)
		if !ok || op == nil {
			break
		}
		first = op.Left
	}
	sel, ok := first.(*SelectStatement)
	if !ok || sel == nil || sel.With == nil {
		return nil, s
	}
	// Levels of the left spine, outermost first.
	var spine []*SetOperation
	for cur := Statement(s); ; {
		op, ok := cur.(*SetOperation)
		if !ok || op == nil {
			break
		}
		spine = append(spine, op)
		cur = op.Left
	}
	needs := false
	for i := len(spine) - 1; i >= 0; i-- {
		level := spine[i]
		if level.LeftParenthesized && !level.LeftWithHoisted {
			return nil, s // the WITH clause is scoped by the source's parentheses
		}
		if level.LeftParenthesized || SetOperandNeedsParens(level, false, dialect) {
			needs = true
		}
	}
	if !needs {
		return nil, s
	}
	copies := make([]SetOperation, len(spine))
	for i, level := range spine {
		copies[i] = *level
		if i > 0 {
			copies[i-1].Left = &copies[i]
		}
	}
	bare := *sel
	bare.With = nil
	copies[len(copies)-1].Left = &bare
	return sel.With, &copies[0]
}

// SetOperationKeyword returns the operator of s as written by the renderers,
// with its ALL / DISTINCT quantifier, and whether the operator is a known
// one (see SetOperatorSQL). EXCEPT written as MINUS is written as MINUS
// again unless dialect is set to one without MINUS.
func SetOperationKeyword(s *SetOperation, dialect string) (string, bool) {
	op, known := SetOperatorSQL(s.Operator)
	if known && s.Minus && strings.EqualFold(op, "EXCEPT") && minusDialect(dialect) {
		op = "MINUS"
	}
	if known && !strings.Contains(op, " ") {
		// A bare operator: append the quantifier.
		switch {
		case s.All:
			op += " ALL"
		case s.Distinct:
			op += " DISTINCT"
		}
	} else if s.All {
		op += " ALL"
	}
	return op, known
}

// minusDialect reports whether MINUS can be written for dialect: Oracle,
// Snowflake, or an unspecified dialect (the source used MINUS).
func minusDialect(dialect string) bool {
	return dialect == "" || dialect == "oracle" || dialect == "snowflake"
}
