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
// unless they were in the source: the parser builds left-deep trees for
// operators of equal precedence, and parenthesizing the left operand would
// also move a WITH clause of its first SELECT inside the parentheses.
func SetOperandNeedsParens(s *SetOperation, right bool, dialect string) bool {
	if s == nil {
		return false
	}
	if !right {
		return s.LeftParenthesized
	}
	if s.RightParenthesized {
		return true
	}
	child, ok := s.Right.(*SetOperation)
	if !ok || child == nil {
		return false
	}
	if SetOperatorsEqualPrecedence(dialect) {
		return true
	}
	// a UNION b INTERSECT c already reads as a UNION (b INTERSECT c).
	return setOperatorPrecedence(child.Operator) <= setOperatorPrecedence(s.Operator)
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
