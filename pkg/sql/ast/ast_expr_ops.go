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

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// AtTimeZoneExpression represents the postfix AT TIME ZONE operator
// (PostgreSQL, Snowflake, SQL Server AT TIME ZONE, Oracle):
//
//	created_at AT TIME ZONE 'UTC'
//
// Chained uses nest to the left: a AT TIME ZONE 'UTC' AT TIME ZONE 'PST' is
// AtTimeZone(AtTimeZone(a, 'UTC'), 'PST').
type AtTimeZoneExpression struct {
	Expr Expression
	Zone Expression
	Pos  models.Location // Source position of the AT keyword
}

func (a *AtTimeZoneExpression) expressionNode()     {}
func (a AtTimeZoneExpression) TokenLiteral() string { return "AT TIME ZONE" }
func (a AtTimeZoneExpression) Children() []Node {
	var nodes []Node
	if a.Expr != nil {
		nodes = append(nodes, a.Expr)
	}
	if a.Zone != nil {
		nodes = append(nodes, a.Zone)
	}
	return nodes
}

// CollateExpression represents the postfix COLLATE operator:
//
//	name COLLATE "C"          (PostgreSQL)
//	x COLLATE utf8mb4_bin     (MySQL / MariaDB)
//	a COLLATE Latin1_General_CI_AS (SQL Server)
//	a COLLATE NOCASE          (SQLite)
type CollateExpression struct {
	Expr Expression
	// Collation is the collation name; a schema-qualified name is dotted
	// ("pg_catalog.default").
	Collation string
	// Quoted records that the (last part of the) name was written as a
	// double-quoted identifier. It is re-quoted on output because PostgreSQL
	// folds a bare C to c, which is a different (nonexistent) collation.
	Quoted bool
	// Literal records a collation written as a string literal (ClickHouse
	// ORDER BY y COLLATE 'en'); it is written back as one.
	Literal bool
	Pos     models.Location // Source position of the COLLATE keyword
}

func (c *CollateExpression) expressionNode()     {}
func (c CollateExpression) TokenLiteral() string { return "COLLATE" }
func (c CollateExpression) Children() []Node {
	if c.Expr == nil {
		return nil
	}
	return []Node{c.Expr}
}

// AnyAllExpression represents a quantified comparison whose right side is an
// array-valued expression rather than a subquery:
//
//	id = ANY($1)
//	'x' = ANY(tags)
//	id <> ALL(ARRAY[1, 2])
//	id = SOME(ARRAY[1, 2])
//
// The subquery forms are AnyExpression and AllExpression. Quantifier is the
// canonical upper-case keyword: ANY, ALL or SOME.
type AnyAllExpression struct {
	Expr       Expression
	Operator   string
	Quantifier string
	Array      Expression
	Pos        models.Location // Source position of the quantifier keyword
}

func (a *AnyAllExpression) expressionNode() {}
func (a AnyAllExpression) TokenLiteral() string {
	if a.Quantifier == "" {
		return "ANY"
	}
	return a.Quantifier
}
func (a AnyAllExpression) Children() []Node {
	var nodes []Node
	if a.Expr != nil {
		nodes = append(nodes, a.Expr)
	}
	if a.Array != nil {
		nodes = append(nodes, a.Array)
	}
	return nodes
}

// TernaryExpression represents the ClickHouse conditional operator
// cond ? then : else.
type TernaryExpression struct {
	Cond Expression
	Then Expression
	Else Expression
	Pos  models.Location // Source position of the ? operator
}

func (t *TernaryExpression) expressionNode()     {}
func (t TernaryExpression) TokenLiteral() string { return "?" }
func (t TernaryExpression) Children() []Node {
	var nodes []Node
	if t.Cond != nil {
		nodes = append(nodes, t.Cond)
	}
	if t.Then != nil {
		nodes = append(nodes, t.Then)
	}
	if t.Else != nil {
		nodes = append(nodes, t.Else)
	}
	return nodes
}
