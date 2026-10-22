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

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// CTESearchClause is the SEARCH clause of a recursive CTE:
//
//	SEARCH {DEPTH | BREADTH} FIRST BY col [, col ...] SET sequence_col
type CTESearchClause struct {
	// Breadth is true for BREADTH FIRST, false for DEPTH FIRST.
	Breadth bool
	// By are the ordering columns.
	By []string
	// Set is the generated sequence column.
	Set string
	Pos models.Location
}

// CTECycleClause is the CYCLE clause of a recursive CTE:
//
//	CYCLE col [, col ...] SET mark_col [TO value DEFAULT value] [USING path_col]
//
// PostgreSQL 14+ takes the optional TO / DEFAULT values and requires USING;
// Oracle requires TO / DEFAULT and has no USING.
type CTECycleClause struct {
	// Columns are the columns checked for cycles.
	Columns []string
	// Set is the generated cycle mark column.
	Set string
	// To and Default are the mark values for a cycle and for no cycle.
	To      Expression
	Default Expression
	// Using is the generated path column (PostgreSQL).
	Using string
	Pos   models.Location
}

func (c *CTECycleClause) expressionNode()     {}
func (c CTECycleClause) TokenLiteral() string { return "CYCLE" }
func (c CTECycleClause) Children() []Node {
	var nodes []Node
	if c.To != nil {
		nodes = append(nodes, c.To)
	}
	if c.Default != nil {
		nodes = append(nodes, c.Default)
	}
	return nodes
}

// CTESearchCycleSQL returns the " SEARCH ..." and " CYCLE ..." clauses of
// cte, with keywords passed through kw (nil keeps them upper case), or "".
func CTESearchCycleSQL(cte *CommonTableExpr, kw func(string) string) string {
	if cte == nil || (cte.Search == nil && cte.Cycle == nil) {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writeCTESearchCycle(&sb, cte, kw)
	return sb.String()
}

func writeCTESearchCycle(w textWriter, cte *CommonTableExpr, kw func(string) string) {
	if s := cte.Search; s != nil && len(s.By) > 0 && s.Set != "" {
		w.WriteByte(' ')
		w.WriteString(kw("SEARCH"))
		w.WriteByte(' ')
		if s.Breadth {
			w.WriteString(kw("BREADTH FIRST BY"))
		} else {
			w.WriteString(kw("DEPTH FIRST BY"))
		}
		w.WriteByte(' ')
		writeQuotedNameList(w, s.By)
		w.WriteByte(' ')
		w.WriteString(kw("SET"))
		w.WriteByte(' ')
		w.WriteString(QuoteName(s.Set))
	}
	if c := cte.Cycle; c != nil && len(c.Columns) > 0 && c.Set != "" {
		w.WriteByte(' ')
		w.WriteString(kw("CYCLE"))
		w.WriteByte(' ')
		writeQuotedNameList(w, c.Columns)
		w.WriteByte(' ')
		w.WriteString(kw("SET"))
		w.WriteByte(' ')
		w.WriteString(QuoteName(c.Set))
		if c.To != nil && c.Default != nil {
			w.WriteByte(' ')
			w.WriteString(kw("TO"))
			w.WriteByte(' ')
			w.WriteString(exprSQL(c.To))
			w.WriteByte(' ')
			w.WriteString(kw("DEFAULT"))
			w.WriteByte(' ')
			w.WriteString(exprSQL(c.Default))
		}
		if c.Using != "" {
			w.WriteByte(' ')
			w.WriteString(kw("USING"))
			w.WriteByte(' ')
			w.WriteString(QuoteName(c.Using))
		}
	}
}

func writeQuotedNameList(w textWriter, names []string) {
	for i, n := range names {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(QuoteName(n))
	}
}
