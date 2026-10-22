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

// PivotAggregate is one aggregate of a PIVOT clause with its optional alias:
// SUM(amount) AS total.
type PivotAggregate struct {
	Expr  Expression
	Alias string
}

// PivotExtensions holds the PIVOT forms beyond a single aggregate and a
// literal IN list:
//
//	Oracle:    PIVOT (SUM(c) AS total, COUNT(*) AS cnt FOR a IN (1 AS x, 2 AS y))
//	Oracle:    PIVOT XML (SUM(c) FOR a IN (ANY))
//	Snowflake: PIVOT (AVG(a) FOR q IN (ANY ORDER BY q)), IN (SELECT ...)
type PivotExtensions struct {
	// Aggregates lists every aggregate when there is more than one or one
	// has an alias; AggregateFunction is then Aggregates[0].Expr.
	Aggregates []PivotAggregate
	// XML is the Oracle PIVOT XML form.
	XML bool
	// InAny is IN (ANY [ORDER BY ...]) in place of a value list.
	InAny bool
	// InAnyOrderBy is the Snowflake ORDER BY of IN (ANY ORDER BY ...).
	InAnyOrderBy []OrderByExpression
	// InSubquery is IN (SELECT ...) in place of a value list.
	InSubquery Statement
	// SourceAlias is the alias of the pivoted table or derived table:
	// (SELECT ...) s PIVOT (...) AS p. The PIVOT alias stays in
	// TableReference.Alias.
	SourceAlias string
	// SourceAliasQuote records the delimiters of SourceAlias when they must
	// be kept (see NameQuote).
	SourceAliasQuote NameQuote
}

func (e *PivotExtensions) pivotExtensionChildren(nodes []Node) []Node {
	for i := 1; i < len(e.Aggregates); i++ {
		if e.Aggregates[i].Expr != nil {
			nodes = append(nodes, e.Aggregates[i].Expr)
		}
	}
	for i := range e.InAnyOrderBy {
		nodes = append(nodes, &e.InAnyOrderBy[i])
	}
	if e.InSubquery != nil {
		nodes = append(nodes, e.InSubquery)
	}
	return nodes
}

// PivotSQL returns " PIVOT (...)" for p with keywords passed through kw
// (nil keeps them upper case), or "" for nil.
func PivotSQL(p *PivotClause, kw func(string) string) string {
	if p == nil {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writePivot(&sb, p, kw)
	return sb.String()
}

// UnpivotSQL returns " UNPIVOT (...)" for u with keywords passed through kw
// (nil keeps them upper case), or "" for nil.
func UnpivotSQL(u *UnpivotClause, kw func(string) string) string {
	if u == nil {
		return ""
	}
	if kw == nil {
		kw = identityKeyword
	}
	var sb strings.Builder
	writeUnpivot(&sb, u, kw)
	return sb.String()
}

// TableRefSourceAliasSQL returns " alias" for the alias of the table that a
// PIVOT / UNPIVOT applies to, or "".
func TableRefSourceAliasSQL(t *TableReference) string {
	return TableRefSourceAliasSQLWith(t, nil)
}

// TableRefSourceAliasSQLWith is TableRefSourceAliasSQL with the alias's
// recorded NameQuote passed through nq first (nil leaves it unchanged).
func TableRefSourceAliasSQLWith(t *TableReference, nq func(NameQuote) NameQuote) string {
	alias, q := tableRefSourceAlias(t)
	if alias == "" {
		return ""
	}
	if nq != nil {
		q = nq(q)
	}
	return " " + QuoteTableAliasWith(alias, q)
}

func tableRefSourceAlias(t *TableReference) (string, NameQuote) {
	if t == nil {
		return "", 0
	}
	if t.Pivot != nil {
		return t.Pivot.SourceAlias, t.Pivot.SourceAliasQuote
	}
	if t.Unpivot != nil {
		return t.Unpivot.SourceAlias, t.Unpivot.SourceAliasQuote
	}
	return "", 0
}

func writePivot(w textWriter, p *PivotClause, kw func(string) string) {
	w.WriteByte(' ')
	w.WriteString(kw("PIVOT"))
	if p.XML {
		w.WriteByte(' ')
		w.WriteString(kw("XML"))
	}
	w.WriteString(" (")
	if len(p.Aggregates) > 0 {
		for i, a := range p.Aggregates {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(exprSQL(a.Expr))
			if a.Alias != "" {
				w.WriteByte(' ')
				w.WriteString(kw("AS"))
				w.WriteByte(' ')
				w.WriteString(QuoteName(a.Alias))
			}
		}
	} else {
		w.WriteString(exprSQL(p.AggregateFunction))
	}
	w.WriteByte(' ')
	w.WriteString(kw("FOR"))
	w.WriteByte(' ')
	w.WriteString(QuotePivotColumn(p.PivotColumn))
	w.WriteByte(' ')
	w.WriteString(kw("IN"))
	w.WriteString(" (")
	switch {
	case p.InAny:
		w.WriteString(kw("ANY"))
		if len(p.InAnyOrderBy) > 0 {
			w.WriteByte(' ')
			w.WriteString(kw("ORDER BY"))
			w.WriteByte(' ')
			for i := range p.InAnyOrderBy {
				if i > 0 {
					w.WriteString(", ")
				}
				w.WriteString(exprSQL(p.InAnyOrderBy[i].Expression))
				if !p.InAnyOrderBy[i].Ascending {
					w.WriteByte(' ')
					w.WriteString(kw("DESC"))
				}
			}
		}
	case p.InSubquery != nil:
		w.WriteString(stmtSQL(p.InSubquery))
	default:
		writePivotItemList(w, p.InValues)
	}
	w.WriteString("))")
}

func writeUnpivot(w textWriter, u *UnpivotClause, kw func(string) string) {
	w.WriteByte(' ')
	w.WriteString(kw("UNPIVOT"))
	switch strings.ToUpper(u.NullHandling) {
	case "INCLUDE", "EXCLUDE":
		w.WriteByte(' ')
		w.WriteString(kw(strings.ToUpper(u.NullHandling) + " NULLS"))
	}
	w.WriteString(" (")
	if len(u.ValueColumns) > 1 {
		w.WriteByte('(')
		for i, c := range u.ValueColumns {
			if i > 0 {
				w.WriteString(", ")
			}
			w.WriteString(QuotePivotColumn(c))
		}
		w.WriteByte(')')
	} else {
		w.WriteString(QuotePivotColumn(u.ValueColumn))
	}
	w.WriteByte(' ')
	w.WriteString(kw("FOR"))
	w.WriteByte(' ')
	w.WriteString(QuotePivotColumn(u.NameColumn))
	w.WriteByte(' ')
	w.WriteString(kw("IN"))
	w.WriteString(" (")
	writePivotItemList(w, u.InColumns)
	w.WriteString("))")
}

func writePivotItemList(w textWriter, items []string) {
	for i, item := range items {
		if i > 0 {
			w.WriteString(", ")
		}
		w.WriteString(QuotePivotItem(item))
	}
}

// pivotTupleLen returns the length of a parenthesized atom list "(a, b)" at
// the start of s (an Oracle multi-column UNPIVOT IN entry), or 0.
func pivotTupleLen(s string) int {
	if s == "" || s[0] != '(' {
		return 0
	}
	i := 1
	for {
		n := pivotAtomLen(s[i:])
		if n == 0 {
			return 0
		}
		i += n
		if strings.HasPrefix(s[i:], ", ") {
			i += 2
			continue
		}
		if i < len(s) && s[i] == ')' {
			return i + 1
		}
		return 0
	}
}

// releasePivotExtensions releases the expressions only PivotExtensions
// holds: the aggregates after the first (the first is AggregateFunction)
// and the IN (ANY ORDER BY) expressions.
func releasePivotExtensions(p *PivotClause, mode releaseMode) {
	for i := 1; i < len(p.Aggregates); i++ {
		releaseExpression(p.Aggregates[i].Expr, mode)
	}
	for i := range p.InAnyOrderBy {
		releaseExpression(p.InAnyOrderBy[i].Expression, mode)
	}
	if p.InSubquery != nil {
		releaseStatement(p.InSubquery, mode)
	}
	p.PivotExtensions = PivotExtensions{}
}
