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

// render_select_ext.go renders the SELECT clauses that renderSelect used to
// drop or mangle: select modifiers, TOP parentheses, INTO, ARRAY JOIN,
// PREWHERE, GROUP BY modifiers, QUALIFY, START WITH / CONNECT BY, ORDER
// SIBLINGS BY, LIMIT BY, LIMIT/OFFSET expressions, FOR JSON/XML, OPTION (...)
// and FORMAT.

package formatter

import (
	"strconv"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// noSelectExtras is the read-only stand-in selectExtras returns for a
// statement without Extras. Nothing may write through it.
var noSelectExtras ast.SelectExtras

// selectExtras returns s.Extras, or a read-only empty SelectExtras when it is
// nil, so the renderers can read the rarer clauses without nil checks.
func selectExtras(s *ast.SelectStatement) *ast.SelectExtras {
	if s.Extras != nil {
		return s.Extras
	}
	return &noSelectExtras
}

// writeSelectPrologue writes the MySQL select modifiers and the TOP clause,
// each followed by a space.
func writeSelectPrologue(sb *strings.Builder, s *ast.SelectStatement, f *nodeFormatter) {
	for _, m := range selectExtras(s).SelectModifiers {
		if t := ast.SelectModifierText(m); t != "" {
			sb.WriteString(f.kw(t))
			sb.WriteString(" ")
		}
	}
	if s.Top == nil || s.Top.Count == nil {
		return
	}
	sb.WriteString(f.kw("TOP"))
	sb.WriteString(" ")
	if ast.TopNeedsParens(s.Top) {
		sb.WriteString("(")
		sb.WriteString(formatExpression(s.Top.Count, f.opts))
		sb.WriteString(")")
	} else {
		sb.WriteString(formatExpression(s.Top.Count, f.opts))
	}
	if s.Top.IsPercent {
		sb.WriteString(" ")
		sb.WriteString(f.kw("PERCENT"))
	}
	if s.Top.WithTies {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH TIES"))
	}
	sb.WriteString(" ")
}

// selectIntoSQL renders "INTO ..." (without a leading separator).
func selectIntoSQL(in *ast.SelectInto, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(f.kw("INTO"))
	sb.WriteString(" ")
	switch in.Kind {
	case ast.SelectIntoVariables:
		sb.WriteString(exprListSQL(in.Targets))
	case ast.SelectIntoOutfile, ast.SelectIntoDumpfile:
		sb.WriteString(f.kw(in.Kind))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(in.File))
		if in.Kind == ast.SelectIntoOutfile {
			if in.CharacterSet != "" {
				sb.WriteString(" ")
				sb.WriteString(f.kw("CHARACTER SET"))
				sb.WriteString(" ")
				sb.WriteString(ast.QuoteName(in.CharacterSet))
			}
			writeIntoFileOptions(&sb, "FIELDS", in.FieldsOptions, f)
			writeIntoFileOptions(&sb, "LINES", in.LinesOptions, f)
		}
	default:
		if t := ast.SelectIntoTemporaryText(in.Temporary); t != "" {
			sb.WriteString(f.kw(t))
			sb.WriteString(" ")
		}
		if in.TableKeyword {
			sb.WriteString(f.kw("TABLE"))
			sb.WriteString(" ")
		}
		sb.WriteString(ast.QuoteQualifiedName(in.Table))
	}
	return sb.String()
}

func writeIntoFileOptions(sb *strings.Builder, clause string, opts []ast.IntoFileOption, f *nodeFormatter) {
	wrote := false
	for _, o := range opts {
		kw := ast.IntoFileOptionText(o.Option)
		if kw == "" || o.Value == nil {
			continue
		}
		if !wrote {
			sb.WriteString(" ")
			sb.WriteString(f.kw(clause))
			wrote = true
		}
		sb.WriteString(" ")
		sb.WriteString(f.kw(kw))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(o.Value))
	}
}

// arrayJoinSQL renders a ClickHouse [LEFT] ARRAY JOIN clause.
func arrayJoinSQL(a *ast.ArrayJoinClause, f *nodeFormatter) string {
	var sb strings.Builder
	if a.Left {
		sb.WriteString(f.kw("LEFT ARRAY JOIN"))
	} else {
		sb.WriteString(f.kw("ARRAY JOIN"))
	}
	sb.WriteString(" ")
	for i, e := range a.Elements {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(exprSQL(e.Expr))
		if e.Alias != "" {
			sb.WriteString(" ")
			sb.WriteString(f.kw("AS"))
			sb.WriteString(" ")
			sb.WriteString(ast.QuoteName(e.Alias))
		}
	}
	return sb.String()
}

// groupBySQL renders the GROUP BY clause with its modifiers, or "" when the
// statement has none.
func groupBySQL(s *ast.SelectStatement, f *nodeFormatter) string {
	m := s.DialectExtras().GroupByModifiers
	if len(s.GroupBy) == 0 && !m.All {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(f.kw("GROUP BY"))
	sb.WriteString(" ")
	if m.All {
		sb.WriteString(f.kw("ALL"))
	} else {
		sb.WriteString(exprListSQL(s.GroupBy))
	}
	switch {
	case m.WithRollup:
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH ROLLUP"))
	case m.WithCube:
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH CUBE"))
	}
	if m.WithTotals {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WITH TOTALS"))
	}
	return sb.String()
}

// writeHierarchical writes QUALIFY and the Oracle / MariaDB START WITH and
// CONNECT BY clauses, each preceded by a clause separator.
func writeHierarchical(sb *strings.Builder, s *ast.SelectStatement, f *nodeFormatter) {
	if s.Qualify != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("QUALIFY"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(s.Qualify, f.opts))
	}
	if s.StartWith != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("START WITH"))
		sb.WriteString(" ")
		sb.WriteString(formatExpression(s.StartWith, f.opts))
	}
	if s.ConnectBy != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("CONNECT BY"))
		sb.WriteString(" ")
		if s.ConnectBy.NoCycle {
			sb.WriteString(f.kw("NOCYCLE"))
			sb.WriteString(" ")
		}
		sb.WriteString(formatExpression(s.ConnectBy.Condition, f.opts))
	}
}

// writeLimitOffsetClauses writes LIMIT BY, LIMIT and OFFSET, each preceded by
// a clause separator. OFFSET keeps ROWS when it was written or a FETCH
// clause follows.
func writeLimitOffsetClauses(sb *strings.Builder, s *ast.SelectStatement, f *nodeFormatter) {
	if lb := selectExtras(s).LimitBy; lb != nil && lb.Count != nil && len(lb.Exprs) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("LIMIT"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(lb.Count))
		if lb.Offset != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("OFFSET"))
			sb.WriteString(" ")
			sb.WriteString(exprSQL(lb.Offset))
		}
		sb.WriteString(" ")
		sb.WriteString(f.kw("BY"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(lb.Exprs))
	}
	if s.HasLimit() {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("LIMIT"))
		sb.WriteString(" ")
		switch {
		case s.Limit != nil:
			sb.WriteString(strconv.Itoa(*s.Limit))
		case s.DialectExtras().LimitExpr != nil:
			sb.WriteString(exprSQL(s.DialectExtras().LimitExpr))
		default:
			sb.WriteString(f.kw("ALL"))
		}
		if s.DialectExtras().LimitWithTies {
			sb.WriteString(" ")
			sb.WriteString(f.kw("WITH TIES"))
		}
	}
	if s.HasOffset() {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("OFFSET"))
		sb.WriteString(" ")
		if s.Offset != nil {
			sb.WriteString(strconv.Itoa(*s.Offset))
		} else {
			sb.WriteString(exprSQL(s.DialectExtras().OffsetExpr))
		}
		if s.DialectExtras().OffsetRows || s.Fetch != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw(ast.OffsetRowsKeyword(s)))
		}
	}
	if x := s.Extras; x != nil && x.RowsExamined != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("ROWS EXAMINED"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(x.RowsExamined))
	}
}

// forOutputSQL renders " FOR JSON|XML|BROWSE ..." (with a leading space), or
// "" for an unknown kind.
func forOutputSQL(fo *ast.ForOutputClause, f *nodeFormatter) string {
	kind := ast.ForOutputKindText(fo.Kind)
	if kind == "" {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(f.kw("FOR"))
	sb.WriteString(" ")
	sb.WriteString(f.kw(kind))
	if mode := ast.ForOutputModeText(fo.Mode); mode != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw(mode))
		if fo.ModeArg != nil {
			sb.WriteString("(")
			sb.WriteString(exprSQL(fo.ModeArg))
			sb.WriteString(")")
		}
	}
	for _, o := range fo.Options {
		name := ast.ForOutputOptionText(o.Name)
		if name == "" {
			continue
		}
		sb.WriteString(", ")
		sb.WriteString(f.kw(name))
		if o.Arg != nil {
			sb.WriteString("(")
			sb.WriteString(exprSQL(o.Arg))
			sb.WriteString(")")
		}
	}
	return sb.String()
}

// queryHintsSQL renders "OPTION (hint, ...)" (without a leading separator).
func queryHintsSQL(hints []ast.QueryHint, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(f.kw("OPTION"))
	sb.WriteString(" (")
	first := true
	for i := range hints {
		h := &hints[i]
		name := ast.QueryHintNameText(h.Name)
		if name == "" {
			continue
		}
		if !first {
			sb.WriteString(", ")
		}
		first = false
		sb.WriteString(f.kw(name))
		if h.Value != nil {
			if h.Equals {
				sb.WriteString(" = ")
			} else {
				sb.WriteString(" ")
			}
			sb.WriteString(exprSQL(h.Value))
		}
		if h.HasArgs {
			sb.WriteString(" (")
			for j, a := range h.Args {
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(exprSQL(a.Expr))
				if a.Unknown {
					sb.WriteString(" ")
					sb.WriteString(f.kw("UNKNOWN"))
				}
			}
			sb.WriteString(")")
		}
	}
	sb.WriteString(")")
	return sb.String()
}

// writeSelectEpilogue writes the clauses after FOR UPDATE: FOR JSON/XML,
// SETTINGS, OPTION (...) and FORMAT.
func writeSelectEpilogue(sb *strings.Builder, s *ast.SelectStatement, f *nodeFormatter) {
	x := selectExtras(s)
	if x.ForOutput != nil {
		sb.WriteString(forOutputSQL(x.ForOutput, f))
	}
	if len(s.Settings) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("SETTINGS"))
		sb.WriteString(" ")
		parts := make([]string, len(s.Settings))
		for i := range s.Settings {
			parts[i] = s.Settings[i].SQL()
		}
		sb.WriteString(strings.Join(parts, ", "))
	}
	if len(x.QueryHints) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(queryHintsSQL(x.QueryHints, f))
	}
	if n := ast.FormatNameText(x.OutputFormat); n != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FORMAT"))
		sb.WriteString(" ")
		sb.WriteString(n)
	}
}

// joinKeywordsSQL renders the keywords of a join ("LEFT JOIN", "CROSS
// APPLY", "GLOBAL ANY LEFT JOIN", ...) with the formatter's keyword case.
func joinKeywordsSQL(j *ast.JoinClause, f *nodeFormatter) string {
	return f.kw(ast.JoinKeywordsText(j))
}

// interpolateSQL renders " INTERPOLATE [(col [AS expr], ...)]".
func interpolateSQL(c *ast.InterpolateClause, f *nodeFormatter) string {
	var sb strings.Builder
	sb.WriteString(" ")
	sb.WriteString(f.kw("INTERPOLATE"))
	if len(c.Items) == 0 {
		return sb.String()
	}
	sb.WriteString(" (")
	for i, it := range c.Items {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(ast.QuoteName(it.Column))
		if it.Expr != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("AS"))
			sb.WriteString(" ")
			sb.WriteString(exprSQL(it.Expr))
		}
	}
	sb.WriteString(")")
	return sb.String()
}

// normalizeLimitForDialect rewrites LIMIT / OFFSET (integer or expression
// values) into TOP or OFFSET ... FETCH for SQL Server and into FETCH FIRST
// for Oracle, on the caller's shallow copy of the statement. LIMIT ALL means
// no limit and is dropped for those dialects.
func normalizeLimitForDialect(s *ast.SelectStatement, dialect string) {
	if dialect != "sqlserver" && dialect != "oracle" {
		return
	}
	if s.Extras != nil {
		// renderSelect copied the statement; detach metadata before normalization.
		x := *s.Extras
		s.Extras = &x
		s.Extras.LimitAll = false
	}
	if s.Limit == nil && s.DialectExtras().LimitExpr == nil {
		return
	}
	newFetch := func(fetchType string) *ast.FetchClause {
		fc := &ast.FetchClause{FetchType: fetchType}
		if s.Limit != nil {
			v := int64(*s.Limit)
			fc.FetchValue = &v
		} else {
			fc.FetchExpr = s.DialectExtras().LimitExpr
		}
		return fc
	}
	clearLimit := func() {
		s.Limit = nil
		if s.Extras != nil {
			s.Extras.LimitExpr, s.Extras.LimitWithTies = nil, false
		}
	}
	// moveOffset moves an integer OFFSET into the FETCH clause; an OFFSET
	// expression stays on the statement and renders as OFFSET expr ROWS.
	moveOffset := func(fc *ast.FetchClause, defaultZero bool) {
		switch {
		case s.Offset != nil:
			v := int64(*s.Offset)
			fc.OffsetValue = &v
			s.Offset = nil
		case s.DialectExtras().OffsetExpr == nil && defaultZero:
			var zero int64
			fc.OffsetValue = &zero
		}
	}

	switch dialect {
	case "sqlserver":
		if s.Top != nil {
			return
		}
		if s.HasOffset() || len(s.OrderBy) > 0 {
			// SQL Server 2012+ OFFSET/FETCH syntax (requires ORDER BY in practice,
			// but we emit it faithfully and let the database validate).
			s.Fetch = newFetch("NEXT")
			moveOffset(s.Fetch, true)
		} else {
			// Simple TOP N
			var count ast.Expression = s.DialectExtras().LimitExpr
			if s.Limit != nil {
				count = &ast.LiteralValue{Value: *s.Limit, Type: "int"}
			}
			s.Top = &ast.TopClause{Count: count}
		}
		clearLimit()

	case "oracle":
		if s.Fetch != nil {
			return
		}
		s.Fetch = newFetch("FIRST")
		moveOffset(s.Fetch, false)
		clearLimit()
	}
}
