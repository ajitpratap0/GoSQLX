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

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// writeDMLModifiers writes each known statement modifier followed by a space.
func writeDMLModifiers(sb *strings.Builder, f *nodeFormatter, mods []string) {
	for _, m := range mods {
		if t := ast.DMLModifierText(m); t != "" {
			sb.WriteString(f.kw(t))
			sb.WriteString(" ")
		}
	}
}

// writeDMLTop writes "TOP (n) [PERCENT] "; DML requires the parentheses.
func writeDMLTop(sb *strings.Builder, f *nodeFormatter, top *ast.TopClause) {
	if top == nil || top.Count == nil {
		return
	}
	sb.WriteString(f.kw("TOP"))
	sb.WriteString(" (")
	sb.WriteString(exprSQL(top.Count))
	sb.WriteString(") ")
	if top.IsPercent {
		sb.WriteString(f.kw("PERCENT"))
		sb.WriteString(" ")
	}
}

// noDMLExtras is the read-only stand-in dmlExtras returns for a statement
// without Extras. Nothing may write through it.
var noDMLExtras ast.DMLTargetFields

// dmlExtras returns x, or a read-only empty DMLTargetFields when it is nil,
// so the renderers can read the UPDATE / DELETE fields without nil checks.
func dmlExtras(x *ast.DMLTargetFields) *ast.DMLTargetFields {
	if x != nil {
		return x
	}
	return &noDMLExtras
}

// writeDMLTargets writes the UPDATE / DELETE target list.
func writeDMLTargets(sb *strings.Builder, f *nodeFormatter, d *ast.DMLTargetFields, name string, nameQ ast.NameQuote, alias string, aliasQ ast.NameQuote) {
	if d.Only {
		sb.WriteString(f.kw("ONLY"))
		sb.WriteString(" ")
	}
	first := true
	if name != "" {
		sb.WriteString(ast.QuoteQualifiedNameWith(name, f.nq(nameQ)))
		if alias != "" {
			sb.WriteString(" ")
			sb.WriteString(ast.QuoteTableAliasWith(alias, f.nq(aliasQ)))
		}
		first = false
	}
	for i := range d.Tables {
		if !first {
			sb.WriteString(", ")
		}
		sb.WriteString(tableRefSQL(&d.Tables[i], f))
		first = false
	}
}

// writeDMLJoins writes the JOIN clauses of a multi-table UPDATE / DELETE.
func writeDMLJoins(sb *strings.Builder, f *nodeFormatter, joins []ast.JoinClause) {
	for i := range joins {
		sb.WriteString(f.clauseSep())
		sb.WriteString(joinSQL(&joins[i], f))
	}
}

// writeDMLOutput writes the SQL Server OUTPUT [INTO] clause.
func writeDMLOutput(sb *strings.Builder, f *nodeFormatter, output []ast.Expression, into *ast.OutputInto) {
	if len(output) == 0 {
		return
	}
	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("OUTPUT"))
	sb.WriteString(" ")
	sb.WriteString(exprListSQL(output))
	if into != nil && into.Target != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("INTO"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteQualifiedName(into.Target))
		if len(into.Columns) > 0 {
			sb.WriteString(" (")
			sb.WriteString(ast.ColumnRefListSQL(into.Columns))
			sb.WriteString(")")
		}
	}
}

// writeDMLOrderLimit writes the single-table ORDER BY ... LIMIT n clauses.
func writeDMLOrderLimit(sb *strings.Builder, f *nodeFormatter, d *ast.DMLTargetFields) {
	if len(d.OrderBy) > 0 {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("ORDER BY"))
		sb.WriteString(" ")
		sb.WriteString(orderBySQL(d.OrderBy))
	}
	if d.Limit != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("LIMIT"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(d.Limit))
	}
}

// writeReturning writes RETURNING items [INTO targets].
func writeReturning(sb *strings.Builder, f *nodeFormatter, returning, into []ast.Expression) {
	if len(returning) == 0 {
		return
	}
	sb.WriteString(f.clauseSep())
	sb.WriteString(f.kw("RETURNING"))
	sb.WriteString(" ")
	sb.WriteString(exprListSQL(returning))
	if len(into) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("INTO"))
		sb.WriteString(" ")
		sb.WriteString(exprListSQL(into))
	}
}

// writeInsertHead writes "INSERT [modifiers] INTO target".
func writeInsertHead(sb *strings.Builder, f *nodeFormatter, i *ast.InsertStatement) {
	sb.WriteString(f.kw("INSERT"))
	sb.WriteString(" ")
	writeDMLModifiers(sb, f, i.Modifiers)
	sb.WriteString(f.kw("INTO"))
	sb.WriteString(" ")
	if i.TableFunction != nil {
		sb.WriteString(f.kw("FUNCTION"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(i.TableFunction))
		return
	}
	sb.WriteString(ast.QuoteQualifiedNameWith(i.TableName, f.nq(i.TableNameQuote)))
}

// writeInsertBeforeSource writes ClickHouse SETTINGS and PostgreSQL
// OVERRIDING ... VALUE, which sit between the column list and the source.
func writeInsertBeforeSource(sb *strings.Builder, f *nodeFormatter, i *ast.InsertStatement) {
	if len(i.Settings) > 0 {
		sb.WriteString(" ")
		sb.WriteString(f.kw("SETTINGS"))
		sb.WriteString(" ")
		for k := range i.Settings {
			if k > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(i.Settings[k].SQL())
		}
	}
	if t := ast.OverridingText(i.Overriding); t != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("OVERRIDING " + t + " VALUE"))
	}
}

// writeInsertAfterSource writes the MySQL row alias AS name [(cols)].
func writeInsertAfterSource(sb *strings.Builder, f *nodeFormatter, i *ast.InsertStatement) {
	if i.RowAlias == "" {
		return
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("AS"))
	sb.WriteString(" ")
	sb.WriteString(ast.QuoteTableAlias(i.RowAlias))
	if len(i.RowAliasColumns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(quoteColumnNames(i.RowAliasColumns))
		sb.WriteString(")")
	}
}

// writeInsertTail writes RETURNING [INTO] and the ClickHouse FORMAT name.
func writeInsertTail(sb *strings.Builder, f *nodeFormatter, i *ast.InsertStatement) {
	writeReturning(sb, f, i.Returning, i.ReturningInto)
	if l := i.LogErrors; l != nil {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("LOG ERRORS"))
		if l.Into != "" {
			sb.WriteString(" ")
			sb.WriteString(f.kw("INTO"))
			sb.WriteString(" ")
			sb.WriteString(ast.QuoteQualifiedNameWith(l.Into, f.nq(l.IntoQuote)))
		}
		if l.Tag != nil {
			sb.WriteString(" (")
			sb.WriteString(exprSQL(l.Tag))
			sb.WriteString(")")
		}
		if lim := ast.LogErrorsRejectLimitText(l.RejectLimit); lim != "" {
			sb.WriteString(" ")
			sb.WriteString(f.kw("REJECT LIMIT"))
			sb.WriteString(" ")
			sb.WriteString(f.kw(lim))
		}
	}
	if i.DataFormat != "" {
		sb.WriteString(f.clauseSep())
		sb.WriteString(f.kw("FORMAT"))
		sb.WriteString(" ")
		sb.WriteString(formatNameSQL(i.DataFormat))
	}
}

// formatNameSQL writes a ClickHouse format name (CSV, JSONEachRow, Values)
// bare when it is a plain word and double-quoted otherwise.
func formatNameSQL(name string) string {
	for k := 0; k < len(name); k++ {
		c := name[k]
		if c != '_' && (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'z') {
			return ast.QuoteName(name)
		}
	}
	return name
}

// writeMergeTail writes the MERGE OUTPUT and RETURNING clauses.
func writeMergeTail(sb *strings.Builder, f *nodeFormatter, m *ast.MergeStatement) {
	writeDMLOutput(sb, f, m.Output, m.OutputInto)
	writeReturning(sb, f, m.Returning, nil)
}

// writeMergeActionWhere writes the Oracle WHERE / DELETE WHERE predicates of
// a MERGE action.
func writeMergeActionWhere(sb *strings.Builder, f *nodeFormatter, a *ast.MergeAction) {
	if a.Where != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(a.Where))
	}
	if a.DeleteWhere != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("DELETE WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(a.DeleteWhere))
	}
}
