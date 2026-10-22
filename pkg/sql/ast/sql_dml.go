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

import "bytes"

// dmlModifierKeywords are the statement modifiers the parser stores in
// DMLTargetFields.Modifiers and InsertDialectFields.Modifiers.
var dmlModifierKeywords = []string{
	"LOW_PRIORITY", "HIGH_PRIORITY", "DELAYED", "QUICK", "IGNORE", "OVERWRITE",
	"OR REPLACE", "OR IGNORE", "OR ABORT", "OR FAIL", "OR ROLLBACK",
}

// DMLModifierText returns s when it is a known INSERT / UPDATE / DELETE
// modifier (LOW_PRIORITY, IGNORE, OR REPLACE, OVERWRITE, ...; any case) and
// "" otherwise. Renderers drop an unknown modifier instead of writing
// arbitrary text into the statement.
func DMLModifierText(s string) string { return keywordOneOf(s, dmlModifierKeywords) }

// OverridingText returns s when it is SYSTEM or USER (any case), the kinds
// of PostgreSQL OVERRIDING ... VALUE, and "" otherwise.
func OverridingText(s string) string { return keywordOneOf(s, overridingKeywords) }

var overridingKeywords = []string{"SYSTEM", "USER"}

// writeDMLModifiers writes each known modifier followed by a space.
func writeDMLModifiers(buf *bytes.Buffer, mods []string) {
	for _, m := range mods {
		if t := DMLModifierText(m); t != "" {
			buf.WriteString(t)
			buf.WriteByte(' ')
		}
	}
}

// writeDMLTop writes "TOP (n) [PERCENT] " (DML requires the parentheses).
func writeDMLTop(buf *bytes.Buffer, top *TopClause) {
	if top == nil || top.Count == nil {
		return
	}
	buf.WriteString("TOP (")
	writeExpr(buf, top.Count)
	buf.WriteByte(')')
	if top.IsPercent {
		buf.WriteString(" PERCENT")
	}
	buf.WriteByte(' ')
}

// writeDMLTargets writes the target list: name [alias] followed by Tables.
func (d *DMLTargetFields) writeDMLTargets(buf *bytes.Buffer, name, alias string) {
	if d.Only {
		buf.WriteString("ONLY ")
	}
	first := true
	if name != "" {
		writeQualifiedNameQ(buf, name, d.TableNameQuote)
		if alias != "" {
			buf.WriteByte(' ')
			writeTableAliasQ(buf, alias, d.AliasQuote)
		}
		first = false
	}
	for i := range d.Tables {
		if !first {
			buf.WriteString(", ")
		}
		writeTableRef(buf, &d.Tables[i])
		first = false
	}
}

// writeDMLJoins writes " JOIN ..." for every join.
func writeDMLJoins(buf *bytes.Buffer, joins []JoinClause) {
	for i := range joins {
		buf.WriteByte(' ')
		writeJoin(buf, &joins[i])
	}
}

// writeDMLOutput writes " OUTPUT items [INTO target [(cols)]]".
func writeDMLOutput(buf *bytes.Buffer, output []Expression, into *OutputInto) {
	if len(output) == 0 {
		return
	}
	buf.WriteString(" OUTPUT ")
	writeExprList(buf, output)
	if into != nil && into.Target != "" {
		buf.WriteString(" INTO ")
		writeQualifiedName(buf, into.Target)
		if len(into.Columns) > 0 {
			buf.WriteString(" (")
			writeColumnRefList(buf, into.Columns)
			buf.WriteByte(')')
		}
	}
}

// writeDMLOrderLimit writes " ORDER BY ... LIMIT n".
func (d *DMLTargetFields) writeDMLOrderLimit(buf *bytes.Buffer) {
	if len(d.OrderBy) > 0 {
		buf.WriteString(" ORDER BY ")
		writeOrderBy(buf, d.OrderBy)
	}
	if d.Limit != nil {
		buf.WriteString(" LIMIT ")
		writeExpr(buf, d.Limit)
	}
}

// writeReturning writes " RETURNING items [INTO targets]".
func writeReturning(buf *bytes.Buffer, returning, into []Expression) {
	if len(returning) == 0 {
		return
	}
	buf.WriteString(" RETURNING ")
	writeExprList(buf, returning)
	if len(into) > 0 {
		buf.WriteString(" INTO ")
		writeExprList(buf, into)
	}
}

// writeInsertHead writes "INSERT [modifiers] INTO target" for an INSERT
// statement, including the ClickHouse FUNCTION target.
func (i *InsertStatement) writeInsertHead(buf *bytes.Buffer) {
	buf.WriteString("INSERT ")
	writeDMLModifiers(buf, i.Modifiers)
	buf.WriteString("INTO ")
	if i.TableFunction != nil {
		buf.WriteString("FUNCTION ")
		i.TableFunction.writeSQL(buf)
		return
	}
	writeQualifiedNameQ(buf, i.TableName, i.TableNameQuote)
}

// writeInsertBeforeSource writes the clauses between the column list and the
// row source: ClickHouse SETTINGS and PostgreSQL OVERRIDING ... VALUE.
func (i *InsertStatement) writeInsertBeforeSource(buf *bytes.Buffer) {
	if len(i.Settings) > 0 {
		buf.WriteString(" SETTINGS ")
		writeQuerySettings(buf, i.Settings)
	}
	if t := OverridingText(i.Overriding); t != "" {
		buf.WriteString(" OVERRIDING ")
		buf.WriteString(t)
		buf.WriteString(" VALUE")
	}
}

// writeInsertRowAlias writes the MySQL row alias " AS name [(cols)]".
func (i *InsertStatement) writeInsertRowAlias(buf *bytes.Buffer) {
	if i.RowAlias == "" {
		return
	}
	buf.WriteString(" AS ")
	writeTableAlias(buf, i.RowAlias)
	if len(i.RowAliasColumns) > 0 {
		buf.WriteString(" (")
		writeColumnNameList(buf, i.RowAliasColumns)
		buf.WriteByte(')')
	}
}

// writeInsertFormat writes the ClickHouse " FORMAT name" suffix.
func (i *InsertStatement) writeInsertFormat(buf *bytes.Buffer) {
	if i.DataFormat != "" {
		buf.WriteString(" FORMAT ")
		writeSafeIdentifier(buf, i.DataFormat)
	}
}

// writeMultiTableInsert writes an Oracle INSERT ALL / INSERT FIRST statement.
func (i *InsertStatement) writeMultiTableInsert(buf *bytes.Buffer) {
	m := i.MultiTable
	if m.First {
		buf.WriteString("INSERT FIRST")
	} else {
		buf.WriteString("INSERT ALL")
	}
	for bi := range m.Branches {
		b := &m.Branches[bi]
		switch {
		case b.Else:
			buf.WriteString(" ELSE")
		case b.When != nil:
			buf.WriteString(" WHEN ")
			writeExpr(buf, b.When)
			buf.WriteString(" THEN")
		}
		for j := range b.Into {
			in := &b.Into[j]
			buf.WriteString(" INTO ")
			writeQualifiedName(buf, in.Table)
			if len(in.Columns) > 0 {
				buf.WriteString(" (")
				writeColumnRefList(buf, in.Columns)
				buf.WriteByte(')')
			}
			if in.Values != nil {
				buf.WriteString(" VALUES (")
				writeExprList(buf, in.Values)
				buf.WriteByte(')')
			}
		}
	}
	if i.Query != nil {
		buf.WriteByte(' ')
		writeStmt(buf, i.Query)
	}
}

// writeMergeTail writes the MERGE OUTPUT and RETURNING clauses.
func (m *MergeStatement) writeMergeTail(buf *bytes.Buffer) {
	writeDMLOutput(buf, m.Output, m.OutputInto)
	writeReturning(buf, m.Returning, nil)
}

// mergeActionWhereSQL returns the Oracle " WHERE c" and " DELETE WHERE c"
// action predicates.
func mergeActionWhereSQL(a *MergeAction) string {
	if a.Where == nil && a.DeleteWhere == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	if a.Where != nil {
		buf.WriteString(" WHERE ")
		writeExpr(buf, a.Where)
	}
	if a.DeleteWhere != nil {
		buf.WriteString(" DELETE WHERE ")
		writeExpr(buf, a.DeleteWhere)
	}
	return buf.String()
}

// MergeActionWhereSQL returns the Oracle WHERE / DELETE WHERE predicates of
// a MERGE action, each with a leading space, or "" when there are none.
func MergeActionWhereSQL(a *MergeAction) string {
	if a == nil {
		return ""
	}
	return mergeActionWhereSQL(a)
}

// writeReplaceSQL writes a REPLACE statement in the form it was parsed.
func (r *ReplaceStatement) writeReplaceSQL(buf *bytes.Buffer) {
	buf.WriteString("REPLACE INTO ")
	writeQualifiedName(buf, r.TableName)
	if r.SetSyntax && r.Query == nil && len(r.Values) == 1 && len(r.Values[0]) == len(r.Columns) && len(r.Columns) > 0 {
		buf.WriteString(" SET ")
		for idx, col := range r.Columns {
			if idx > 0 {
				buf.WriteString(", ")
			}
			writeColumnRef(buf, col)
			buf.WriteString(" = ")
			writeExpr(buf, r.Values[0][idx])
		}
	} else {
		if len(r.Columns) > 0 {
			buf.WriteString(" (")
			writeColumnRefList(buf, r.Columns)
			buf.WriteByte(')')
		}
		if r.Query != nil {
			buf.WriteByte(' ')
			writeStmt(buf, r.Query)
		} else if len(r.Values) > 0 {
			buf.WriteString(" VALUES ")
			writeValueRows(buf, r.Values)
		}
	}
	writeReturning(buf, r.Returning, nil)
}
