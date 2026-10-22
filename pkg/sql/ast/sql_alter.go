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

// sql_alter.go - shared SQL writer for ALTER TABLE, ALTER ROLE, ALTER POLICY
// and ALTER CONNECTOR. AlterStatement.SQL() and the formatter both use it;
// DDLStyle carries the formatter's keyword casing and clause separator.

package ast

import (
	"bytes"
	"sort"
	"strings"
)

// SQL returns the SQL representation of this ALTER statement. ALTER TABLE
// (every action the parser produces), ALTER ROLE, ALTER POLICY and ALTER
// CONNECTOR are written in full; a statement with no operation is "ALTER".
func (a *AlterStatement) SQL() string {
	if a == nil {
		return ""
	}
	return AlterSQL(a, DDLStyle{})
}

// AlterSQL renders an ALTER statement with the keyword casing, nested
// rendering, name delimiters and clause separator of st. It writes no
// trailing semicolon. A statement without a renderable operation yields the
// bare "ALTER" keyword.
func AlterSQL(a *AlterStatement, st DDLStyle) string {
	if a == nil {
		return ""
	}
	buf := getBuf()
	defer putBuf(buf)
	w := alterWriter{buf: buf, st: st}
	if a.Type != AlterTypeTable {
		if !w.writeOther(a) {
			buf.WriteString(st.kw("ALTER"))
		}
		return buf.String()
	}
	w.writeTable(a)
	return buf.String()
}

// alterWriter carries the output buffer and style of one ALTER rendering.
type alterWriter struct {
	buf *bytes.Buffer
	st  DDLStyle
}

func (w alterWriter) kw(k string) string { return w.st.kw(k) }

func (w alterWriter) str(s string) { w.buf.WriteString(s) }

// kwStr writes keyword k cased by the style.
func (w alterWriter) kwStr(k string) { w.buf.WriteString(w.st.kw(k)) }

func (w alterWriter) expr(e Expression) { w.st.writeExpr(w.buf, e) }

func (w alterWriter) exprStr(e Expression) string {
	b := getBuf()
	defer putBuf(b)
	w.st.writeExpr(b, e)
	return b.String()
}

// writeTable writes ALTER [modifiers] TABLE ... and every action.
func (w alterWriter) writeTable(a *AlterStatement) {
	w.kwStr("ALTER")
	for _, m := range a.Modifiers {
		if m = alterWordsText(m); m != "" {
			w.str(" ")
			w.kwStr(m)
		}
	}
	w.str(" ")
	w.kwStr("TABLE")
	if a.IfExists {
		w.str(" ")
		w.kwStr("IF EXISTS")
	}
	if a.Only {
		w.str(" ")
		w.kwStr("ONLY")
	}
	w.str(" ")
	w.str(QuoteQualifiedNameWith(a.Name, w.st.nq(a.NameQuote)))
	if cluster := alterClusterText(a.OnCluster); cluster != "" {
		w.str(" ")
		w.kwStr("ON CLUSTER")
		w.str(" ")
		w.str(cluster)
	}
	ops := a.Operations
	if len(ops) == 0 && a.Operation != nil {
		ops = []AlterOperation{a.Operation}
	}
	first := true
	for _, o := range ops {
		op, ok := o.(*AlterTableOperation)
		if !ok || op == nil {
			continue
		}
		if !first {
			w.str(",")
		}
		w.str(w.st.sep())
		w.writeOperation(op)
		first = false
	}
}

// identName returns the name of i quoted as a column name when it needs
// delimiters (or the source's are recorded); nil renders as an empty name.
func (w alterWriter) identName(i *Ident) string {
	if i == nil {
		return QuoteColumnName("")
	}
	return QuoteColumnNameWith(i.Name, w.st.nq(i.Quote))
}

// constraintName returns i as a constraint name, quoted when needed and
// honouring its recorded delimiters.
func (w alterWriter) constraintName(i *Ident) string {
	if i == nil {
		return QuoteConstraintName("")
	}
	return QuoteConstraintNameWith(i.Name, w.st.nq(i.Quote))
}

// colNames renders i followed by extra, comma-separated.
func (w alterWriter) colNames(i *Ident, extra []*Ident) string {
	parts := make([]string, 0, 1+len(extra))
	parts = append(parts, w.identName(i))
	for _, e := range extra {
		parts = append(parts, w.identName(e))
	}
	return strings.Join(parts, ", ")
}

// columnKeyword returns "<verb> COLUMN" or "<verb>" when the action was
// written without the COLUMN keyword.
func (w alterWriter) columnKeyword(verb string, op *AlterTableOperation) string {
	if op.NoColumnKeyword {
		return w.kw(verb)
	}
	return w.kw(verb + " COLUMN")
}

// writeColumnDefs renders the column definition(s) of an ADD / MODIFY.
func (w alterWriter) writeColumnDefs(op *AlterTableOperation) {
	defs := op.ColumnDefs
	if len(defs) == 0 && op.ColumnDef != nil {
		defs = []*ColumnDef{op.ColumnDef}
	}
	if op.Parenthesized {
		w.str("(")
	}
	for i, d := range defs {
		if i > 0 {
			w.str(", ")
		}
		if d != nil {
			w.str(columnDefSQL(d))
		}
	}
	if op.Parenthesized {
		w.str(")")
	}
}

// writeColumnPosition renders FIRST / AFTER column.
func (w alterWriter) writeColumnPosition(op *AlterTableOperation) {
	pos := op.ColumnPosition
	if pos == nil {
		return
	}
	switch {
	case pos.First:
		w.str(" ")
		w.kwStr("FIRST")
	case pos.After != nil:
		w.str(" ")
		w.kwStr("AFTER")
		w.str(" ")
		w.str(w.identName(pos.After))
	}
}

// writeDropTail renders the CASCADE / RESTRICT that ends a DROP.
func (w alterWriter) writeDropTail(op *AlterTableOperation) {
	switch {
	case op.CascadeDrops:
		w.str(" ")
		w.kwStr("CASCADE")
	case op.Restrict:
		w.str(" ")
		w.kwStr("RESTRICT")
	}
}

// writeKeywordText renders a keyword phrase followed by text as written.
func (w alterWriter) writeKeywordText(keyword, text string) {
	keyword = alterWordsText(keyword)
	if keyword != "" {
		w.kwStr(keyword)
	}
	if keyword != "" && text != "" {
		w.str(" ")
	}
	w.str(text)
}

// writeColumnSub renders the sub-action of ALTER / MODIFY COLUMN name.
func (w alterWriter) writeColumnSub(op *AlterTableOperation) {
	switch *op.AlterColumnOp {
	case AlterColumnSetDefault:
		w.kwStr("SET DEFAULT")
		if op.DefaultValue != nil {
			w.str(" ")
			w.expr(op.DefaultValue)
		}
	case AlterColumnDropDefault:
		w.kwStr("DROP DEFAULT")
	case AlterColumnSetNotNull:
		w.kwStr("SET NOT NULL")
	case AlterColumnDropNotNull:
		w.kwStr("DROP NOT NULL")
	case AlterColumnSetDataType:
		kw := alterWordsText(op.Keyword)
		if kw == "" {
			kw = "TYPE"
		}
		w.kwStr(kw)
		w.str(" ")
		w.str(QuoteDataType(op.DataType))
		if op.Using != nil {
			w.str(" ")
			w.kwStr("USING")
			w.str(" ")
			w.expr(op.Using)
		}
	case AlterColumnOther:
		w.writeKeywordText(op.Keyword, op.Text)
	}
}

// constraintText renders the constraint of an ADD, with the SQL Server
// CLUSTERED / NONCLUSTERED word and any trailing attribute phrase.
func (w alterWriter) constraintText(op *AlterTableOperation) string {
	tc := op.Constraint
	s := tableConstraintSQL(tc)
	if op.Clustering != "" {
		prefix := ""
		if tc.Name != "" {
			prefix = "CONSTRAINT " + QuoteConstraintNameWith(tc.Name, tc.NameQuote) + " "
		}
		if strings.HasPrefix(s, prefix+tc.Type) {
			rest := s[len(prefix)+len(tc.Type):]
			s = prefix + tc.Type + " " + w.kw(op.Clustering) + rest
		}
	}
	if op.ConstraintSuffix != "" {
		s += " " + op.ConstraintSuffix
	}
	return s
}

// writeOperation renders a single ALTER TABLE operation. Operation types the
// ALTER TABLE parser does not produce are left empty.
func (w alterWriter) writeOperation(op *AlterTableOperation) {
	if m := alterWordsText(op.Modifier); m != "" {
		w.kwStr(m)
		w.str(" ")
	}
	switch op.Type {
	case AddColumn:
		w.str(w.columnKeyword("ADD", op))
		if op.IfNotExists {
			w.str(" ")
			w.kwStr("IF NOT EXISTS")
		}
		if op.ColumnDef != nil || len(op.ColumnDefs) > 0 {
			w.str(" ")
			w.writeColumnDefs(op)
		}
		w.writeColumnPosition(op)
	case AddConstraint:
		w.kwStr("ADD")
		if op.Constraint != nil {
			// tableConstraintSQL prints "CONSTRAINT name" itself when named.
			if op.Constraint.Name == "" && !op.BareConstraint {
				w.str(" ")
				w.kwStr("CONSTRAINT")
			}
			w.str(" ")
			w.str(w.constraintText(op))
		}
	case AddIndex:
		w.kwStr("ADD")
		if k := alterWordsText(op.IndexKind); k != "" {
			w.str(" ")
			w.kwStr(k)
		}
		if k := alterWordsText(op.IndexKeyword); k != "" {
			w.str(" ")
			w.kwStr(k)
		}
		if op.IfNotExists {
			w.str(" ")
			w.kwStr("IF NOT EXISTS")
		}
		if op.IndexName != "" {
			w.str(" ")
			w.str(QuoteColumnNameWith(op.IndexName, w.st.nq(op.IndexNameQuote)))
		}
		if op.Text != "" {
			w.str(" ")
			w.str(op.Text)
		}
	case DropColumn:
		w.str(w.columnKeyword("DROP", op))
		if op.IfExists {
			w.str(" ")
			w.kwStr("IF EXISTS")
		}
		w.str(" ")
		w.str(w.colNames(op.ColumnName, op.ExtraNames))
		w.writeDropTail(op)
	case DropConstraint:
		kind := "CONSTRAINT"
		if k := alterWordsText(op.ConstraintKind); k != "" {
			kind = k
		}
		w.kwStr("DROP " + kind)
		if op.ConstraintKind == "PRIMARY KEY" {
			return
		}
		if op.IfExists {
			w.str(" ")
			w.kwStr("IF EXISTS")
		}
		w.str(" ")
		names := []string{w.constraintName(op.ConstraintName)}
		for _, e := range op.ExtraNames {
			names = append(names, w.constraintName(e))
		}
		w.str(strings.Join(names, ", "))
		w.writeDropTail(op)
	case DropIndex:
		kw := alterWordsText(op.IndexKeyword)
		if kw == "" {
			kw = "INDEX"
		}
		w.kwStr("DROP " + kw)
		if op.IfExists {
			w.str(" ")
			w.kwStr("IF EXISTS")
		}
		w.str(" ")
		w.str(QuoteColumnNameWith(op.IndexName, w.st.nq(op.IndexNameQuote)))
	case RenameTable:
		w.kwStr("RENAME TO")
		w.str(" ")
		w.str(QuoteQualifiedNameWith(op.NewTableName.Name, w.st.nq(op.NewTableName.Quote)))
	case RenameColumn:
		oldName := op.ColumnName
		if oldName == nil {
			oldName = op.OldColumnName
		}
		w.str(w.columnKeyword("RENAME", op))
		if op.IfExists {
			w.str(" ")
			w.kwStr("IF EXISTS")
		}
		w.str(" ")
		w.str(w.identName(oldName))
		w.str(" ")
		w.kwStr("TO")
		w.str(" ")
		w.str(w.identName(op.NewColumnName))
	case RenameConstraint:
		w.kwStr("RENAME CONSTRAINT")
		w.str(" ")
		w.str(w.constraintName(op.OldName))
		w.str(" ")
		w.kwStr("TO")
		w.str(" ")
		w.str(w.constraintName(op.NewName))
	case AlterColumn:
		w.str(w.columnKeyword("ALTER", op))
		w.writeColumnTarget(op)
		w.writeColumnPosition(op)
	case ModifyColumn:
		w.str(w.columnKeyword("MODIFY", op))
		if op.AlterColumnOp == nil && op.ColumnName == nil {
			if op.ColumnDef != nil || len(op.ColumnDefs) > 0 {
				w.str(" ")
				w.writeColumnDefs(op)
			}
		} else {
			w.writeColumnTarget(op)
		}
		w.writeColumnPosition(op)
	case ChangeColumn:
		w.str(w.columnKeyword("CHANGE", op))
		w.str(" ")
		w.str(w.identName(op.ColumnName))
		if op.ColumnDef != nil {
			w.str(" ")
			w.str(columnDefSQL(op.ColumnDef))
		}
		w.writeColumnPosition(op)
	case AlterTableOther:
		w.writeKeywordText(op.Keyword, op.Text)
	case UpdateMutation:
		w.kwStr("UPDATE")
		w.str(" ")
		for i := range op.Assignments {
			if i > 0 {
				w.str(", ")
			}
			w.expr(op.Assignments[i].Column)
			w.str(" = ")
			w.expr(op.Assignments[i].Value)
		}
		w.writeMutationTail(op)
	case DeleteMutation:
		w.kwStr("DELETE")
		w.writeMutationTail(op)
	}
}

// writeColumnTarget renders the part of ALTER / MODIFY COLUMN after the
// verb: the column name and its sub-action, or a full column definition.
func (w alterWriter) writeColumnTarget(op *AlterTableOperation) {
	if op.AlterColumnOp != nil {
		w.str(" ")
		w.str(w.identName(op.ColumnName))
		w.str(" ")
		w.writeColumnSub(op)
		return
	}
	if op.ColumnDef == nil {
		if op.ColumnName != nil {
			w.str(" ")
			w.str(w.identName(op.ColumnName))
		}
		return
	}
	// The full definition names the column; an older AST kept the column name
	// in ColumnName and the rest of the clause in ColumnDef.
	if op.ColumnName != nil && op.ColumnName.Name != op.ColumnDef.Name {
		w.str(" ")
		w.str(w.identName(op.ColumnName))
	}
	w.str(" ")
	w.str(columnDefSQL(op.ColumnDef))
}

// writeMutationTail renders [IN PARTITION p] [WHERE cond] of a ClickHouse
// mutation.
func (w alterWriter) writeMutationTail(op *AlterTableOperation) {
	if op.PartitionExpr != nil {
		w.str(" ")
		w.kwStr("IN PARTITION")
		w.str(" ")
		w.expr(op.PartitionExpr)
	}
	if op.Where != nil {
		w.str(" ")
		w.kwStr("WHERE")
		w.str(" ")
		w.expr(op.Where)
	}
}

// writeOther renders ALTER ROLE, ALTER POLICY and ALTER CONNECTOR. It
// reports false, writing nothing, when the statement has no operation of the
// matching kind.
func (w alterWriter) writeOther(a *AlterStatement) bool {
	switch op := a.Operation.(type) {
	case *AlterRoleOperation:
		if a.Type != AlterTypeRole || op == nil {
			return false
		}
		w.kwStr("ALTER ROLE")
		w.str(" ")
		w.str(QuoteColumnNameWith(a.Name, w.st.nq(a.NameQuote)))
		w.str(w.st.sep())
		w.writeRoleOperation(op)
	case *AlterPolicyOperation:
		if a.Type != AlterTypePolicy || op == nil {
			return false
		}
		w.kwStr("ALTER POLICY")
		w.str(" ")
		w.str(QuoteColumnNameWith(a.Name, w.st.nq(a.NameQuote)))
		w.str(" ")
		w.kwStr("ON")
		w.str(" ")
		w.str(QuoteQualifiedNameWith(op.Table, w.st.nq(op.TableQuote)))
		w.str(w.st.sep())
		w.writePolicyOperation(op)
	case *AlterConnectorOperation:
		if a.Type != AlterTypeConnector || op == nil {
			return false
		}
		w.kwStr("ALTER CONNECTOR")
		w.str(" ")
		w.str(QuoteColumnNameWith(a.Name, w.st.nq(a.NameQuote)))
		w.str(w.st.sep())
		w.writeConnectorOperation(op)
	default:
		return false
	}
	return true
}

// writeRoleOperation renders the action of ALTER ROLE.
func (w alterWriter) writeRoleOperation(op *AlterRoleOperation) {
	switch op.Type {
	case RenameRole:
		w.kwStr("RENAME TO")
		w.str(" ")
		w.str(QuoteColumnNameWith(op.NewName, w.st.nq(op.NewNameQuote)))
	case AddMember:
		w.kwStr("ADD MEMBER")
		w.str(" ")
		w.str(QuoteColumnNameWith(op.MemberName, w.st.nq(op.MemberNameQuote)))
	case DropMember:
		w.kwStr("DROP MEMBER")
		w.str(" ")
		w.str(QuoteColumnNameWith(op.MemberName, w.st.nq(op.MemberNameQuote)))
	case SetConfig:
		w.kwStr("SET")
		w.str(" ")
		w.str(QuoteColumnName(op.ConfigName))
		if op.ConfigValue != nil {
			w.str(" ")
			w.kwStr("TO")
			w.str(" ")
			w.expr(op.ConfigValue)
		}
	case ResetConfig:
		w.kwStr("RESET")
		w.str(" ")
		if op.ConfigName == "ALL" {
			w.kwStr("ALL")
		} else {
			w.str(QuoteColumnName(op.ConfigName))
		}
	case WithOptions:
		w.kwStr("WITH")
		for i := range op.Options {
			if i > 0 {
				w.str(",")
			}
			w.str(" ")
			w.str(w.roleOption(&op.Options[i]))
		}
	}
}

// roleOption renders one role option; the value of PASSWORD and VALID UNTIL
// is an expression rendered as SQL.
func (w alterWriter) roleOption(opt *RoleOption) string {
	switch opt.Type {
	case Password:
		if e, ok := opt.Value.(Expression); ok && e != nil {
			return w.kw("PASSWORD") + " " + w.exprStr(e)
		}
		return w.kw("PASSWORD NULL")
	case ValidUntil:
		if e, ok := opt.Value.(Expression); ok && e != nil {
			return w.kw("VALID UNTIL") + " " + w.exprStr(e)
		}
		return w.kw("VALID UNTIL")
	}
	return w.kw(opt.String())
}

// writePolicyOperation renders the action of ALTER POLICY.
func (w alterWriter) writePolicyOperation(op *AlterPolicyOperation) {
	if op.Type == RenamePolicy {
		w.kwStr("RENAME TO")
		w.str(" ")
		w.str(QuoteColumnNameWith(op.NewName, w.st.nq(op.NewNameQuote)))
		return
	}
	var parts []string
	if len(op.To) > 0 {
		names := make([]string, len(op.To))
		for i, n := range op.To {
			names[i] = QuoteColumnNameWith(n, w.st.nq(nameQuoteAt(op.ToQuotes, i)))
		}
		parts = append(parts, w.kw("TO")+" "+strings.Join(names, ", "))
	}
	if op.Using != nil {
		parts = append(parts, w.kw("USING")+" ("+w.exprStr(op.Using)+")")
	}
	if op.WithCheck != nil {
		parts = append(parts, w.kw("WITH CHECK")+" ("+w.exprStr(op.WithCheck)+")")
	}
	w.str(strings.Join(parts, w.st.sep()))
}

// writeConnectorOperation renders the action of ALTER CONNECTOR.
func (w alterWriter) writeConnectorOperation(op *AlterConnectorOperation) {
	w.kwStr("SET")
	w.str(" ")
	switch {
	case op.Properties != nil:
		keys := make([]string, 0, len(op.Properties))
		for k := range op.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.kwStr("DCPROPERTIES")
		w.str(" (")
		for i, k := range keys {
			if i > 0 {
				w.str(", ")
			}
			w.str(alterStringLiteral(k))
			w.str(" = ")
			w.str(alterStringLiteral(op.Properties[k]))
		}
		w.str(")")
	case op.Owner != nil:
		w.kwStr("OWNER")
		w.str(" ")
		if op.Owner.IsUser {
			w.kwStr("USER")
		} else {
			w.kwStr("ROLE")
		}
		w.str(" ")
		w.str(QuoteColumnNameWith(op.Owner.Name, w.st.nq(op.Owner.NameQuote)))
	default:
		w.kwStr("URL")
		w.str(" ")
		w.str(alterStringLiteral(op.URL))
	}
}

// alterStringLiteral renders s as a single-quoted string literal.
func alterStringLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// alterWordsText returns s when it is one or more bare words (an ASCII letter
// or '_' followed by letters, digits and '_') separated by single spaces, and
// "" otherwise. The parser only stores such words in the keyword fields of an
// ALTER statement; a hand-built field holding anything else is dropped rather
// than written verbatim (#632).
func alterWordsText(s string) string {
	if s == "" {
		return ""
	}
	for _, w := range strings.Split(s, " ") {
		if w == "" {
			return ""
		}
		for i := 0; i < len(w); i++ {
			c := w[i]
			letter := c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z')
			if !letter && (i == 0 || c < '0' || c > '9') {
				return ""
			}
		}
	}
	return s
}

// alterClusterText returns the ClickHouse ON CLUSTER target c as the parser
// stores it (a single-quoted string, a "..." or `...` identifier, or a bare
// name) when it is well formed, and c as a quoted name otherwise (#632).
func alterClusterText(c string) string {
	if c == "" {
		return ""
	}
	for _, q := range []string{"'", `"`, "`"} {
		if n := len(c); n >= 2 && c[:1] == q && c[n-1:] == q &&
			!strings.Contains(strings.ReplaceAll(c[1:n-1], q+q, ""), q) {
			return c
		}
	}
	return QuoteQualifiedName(c)
}
