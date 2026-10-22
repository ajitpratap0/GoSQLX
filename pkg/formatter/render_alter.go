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

// renderAlterStatement renders an *ast.AlterStatement. ALTER TABLE statements
// (every action the parser produces, comma-separated) are rendered in full;
// other ALTER kinds (ROLE, POLICY, CONNECTOR) keep the previous stmtSQL output.
func renderAlterStatement(a *ast.AlterStatement, opts ast.FormatOptions) string {
	if a == nil {
		return ""
	}
	if a.Type != ast.AlterTypeTable {
		return stmtSQL(a)
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(f.kw("ALTER"))
	for _, m := range a.Modifiers {
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw(m))
	}
	f.sb.WriteString(" ")
	f.sb.WriteString(f.kw("TABLE"))
	if a.IfExists {
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("IF EXISTS"))
	}
	if a.Only {
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("ONLY"))
	}
	f.sb.WriteString(" ")
	f.sb.WriteString(ast.QuoteQualifiedName(a.Name))
	if a.OnCluster != "" {
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("ON CLUSTER"))
		f.sb.WriteString(" ")
		f.sb.WriteString(a.OnCluster)
	}
	ops := a.Operations
	if len(ops) == 0 && a.Operation != nil {
		ops = []ast.AlterOperation{a.Operation}
	}
	first := true
	for _, o := range ops {
		op, ok := o.(*ast.AlterTableOperation)
		if !ok || op == nil {
			continue
		}
		if !first {
			f.sb.WriteString(",")
		}
		f.sb.WriteString(f.clauseSep())
		writeAlterTableOperation(f, op)
		first = false
	}
	if opts.AddSemicolon {
		f.sb.WriteString(";")
	}
	return f.result()
}

// alterIdentName returns the name of i, or "" for nil.
func alterIdentName(i *ast.Ident) string {
	if i == nil {
		return ""
	}
	return i.Name
}

// alterColName returns i as a column name, quoted when needed.
func alterColName(i *ast.Ident) string {
	return ast.QuoteColumnName(alterIdentName(i))
}

// alterColNames renders i followed by extra, comma-separated.
func alterColNames(i *ast.Ident, extra []*ast.Ident) string {
	parts := make([]string, 0, 1+len(extra))
	parts = append(parts, alterColName(i))
	for _, e := range extra {
		parts = append(parts, alterColName(e))
	}
	return strings.Join(parts, ", ")
}

// alterColumnKeyword returns "<verb> COLUMN" or "<verb>" when the action was
// written without the COLUMN keyword.
func alterColumnKeyword(f *nodeFormatter, verb string, op *ast.AlterTableOperation) string {
	if op.NoColumnKeyword {
		return f.kw(verb)
	}
	return f.kw(verb + " COLUMN")
}

// writeAlterColumnDefs renders the column definition(s) of an ADD / MODIFY.
func writeAlterColumnDefs(sb *strings.Builder, op *ast.AlterTableOperation) {
	defs := op.ColumnDefs
	if len(defs) == 0 && op.ColumnDef != nil {
		defs = []*ast.ColumnDef{op.ColumnDef}
	}
	if op.Parenthesized {
		sb.WriteString("(")
	}
	for i, d := range defs {
		if i > 0 {
			sb.WriteString(", ")
		}
		if d != nil {
			sb.WriteString(columnDefSQL(d))
		}
	}
	if op.Parenthesized {
		sb.WriteString(")")
	}
}

// writeAlterColumnPosition renders FIRST / AFTER column.
func writeAlterColumnPosition(f *nodeFormatter, op *ast.AlterTableOperation) {
	pos := op.ColumnPosition
	if pos == nil {
		return
	}
	switch {
	case pos.First:
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("FIRST"))
	case pos.After != nil:
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("AFTER"))
		f.sb.WriteString(" ")
		f.sb.WriteString(alterColName(pos.After))
	}
}

// writeAlterDropTail renders the CASCADE / RESTRICT that ends a DROP.
func writeAlterDropTail(f *nodeFormatter, op *ast.AlterTableOperation) {
	switch {
	case op.CascadeDrops:
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("CASCADE"))
	case op.Restrict:
		f.sb.WriteString(" ")
		f.sb.WriteString(f.kw("RESTRICT"))
	}
}

// writeAlterKeywordText renders a keyword phrase followed by text as written.
func writeAlterKeywordText(f *nodeFormatter, keyword, text string) {
	if keyword != "" {
		f.sb.WriteString(f.kw(keyword))
	}
	if keyword != "" && text != "" {
		f.sb.WriteString(" ")
	}
	f.sb.WriteString(text)
}

// writeAlterColumnSub renders the sub-action of ALTER / MODIFY COLUMN name.
func writeAlterColumnSub(f *nodeFormatter, op *ast.AlterTableOperation) {
	sb := f.sb
	switch *op.AlterColumnOp {
	case ast.AlterColumnSetDefault:
		sb.WriteString(f.kw("SET DEFAULT"))
		if op.DefaultValue != nil {
			sb.WriteString(" ")
			sb.WriteString(exprSQL(op.DefaultValue))
		}
	case ast.AlterColumnDropDefault:
		sb.WriteString(f.kw("DROP DEFAULT"))
	case ast.AlterColumnSetNotNull:
		sb.WriteString(f.kw("SET NOT NULL"))
	case ast.AlterColumnDropNotNull:
		sb.WriteString(f.kw("DROP NOT NULL"))
	case ast.AlterColumnSetDataType:
		kw := op.Keyword
		if kw == "" {
			kw = "TYPE"
		}
		sb.WriteString(f.kw(kw))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteDataType(op.DataType))
		if op.Using != nil {
			sb.WriteString(" ")
			sb.WriteString(f.kw("USING"))
			sb.WriteString(" ")
			sb.WriteString(exprSQL(op.Using))
		}
	case ast.AlterColumnOther:
		writeAlterKeywordText(f, op.Keyword, op.Text)
	}
}

// alterConstraintSQL renders the constraint of an ADD, with the SQL Server
// CLUSTERED / NONCLUSTERED word and any trailing attribute phrase.
func alterConstraintSQL(f *nodeFormatter, op *ast.AlterTableOperation) string {
	tc := op.Constraint
	s := tableConstraintSQL(tc)
	if op.Clustering != "" {
		prefix := ""
		if tc.Name != "" {
			prefix = "CONSTRAINT " + ast.QuoteConstraintName(tc.Name) + " "
		}
		if strings.HasPrefix(s, prefix+tc.Type) {
			rest := s[len(prefix)+len(tc.Type):]
			s = prefix + tc.Type + " " + f.kw(op.Clustering) + rest
		}
	}
	if op.ConstraintSuffix != "" {
		s += " " + op.ConstraintSuffix
	}
	return s
}

// writeAlterTableOperation renders a single ALTER TABLE operation. Operation
// types the ALTER TABLE parser does not produce are left empty.
func writeAlterTableOperation(f *nodeFormatter, op *ast.AlterTableOperation) {
	sb := f.sb
	if op.Modifier != "" {
		sb.WriteString(f.kw(op.Modifier))
		sb.WriteString(" ")
	}
	switch op.Type {
	case ast.AddColumn:
		sb.WriteString(alterColumnKeyword(f, "ADD", op))
		if op.IfNotExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF NOT EXISTS"))
		}
		if op.ColumnDef != nil || len(op.ColumnDefs) > 0 {
			sb.WriteString(" ")
			writeAlterColumnDefs(sb, op)
		}
		writeAlterColumnPosition(f, op)
	case ast.AddConstraint:
		sb.WriteString(f.kw("ADD"))
		if op.Constraint != nil {
			// tableConstraintSQL prints "CONSTRAINT name" itself when named.
			if op.Constraint.Name == "" && !op.BareConstraint {
				sb.WriteString(" ")
				sb.WriteString(f.kw("CONSTRAINT"))
			}
			sb.WriteString(" ")
			sb.WriteString(alterConstraintSQL(f, op))
		}
	case ast.AddIndex:
		sb.WriteString(f.kw("ADD"))
		if op.IndexKind != "" {
			sb.WriteString(" ")
			sb.WriteString(f.kw(op.IndexKind))
		}
		if op.IndexKeyword != "" {
			sb.WriteString(" ")
			sb.WriteString(f.kw(op.IndexKeyword))
		}
		if op.IfNotExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF NOT EXISTS"))
		}
		if op.IndexName != "" {
			sb.WriteString(" ")
			sb.WriteString(ast.QuoteColumnName(op.IndexName))
		}
		if op.Text != "" {
			sb.WriteString(" ")
			sb.WriteString(op.Text)
		}
	case ast.DropColumn:
		sb.WriteString(alterColumnKeyword(f, "DROP", op))
		if op.IfExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF EXISTS"))
		}
		sb.WriteString(" ")
		sb.WriteString(alterColNames(op.ColumnName, op.ExtraNames))
		writeAlterDropTail(f, op)
	case ast.DropConstraint:
		kind := "CONSTRAINT"
		if op.ConstraintKind != "" {
			kind = op.ConstraintKind
		}
		sb.WriteString(f.kw("DROP " + kind))
		if op.ConstraintKind == "PRIMARY KEY" {
			return
		}
		if op.IfExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF EXISTS"))
		}
		sb.WriteString(" ")
		names := []string{ast.QuoteConstraintName(alterIdentName(op.ConstraintName))}
		for _, e := range op.ExtraNames {
			names = append(names, ast.QuoteConstraintName(alterIdentName(e)))
		}
		sb.WriteString(strings.Join(names, ", "))
		writeAlterDropTail(f, op)
	case ast.DropIndex:
		kw := op.IndexKeyword
		if kw == "" {
			kw = "INDEX"
		}
		sb.WriteString(f.kw("DROP " + kw))
		if op.IfExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF EXISTS"))
		}
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteColumnName(op.IndexName))
	case ast.RenameTable:
		sb.WriteString(f.kw("RENAME TO"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteQualifiedName(op.NewTableName.Name))
	case ast.RenameColumn:
		oldName := op.ColumnName
		if oldName == nil {
			oldName = op.OldColumnName
		}
		sb.WriteString(alterColumnKeyword(f, "RENAME", op))
		if op.IfExists {
			sb.WriteString(" ")
			sb.WriteString(f.kw("IF EXISTS"))
		}
		sb.WriteString(" ")
		sb.WriteString(alterColName(oldName))
		sb.WriteString(" ")
		sb.WriteString(f.kw("TO"))
		sb.WriteString(" ")
		sb.WriteString(alterColName(op.NewColumnName))
	case ast.RenameConstraint:
		sb.WriteString(f.kw("RENAME CONSTRAINT"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteConstraintName(alterIdentName(op.OldName)))
		sb.WriteString(" ")
		sb.WriteString(f.kw("TO"))
		sb.WriteString(" ")
		sb.WriteString(ast.QuoteConstraintName(alterIdentName(op.NewName)))
	case ast.AlterColumn:
		sb.WriteString(alterColumnKeyword(f, "ALTER", op))
		writeAlterColumnTarget(f, op)
		writeAlterColumnPosition(f, op)
	case ast.ModifyColumn:
		sb.WriteString(alterColumnKeyword(f, "MODIFY", op))
		if op.AlterColumnOp == nil && op.ColumnName == nil {
			if op.ColumnDef != nil || len(op.ColumnDefs) > 0 {
				sb.WriteString(" ")
				writeAlterColumnDefs(sb, op)
			}
		} else {
			writeAlterColumnTarget(f, op)
		}
		writeAlterColumnPosition(f, op)
	case ast.ChangeColumn:
		sb.WriteString(alterColumnKeyword(f, "CHANGE", op))
		sb.WriteString(" ")
		sb.WriteString(alterColName(op.ColumnName))
		if op.ColumnDef != nil {
			sb.WriteString(" ")
			sb.WriteString(columnDefSQL(op.ColumnDef))
		}
		writeAlterColumnPosition(f, op)
	case ast.AlterTableOther:
		writeAlterKeywordText(f, op.Keyword, op.Text)
	case ast.UpdateMutation:
		sb.WriteString(f.kw("UPDATE"))
		sb.WriteString(" ")
		for i := range op.Assignments {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(exprSQL(op.Assignments[i].Column))
			sb.WriteString(" = ")
			sb.WriteString(exprSQL(op.Assignments[i].Value))
		}
		writeAlterMutationTail(f, op)
	case ast.DeleteMutation:
		sb.WriteString(f.kw("DELETE"))
		writeAlterMutationTail(f, op)
	}
}

// writeAlterColumnTarget renders the part of ALTER / MODIFY COLUMN after the
// verb: the column name and its sub-action, or a full column definition.
func writeAlterColumnTarget(f *nodeFormatter, op *ast.AlterTableOperation) {
	sb := f.sb
	if op.AlterColumnOp != nil {
		sb.WriteString(" ")
		sb.WriteString(alterColName(op.ColumnName))
		sb.WriteString(" ")
		writeAlterColumnSub(f, op)
		return
	}
	if op.ColumnDef == nil {
		if op.ColumnName != nil {
			sb.WriteString(" ")
			sb.WriteString(alterColName(op.ColumnName))
		}
		return
	}
	// The full definition names the column; an older AST kept the column name
	// in ColumnName and the rest of the clause in ColumnDef.
	if op.ColumnName != nil && op.ColumnName.Name != op.ColumnDef.Name {
		sb.WriteString(" ")
		sb.WriteString(alterColName(op.ColumnName))
	}
	sb.WriteString(" ")
	sb.WriteString(columnDefSQL(op.ColumnDef))
}

// writeAlterMutationTail renders [IN PARTITION p] [WHERE cond] of a
// ClickHouse mutation.
func writeAlterMutationTail(f *nodeFormatter, op *ast.AlterTableOperation) {
	sb := f.sb
	if op.PartitionExpr != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("IN PARTITION"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(op.PartitionExpr))
	}
	if op.Where != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("WHERE"))
		sb.WriteString(" ")
		sb.WriteString(exprSQL(op.Where))
	}
}
