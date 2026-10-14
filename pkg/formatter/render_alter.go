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

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// renderAlterStatement renders an *ast.AlterStatement. ALTER TABLE operations
// produced by the parser (ADD COLUMN, ADD CONSTRAINT, DROP COLUMN, DROP
// CONSTRAINT, RENAME TO, RENAME COLUMN, ALTER COLUMN) are rendered in full;
// other ALTER kinds (ROLE, POLICY, CONNECTOR) keep the previous stmtSQL output.
func renderAlterStatement(a *ast.AlterStatement, opts ast.FormatOptions) string {
	if a == nil {
		return ""
	}
	if a.Type != ast.AlterTypeTable {
		return stmtSQL(a)
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(f.kw("ALTER TABLE"))
	f.sb.WriteString(" ")
	f.sb.WriteString(a.Name)
	if op, ok := a.Operation.(*ast.AlterTableOperation); ok && op != nil {
		f.sb.WriteString(f.clauseSep())
		writeAlterTableOperation(f, op)
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

// writeAlterTableOperation renders a single ALTER TABLE operation. Operation
// types the ALTER TABLE parser does not produce are left empty.
func writeAlterTableOperation(f *nodeFormatter, op *ast.AlterTableOperation) {
	sb := f.sb
	switch op.Type {
	case ast.AddColumn:
		sb.WriteString(f.kw("ADD COLUMN"))
		if op.ColumnDef != nil {
			sb.WriteString(" ")
			sb.WriteString(columnDefSQL(op.ColumnDef))
		}
	case ast.AddConstraint:
		sb.WriteString(f.kw("ADD"))
		if op.Constraint != nil {
			// tableConstraintSQL prints "CONSTRAINT name" itself when named.
			if op.Constraint.Name == "" {
				sb.WriteString(" ")
				sb.WriteString(f.kw("CONSTRAINT"))
			}
			sb.WriteString(" ")
			sb.WriteString(tableConstraintSQL(op.Constraint))
		}
	case ast.DropColumn:
		sb.WriteString(f.kw("DROP COLUMN"))
		sb.WriteString(" ")
		sb.WriteString(alterIdentName(op.ColumnName))
		if op.CascadeDrops {
			sb.WriteString(" ")
			sb.WriteString(f.kw("CASCADE"))
		}
	case ast.DropConstraint:
		sb.WriteString(f.kw("DROP CONSTRAINT"))
		sb.WriteString(" ")
		sb.WriteString(alterIdentName(op.ConstraintName))
		if op.CascadeDrops {
			sb.WriteString(" ")
			sb.WriteString(f.kw("CASCADE"))
		}
	case ast.RenameTable:
		sb.WriteString(f.kw("RENAME TO"))
		sb.WriteString(" ")
		sb.WriteString(op.NewTableName.String())
	case ast.RenameColumn:
		oldName := op.ColumnName
		if oldName == nil {
			oldName = op.OldColumnName
		}
		sb.WriteString(f.kw("RENAME COLUMN"))
		sb.WriteString(" ")
		sb.WriteString(alterIdentName(oldName))
		sb.WriteString(" ")
		sb.WriteString(f.kw("TO"))
		sb.WriteString(" ")
		sb.WriteString(alterIdentName(op.NewColumnName))
	case ast.AlterColumn:
		sb.WriteString(f.kw("ALTER COLUMN"))
		sb.WriteString(" ")
		sb.WriteString(alterIdentName(op.ColumnName))
		if op.ColumnDef != nil {
			sb.WriteString(" ")
			sb.WriteString(columnDefSQL(op.ColumnDef))
		}
	}
}
