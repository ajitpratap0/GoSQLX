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

// render_ddl_objects.go - formatter render handlers for CREATE TABLE,
// CREATE INDEX, CREATE [MATERIALIZED] VIEW, DROP and TRUNCATE. The clause
// writers are shared with the AST SQL() methods (ast.DDLStyle); this file
// supplies keyword casing, nested formatting and the CREATE TABLE column
// layout.

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ddlStyle returns the shared-writer style for this formatter: keyword
// casing, formatted nested expressions and queries, and the clause
// separator.
func (f *nodeFormatter) ddlStyle() ast.DDLStyle {
	opts := f.opts
	return ast.DDLStyle{
		Keyword:   f.kw,
		Expr:      func(e ast.Expression) string { return FormatExpression(e, opts) },
		Stmt:      func(s ast.Statement) string { return FormatStatement(s, nestedOpts(opts)) },
		ClauseSep: f.clauseSep(),
		NameQuote: f.nq,
	}
}

// finishDDL appends the optional semicolon and returns the result.
func (f *nodeFormatter) finishDDL() string {
	if f.opts.AddSemicolon {
		f.sb.WriteString(";")
	}
	return f.result()
}

func renderCreateTableStmt(c *ast.CreateTableStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	sb := f.sb
	st := f.ddlStyle()

	sb.WriteString(ast.CreateTableHeadSQL(c, st))

	if c.HasColumnList() {
		parts := make([]string, 0, len(c.Columns)+len(c.PeriodDefinitions)+len(c.Constraints))
		for i := range c.Columns {
			parts = append(parts, columnDefSQL(&c.Columns[i]))
		}
		for _, pd := range c.PeriodDefinitions {
			parts = append(parts, f.kw("PERIOD FOR")+strings.TrimPrefix(pd.SQL(), "PERIOD FOR"))
		}
		for i := range c.Constraints {
			parts = append(parts, tableConstraintSQL(&c.Constraints[i]))
		}
		if opts.NewlinePerClause {
			sb.WriteString(" (\n")
			f.depth++
			for i := range parts {
				parts[i] = f.indentStr() + parts[i]
			}
			sb.WriteString(strings.Join(parts, ",\n"))
			f.depth--
			sb.WriteString("\n")
			sb.WriteString(f.indentStr())
			sb.WriteString(")")
		} else {
			sb.WriteString(" (")
			sb.WriteString(strings.Join(parts, ", "))
			sb.WriteString(")")
		}
	}

	sb.WriteString(ast.CreateTableTailSQL(c, st))
	return f.finishDDL()
}

func renderCreateIndexStmt(c *ast.CreateIndexStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.CreateIndexSQL(c, f.ddlStyle()))
	return f.finishDDL()
}

func renderCreateViewStmt(c *ast.CreateViewStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.CreateViewSQL(c, f.ddlStyle()))
	return f.finishDDL()
}

func renderCreateMaterializedViewStmt(c *ast.CreateMaterializedViewStatement, opts ast.FormatOptions) string {
	if c == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.CreateMaterializedViewSQL(c, f.ddlStyle()))
	return f.finishDDL()
}

func renderDropStmt(d *ast.DropStatement, opts ast.FormatOptions) string {
	if d == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.DropSQL(d, f.ddlStyle()))
	return f.finishDDL()
}

func renderTruncateStmt(t *ast.TruncateStatement, opts ast.FormatOptions) string {
	if t == nil {
		return ""
	}
	f := newNodeFormatter(opts)
	f.sb.WriteString(ast.TruncateSQL(t, f.ddlStyle()))
	return f.finishDDL()
}
