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

// SetNameQuoteStyle rewrites, in place, the identifier delimiter recorded
// for every name under node to style ('"', '`' or '['), so the tree renders
// its delimited names with a target dialect's delimiters instead of the
// source's: a MySQL `my col` becomes "my col" for PostgreSQL and a SQL Server
// [Group] becomes `Group` for MySQL. Names that need delimiters only because
// of their content (a reserved word, a space) are written with style too.
// The parts recorded as delimited are kept; only the delimiter changes.
//
// Oracle bare names containing '#' (NameQuote.BareHash) stay bare only when
// keepBareHash is true; otherwise they are delimited like any other name with
// that character, since '#' starts a comment in MySQL and is not an
// identifier character elsewhere.
//
// It is used by the transpiler after parsing in the source dialect. Names the
// AST does not record (MERGE aliases, most DDL object names other than
// CREATE TABLE / CREATE VIEW names and columns) are not affected.
func SetNameQuoteStyle(node Node, style rune, keepBareHash bool) {
	if node == nil {
		return
	}
	restyle := func(q NameQuote) NameQuote {
		return q.WithStyle(style).WithBareHash(keepBareHash && q.BareHash())
	}
	Inspect(node, func(n Node) bool {
		switch v := n.(type) {
		case *Identifier:
			if v.QuoteStyle != 0 {
				v.QuoteStyle = style
				v.Quoted = style == '"'
			}
			v.Quotes = restyle(v.Quotes)
		case *AliasedExpression:
			v.AliasQuote = restyle(v.AliasQuote)
		case *FunctionCall:
			v.NameQuote = restyle(v.NameQuote)
		case *TableReference:
			v.NameQuote = restyle(v.NameQuote)
			v.AliasQuote = restyle(v.AliasQuote)
			if v.ColumnAliases != nil {
				for i := range v.ColumnAliases.Quotes {
					v.ColumnAliases.Quotes[i] = restyle(v.ColumnAliases.Quotes[i])
				}
			}
		case *CommonTableExpr:
			v.NameQuote = restyle(v.NameQuote)
			for i := range v.ColumnQuotes {
				v.ColumnQuotes[i] = restyle(v.ColumnQuotes[i])
			}
		case *InsertStatement:
			v.TableNameQuote = restyle(v.TableNameQuote)
		case *UpdateStatement:
			v.TableNameQuote = restyle(v.TableNameQuote)
			v.AliasQuote = restyle(v.AliasQuote)
		case *DeleteStatement:
			v.TableNameQuote = restyle(v.TableNameQuote)
			v.AliasQuote = restyle(v.AliasQuote)
		case *MergeStatement:
			v.TargetAliasQuote = restyle(v.TargetAliasQuote)
			v.SourceAliasQuote = restyle(v.SourceAliasQuote)
			for _, w := range v.WhenClauses {
				if w == nil || w.Action == nil {
					continue
				}
				for i := range w.Action.SetClauses {
					w.Action.SetClauses[i].ColumnQuote = restyle(w.Action.SetClauses[i].ColumnQuote)
				}
				for i := range w.Action.ColumnQuotes {
					w.Action.ColumnQuotes[i] = restyle(w.Action.ColumnQuotes[i])
				}
			}
		case *CreateTableStatement:
			v.NameQuote = restyle(v.NameQuote)
			for i := range v.Columns {
				restyleColumnDef(&v.Columns[i], restyle)
			}
			for i := range v.Constraints {
				restyleTableConstraint(&v.Constraints[i], restyle)
			}
		case *CreateViewStatement:
			v.NameQuote = restyle(v.NameQuote)
			restyleList(v.ColumnQuotes, restyle)
		case *CreateMaterializedViewStatement:
			v.NameQuote = restyle(v.NameQuote)
			restyleList(v.ColumnQuotes, restyle)
		case *CreateIndexStatement:
			v.NameQuote = restyle(v.NameQuote)
			v.TableQuote = restyle(v.TableQuote)
			for i := range v.Columns {
				v.Columns[i].ColumnQuote = restyle(v.Columns[i].ColumnQuote)
			}
		case *DropStatement:
			restyleList(v.NameQuotes, restyle)
		case *TruncateStatement:
			restyleList(v.TableQuotes, restyle)
		case *AlterStatement:
			v.NameQuote = restyle(v.NameQuote)
			if op, ok := v.Operation.(*AlterTableOperation); ok && op != nil {
				restyleAlterTableOperation(op, restyle)
			}
		}
		return true
	})
}

// restyleList applies restyle to every entry of qs in place.
func restyleList(qs []NameQuote, restyle func(NameQuote) NameQuote) {
	for i := range qs {
		qs[i] = restyle(qs[i])
	}
}

// restyleColumnDef applies restyle to a column definition's name and to the
// REFERENCES clauses of its constraints.
func restyleColumnDef(c *ColumnDef, restyle func(NameQuote) NameQuote) {
	if c == nil {
		return
	}
	c.NameQuote = restyle(c.NameQuote)
	for i := range c.Constraints {
		restyleReference(c.Constraints[i].References, restyle)
	}
}

// restyleTableConstraint applies restyle to a table constraint's name,
// columns and REFERENCES clause.
func restyleTableConstraint(tc *TableConstraint, restyle func(NameQuote) NameQuote) {
	if tc == nil {
		return
	}
	tc.NameQuote = restyle(tc.NameQuote)
	restyleList(tc.ColumnQuotes, restyle)
	restyleReference(tc.References, restyle)
}

// restyleReference applies restyle to a REFERENCES clause's table and
// columns.
func restyleReference(r *ReferenceDefinition, restyle func(NameQuote) NameQuote) {
	if r == nil {
		return
	}
	r.TableQuote = restyle(r.TableQuote)
	restyleList(r.ColumnQuotes, restyle)
}

// restyleAlterTableOperation applies restyle to the names an ALTER TABLE
// operation carries.
func restyleAlterTableOperation(op *AlterTableOperation, restyle func(NameQuote) NameQuote) {
	restyleColumnDef(op.ColumnDef, restyle)
	restyleTableConstraint(op.Constraint, restyle)
	for _, id := range []*Ident{op.ColumnName, op.ConstraintName, op.OldColumnName, op.NewColumnName} {
		if id != nil {
			id.Quote = restyle(id.Quote)
		}
	}
	op.NewTableName.Quote = restyle(op.NewTableName.Quote)
}
