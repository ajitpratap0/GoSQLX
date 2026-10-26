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

package transform

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// UPDATE and DELETE name tables in more places than TableName: further
// targets and JOIN clauses (ast.DMLTargetFields.Tables / Joins, MySQL
// multi-table forms), the source lists UPDATE ... FROM and DELETE ... FROM /
// USING, and qualified columns in SET, OUTPUT, ORDER BY and RETURNING. The
// table transforms walk all of them so a rename or alias never leaves a
// reference to the old name behind.

// replaceTableInUpdate renames old to new in every table reference and
// column qualifier of an UPDATE statement.
func replaceTableInUpdate(s *ast.UpdateStatement, old, new string) {
	renameTableName(&s.TableName, &s.TableNameQuote, old, new)
	replaceTableInDMLTargets(s.Extras, old, new)
	replaceTableInFrom(s.From, old, new)
	for i := range s.Assignments {
		s.Assignments[i].Column = replaceTableInExpr(s.Assignments[i].Column, old, new)
		s.Assignments[i].Value = replaceTableInExpr(s.Assignments[i].Value, old, new)
	}
	s.Where = replaceTableInExpr(s.Where, old, new)
	for i := range s.Returning {
		s.Returning[i] = replaceTableInExpr(s.Returning[i], old, new)
	}
}

// replaceTableInDelete renames old to new in every table reference and
// column qualifier of a DELETE statement.
func replaceTableInDelete(s *ast.DeleteStatement, old, new string) {
	renameTableName(&s.TableName, &s.TableNameQuote, old, new)
	replaceTableInDMLTargets(s.Extras, old, new)
	replaceTableInFrom(s.From, old, new)
	replaceTableInFrom(s.Using, old, new)
	s.Where = replaceTableInExpr(s.Where, old, new)
	for i := range s.Returning {
		s.Returning[i] = replaceTableInExpr(s.Returning[i], old, new)
	}
}

// replaceTableInDMLTargets renames old to new in the extra targets, the
// joins, the OUTPUT list and the ORDER BY of a DML statement.
func replaceTableInDMLTargets(d *ast.DMLTargetFields, old, new string) {
	if d == nil {
		return
	}
	replaceTableInFrom(d.Tables, old, new)
	replaceTableInJoins(d.Joins, old, new)
	for i := range d.Output {
		d.Output[i] = replaceTableInExpr(d.Output[i], old, new)
	}
	for i := range d.OrderBy {
		d.OrderBy[i].Expression = replaceTableInExpr(d.OrderBy[i].Expression, old, new)
	}
}

// noDMLTargets is the read-only stand-in dmlTargets returns for a statement
// without Extras. Nothing may write to its fields.
var noDMLTargets ast.DMLTargetFields

// dmlTargets returns x, or a read-only empty DMLTargetFields when it is nil.
func dmlTargets(x *ast.DMLTargetFields) *ast.DMLTargetFields {
	if x != nil {
		return x
	}
	return &noDMLTargets
}

func renameTableName(name *string, quote *ast.NameQuote, old, new string) {
	if strings.EqualFold(*name, old) {
		*name = new
		*quote = replacedNameQuote(*quote)
	}
}

// addAliasToUpdate gives the table tableName the alias in an UPDATE
// statement and points the column qualifiers at the alias.
func addAliasToUpdate(s *ast.UpdateStatement, tableName, alias string) error {
	refs := dmlAliasTargets{tableName: tableName, alias: alias}
	refs.name(&s.TableName, &s.Alias, &s.AliasQuote)
	refs.list(dmlTargets(s.Extras).Tables)
	refs.list(s.From)
	refs.joins(dmlTargets(s.Extras).Joins)
	if err := refs.check(); err != nil {
		return err
	}
	refs.apply()
	rewrite := refs.qualifierRewriter()
	for i := range s.Assignments {
		s.Assignments[i].Column = rewrite(s.Assignments[i].Column)
		s.Assignments[i].Value = rewrite(s.Assignments[i].Value)
	}
	s.Where = rewrite(s.Where)
	for i := range s.Returning {
		s.Returning[i] = rewrite(s.Returning[i])
	}
	rewriteDMLTargetExprs(s.Extras, rewrite)
	return nil
}

// addAliasToDelete gives the table tableName the alias in a DELETE
// statement and points the column qualifiers at the alias. In the
// DELETE t1[, t2] FROM ... form the targets name the FROM entries, so a
// target that names the aliased table is renamed to the alias.
func addAliasToDelete(s *ast.DeleteStatement, tableName, alias string) error {
	refs := dmlAliasTargets{tableName: tableName, alias: alias}
	multi := deleteTargetsReferenceSources(s)
	if multi {
		// The targets are names of source entries and are written without
		// an alias of their own.
		refs.list(s.From)
	} else {
		refs.name(&s.TableName, &s.Alias, &s.AliasQuote)
		refs.list(dmlTargets(s.Extras).Tables)
	}
	refs.list(s.Using)
	refs.joins(dmlTargets(s.Extras).Joins)
	if err := refs.check(); err != nil {
		return err
	}
	refs.apply()
	if multi {
		renameDeleteTargets(s, refs.matched, alias)
	}
	rewrite := refs.qualifierRewriter()
	s.Where = rewrite(s.Where)
	for i := range s.Returning {
		s.Returning[i] = rewrite(s.Returning[i])
	}
	rewriteDMLTargetExprs(s.Extras, rewrite)
	return nil
}

// deleteTargetsReferenceSources reports whether the targets of a DELETE name
// entries of its source list instead of being tables of their own: always in
// DELETE t1[, t2] FROM sources, and in MySQL DELETE FROM t1[, t2] USING
// sources when a target is the name an entry of USING is known by (PostgreSQL
// DELETE FROM t USING u has a target of its own).
func deleteTargetsReferenceSources(s *ast.DeleteStatement) bool {
	if len(s.From) > 0 {
		return true
	}
	for i := range s.Using {
		eff := effectiveRefName(&s.Using[i])
		if eff == "" {
			continue
		}
		if strings.EqualFold(s.TableName, eff) {
			return true
		}
		for _, t := range dmlTargets(s.Extras).Tables {
			if strings.EqualFold(t.Name, eff) {
				return true
			}
		}
	}
	return false
}

// effectiveRefName is the name a table reference is known by in the
// statement: its alias, or its table name when it has none.
func effectiveRefName(ref *ast.TableReference) string {
	if ref.Alias != "" {
		return ref.Alias
	}
	return ref.Name
}

// renameDeleteTargets points the targets of DELETE t1[, t2] FROM ... that
// name an aliased FROM entry (by table name or by its previous alias) at the
// new alias.
func renameDeleteTargets(s *ast.DeleteStatement, names []string, alias string) {
	if len(names) == 0 {
		return
	}
	matches := func(n string) bool {
		for _, m := range names {
			if m != "" && strings.EqualFold(n, m) {
				return true
			}
		}
		return false
	}
	if matches(s.TableName) {
		s.TableName = alias
		s.Alias = ""
		s.TableNameQuote = replacedNameQuote(s.TableNameQuote)
		s.AliasQuote = 0
	}
	tables := dmlTargets(s.Extras).Tables
	for i := range tables {
		if matches(tables[i].Name) {
			tables[i].Name = alias
			tables[i].Alias = ""
			tables[i].NameQuote = replacedNameQuote(tables[i].NameQuote)
			tables[i].AliasQuote = 0
		}
	}
}

// rewriteDMLTargetExprs applies rewrite to the expressions held by the DML
// target fields: join conditions, OUTPUT and ORDER BY.
func rewriteDMLTargetExprs(d *ast.DMLTargetFields, rewrite func(ast.Expression) ast.Expression) {
	if d == nil {
		return
	}
	for i := range d.Joins {
		d.Joins[i].Condition = rewrite(d.Joins[i].Condition)
		for j := range d.Joins[i].Using {
			d.Joins[i].Using[j] = rewrite(d.Joins[i].Using[j])
		}
	}
	for i := range d.Output {
		d.Output[i] = rewrite(d.Output[i])
	}
	for i := range d.OrderBy {
		d.OrderBy[i].Expression = rewrite(d.OrderBy[i].Expression)
	}
}

// dmlAliasTargets collects the references of a DML statement that name the
// table to alias, so that a table appearing more than once (a self join)
// is reported instead of receiving one alias twice.
type dmlAliasTargets struct {
	tableName string
	alias     string
	// matched lists the names the table was known by (its own name and any
	// previous alias): qualifiers with these names are rewritten.
	matched []string
	sets    []aliasSlot
}

type aliasSlot struct {
	alias *string
	quote *ast.NameQuote
	prev  string
}

func (t *dmlAliasTargets) record(alias *string, quote *ast.NameQuote) {
	t.matched = append(t.matched, t.tableName)
	if *alias != "" {
		t.matched = append(t.matched, *alias)
	}
	t.sets = append(t.sets, aliasSlot{alias: alias, quote: quote, prev: *alias})
}

// name records the statement's own target.
func (t *dmlAliasTargets) name(name, alias *string, quote *ast.NameQuote) {
	if strings.EqualFold(*name, t.tableName) {
		t.record(alias, quote)
	}
}

// list records the matching entries of a table-reference list.
func (t *dmlAliasTargets) list(refs []ast.TableReference) {
	for i := range refs {
		if strings.EqualFold(refs[i].Name, t.tableName) {
			t.record(&refs[i].Alias, &refs[i].AliasQuote)
		}
	}
}

// joins records the matching right-hand tables of JOIN clauses.
func (t *dmlAliasTargets) joins(joins []ast.JoinClause) {
	for i := range joins {
		if strings.EqualFold(joins[i].Right.Name, t.tableName) {
			t.record(&joins[i].Right.Alias, &joins[i].Right.AliasQuote)
		}
	}
}

// check reports a table that appears more than once.
func (t *dmlAliasTargets) check() error {
	if len(t.sets) > 1 {
		return fmt.Errorf("transform AddTableAlias: table %q appears %d times in the statement; one alias would be ambiguous", t.tableName, len(t.sets))
	}
	return nil
}

func (t *dmlAliasTargets) apply() {
	for _, s := range t.sets {
		*s.alias = t.alias
		*s.quote = replacedNameQuote(*s.quote)
	}
}

// qualifierRewriter returns a function that renames the qualifier of every
// column that named the table (by name or previous alias) to the alias.
// Columns inside a subquery whose own FROM / JOIN introduces one of those
// names refer to the subquery's table, not the aliased one, and are left
// alone.
func (t *dmlAliasTargets) qualifierRewriter() func(ast.Expression) ast.Expression {
	names := t.matched
	return func(expr ast.Expression) ast.Expression {
		shadowed := shadowedIdentifiers(expr, names)
		return walkExpr(expr, func(e ast.Expression) ast.Expression {
			if id, ok := e.(*ast.Identifier); ok && id.Table != "" && !shadowed[id] {
				for _, n := range names {
					if strings.EqualFold(id.Table, n) {
						id.Table = t.alias
						id.Quotes = replacedQualifierQuote(id.Quotes)
						break
					}
				}
			}
			return e
		})
	}
}

// shadowedIdentifiers returns the identifiers of expr that sit inside a
// subquery whose FROM or JOIN list introduces one of names, so that a
// qualifier with that name resolves to the subquery's own table.
func shadowedIdentifiers(expr ast.Expression, names []string) map[*ast.Identifier]bool {
	var shadowed map[*ast.Identifier]bool
	mark := func(e ast.Expression) ast.Expression {
		if id, ok := e.(*ast.Identifier); ok {
			if shadowed == nil {
				shadowed = make(map[*ast.Identifier]bool)
			}
			shadowed[id] = true
		}
		return e
	}
	walkExpr(expr, func(e ast.Expression) ast.Expression {
		if sel := exprSubquery(e); sel != nil && selectIntroduces(sel, names) {
			walkStmtExprs(sel, mark)
		}
		return e
	})
	return shadowed
}

// exprSubquery returns the SELECT held by a subquery-bearing expression.
func exprSubquery(e ast.Expression) *ast.SelectStatement {
	var stmt ast.Statement
	switch x := e.(type) {
	case *ast.SubqueryExpression:
		stmt = x.Subquery
	case *ast.ExistsExpression:
		stmt = x.Subquery
	case *ast.InExpression:
		stmt = x.Subquery
	case *ast.AnyExpression:
		stmt = x.Subquery
	case *ast.AllExpression:
		stmt = x.Subquery
	case *ast.ArrayConstructorExpression:
		stmt = x.Subquery
	}
	sel, _ := stmt.(*ast.SelectStatement)
	return sel
}

// selectIntroduces reports whether the FROM or JOIN list of sel introduces
// a table known by one of names.
func selectIntroduces(sel *ast.SelectStatement, names []string) bool {
	match := func(ref *ast.TableReference) bool {
		eff := effectiveRefName(ref)
		for _, n := range names {
			if eff != "" && strings.EqualFold(eff, n) {
				return true
			}
		}
		return false
	}
	for i := range sel.From {
		if match(&sel.From[i]) {
			return true
		}
	}
	for i := range sel.Joins {
		if match(&sel.Joins[i].Right) {
			return true
		}
	}
	return false
}
