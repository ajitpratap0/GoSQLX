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
	refs.list(s.DialectExtras().Tables)
	refs.list(s.From)
	refs.joins(s.DialectExtras().Joins)
	if err := refs.check(); err != nil {
		return err
	}
	if err := refs.checkCaptures(s); err != nil {
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
		refs.list(s.DialectExtras().Tables)
	}
	refs.list(s.Using)
	refs.joins(s.DialectExtras().Joins)
	if err := refs.check(); err != nil {
		return err
	}
	if err := refs.checkCaptures(s); err != nil {
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
		for _, t := range s.DialectExtras().Tables {
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
	tables := s.DialectExtras().Tables
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
	return func(expr ast.Expression) ast.Expression {
		rewriteAliasQualifiers(expr, t.matched, t.alias)
		return expr
	}
}

// rewriteAliasQualifiers follows AST children, including window clauses.
// Each nested SELECT shadows only the names it binds, leaving other
// correlated qualifiers visible.
func rewriteAliasQualifiers(node ast.Node, names []string, alias string) {
	walkAliasQualifiers(node, names, alias, false, func(id *ast.Identifier, _ bool) {
		id.Table = alias
		id.Quotes = replacedQualifierQuote(id.Quotes)
	})
}

// checkCaptures rejects aliases that would redirect a correlated reference
// to a different table introduced by a nested query.
func (t *dmlAliasTargets) checkCaptures(stmt ast.Statement) error {
	captured := false
	for _, child := range stmt.Children() {
		walkAliasQualifiers(child, t.matched, t.alias, false, func(_ *ast.Identifier, shadowed bool) {
			captured = captured || shadowed
		})
	}
	if captured {
		return fmt.Errorf("transform AddTableAlias: alias %q would capture a correlated qualifier", t.alias)
	}
	return nil
}

func walkAliasQualifiers(node ast.Node, names []string, alias string, captured bool, visit func(*ast.Identifier, bool)) {
	if node == nil || len(names) == 0 {
		return
	}
	switch n := node.(type) {
	case *ast.Identifier:
		for _, name := range names {
			if strings.EqualFold(n.Table, name) {
				visit(n, captured)
				return
			}
		}
	case *ast.SelectStatement:
		visible := make([]string, 0, len(names))
		for _, name := range names {
			if !selectIntroduces(n, []string{name}) {
				visible = append(visible, name)
			}
		}
		names = visible
		captured = captured || selectIntroduces(n, []string{alias})
	}
	for _, child := range node.Children() {
		if ref, ok := node.(*ast.TableReference); ok && !ref.Lateral {
			switch child.(type) {
			case *ast.SelectStatement, *ast.SetOperation:
				// Only LATERAL derived tables can use this query's bindings.
				continue
			}
		}
		walkAliasQualifiers(child, names, alias, captured, visit)
	}
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
