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

// GetInsertStatement gets an InsertStatement from the pool
func GetInsertStatement() *InsertStatement {
	return insertStmtPool.Get().(*InsertStatement)
}

// PutInsertStatement returns an InsertStatement to the pool.
//
// Releases every pooled Expression/Statement reachable from the InsertStatement:
//   - With (CTEs + nested statements + scalar CTE expressions)
//   - Columns
//   - Output (SQL Server OUTPUT clause)
//   - Values (all rows, all cells)
//   - Query (INSERT ... SELECT — the nested QueryExpression)
//   - Returning
//   - OnConflict.Target, OnConflict.Action.DoUpdate (Column, Value), OnConflict.Action.Where
//   - OnDuplicateKey.Updates (Column, Value)
func PutInsertStatement(stmt *InsertStatement) {
	if stmt == nil {
		return
	}

	// ── WITH clause / CTEs ────────────────────────────────────────────
	if stmt.With != nil {
		for _, cte := range stmt.With.CTEs {
			if cte == nil {
				continue
			}
			releaseStatement(cte.Statement)
			cte.Statement = nil
			PutExpression(cte.ScalarExpr)
			cte.ScalarExpr = nil
		}
		stmt.With.CTEs = nil
		stmt.With = nil
	}

	// ── Column list ───────────────────────────────────────────────────
	for i := range stmt.Columns {
		PutExpression(stmt.Columns[i])
		stmt.Columns[i] = nil
	}
	stmt.Columns = stmt.Columns[:0]

	// ── OUTPUT clause (SQL Server) ────────────────────────────────────
	for i := range stmt.Output {
		PutExpression(stmt.Output[i])
		stmt.Output[i] = nil
	}
	stmt.Output = stmt.Output[:0]

	// ── VALUES (multi-row) ────────────────────────────────────────────
	for i := range stmt.Values {
		for j := range stmt.Values[i] {
			PutExpression(stmt.Values[i][j])
			stmt.Values[i][j] = nil
		}
		stmt.Values[i] = stmt.Values[i][:0]
	}
	stmt.Values = stmt.Values[:0]

	// ── Query (INSERT ... SELECT) ─────────────────────────────────────
	if stmt.Query != nil {
		// Query is a QueryExpression (Statement); dispatch via releaseStatement.
		releaseStatement(stmt.Query)
		stmt.Query = nil
	}

	// ── RETURNING ──────────────────────────────────────────────────────
	for i := range stmt.Returning {
		PutExpression(stmt.Returning[i])
		stmt.Returning[i] = nil
	}
	stmt.Returning = stmt.Returning[:0]

	// ── ON CONFLICT (PostgreSQL) ──────────────────────────────────────
	if stmt.OnConflict != nil {
		for i := range stmt.OnConflict.Target {
			PutExpression(stmt.OnConflict.Target[i])
			stmt.OnConflict.Target[i] = nil
		}
		stmt.OnConflict.Target = nil
		for i := range stmt.OnConflict.Action.DoUpdate {
			PutExpression(stmt.OnConflict.Action.DoUpdate[i].Column)
			PutExpression(stmt.OnConflict.Action.DoUpdate[i].Value)
			stmt.OnConflict.Action.DoUpdate[i].Column = nil
			stmt.OnConflict.Action.DoUpdate[i].Value = nil
		}
		stmt.OnConflict.Action.DoUpdate = nil
		PutExpression(stmt.OnConflict.Action.Where)
		stmt.OnConflict.Action.Where = nil
		stmt.OnConflict = nil
	}

	// ── ON DUPLICATE KEY UPDATE (MySQL) ───────────────────────────────
	if stmt.OnDuplicateKey != nil {
		for i := range stmt.OnDuplicateKey.Updates {
			PutExpression(stmt.OnDuplicateKey.Updates[i].Column)
			PutExpression(stmt.OnDuplicateKey.Updates[i].Value)
			stmt.OnDuplicateKey.Updates[i].Column = nil
			stmt.OnDuplicateKey.Updates[i].Value = nil
		}
		stmt.OnDuplicateKey.Updates = nil
		stmt.OnDuplicateKey = nil
	}

	stmt.TableName = ""

	// Return to pool
	insertStmtPool.Put(stmt)
}

// GetUpdateStatement gets an UpdateStatement from the pool
func GetUpdateStatement() *UpdateStatement {
	return updateStmtPool.Get().(*UpdateStatement)
}

// PutUpdateStatement returns an UpdateStatement to the pool.
//
// Releases every pooled Expression/Statement reachable from the UpdateStatement:
//   - With (CTEs + nested statements + scalar CTE expressions)
//   - Assignments (Column, Value)
//   - From (TableReference.Subquery, TableFunc, Pivot, MatchRecognize, TimeTravel, ForSystemTime)
//   - Where
//   - Returning
func PutUpdateStatement(stmt *UpdateStatement) {
	if stmt == nil {
		return
	}

	// ── WITH clause / CTEs ────────────────────────────────────────────
	if stmt.With != nil {
		for _, cte := range stmt.With.CTEs {
			if cte == nil {
				continue
			}
			releaseStatement(cte.Statement)
			cte.Statement = nil
			PutExpression(cte.ScalarExpr)
			cte.ScalarExpr = nil
		}
		stmt.With.CTEs = nil
		stmt.With = nil
	}

	// ── SET assignments ───────────────────────────────────────────────
	for i := range stmt.Assignments {
		PutExpression(stmt.Assignments[i].Column)
		PutExpression(stmt.Assignments[i].Value)
		stmt.Assignments[i].Column = nil
		stmt.Assignments[i].Value = nil
	}
	stmt.Assignments = stmt.Assignments[:0]

	// ── FROM table references ─────────────────────────────────────────
	for i := range stmt.From {
		releaseTableReference(&stmt.From[i])
	}
	stmt.From = stmt.From[:0]

	// ── WHERE ──────────────────────────────────────────────────────────
	PutExpression(stmt.Where)
	stmt.Where = nil

	// ── RETURNING ──────────────────────────────────────────────────────
	for i := range stmt.Returning {
		PutExpression(stmt.Returning[i])
		stmt.Returning[i] = nil
	}
	stmt.Returning = stmt.Returning[:0]

	// ── Scalars ────────────────────────────────────────────────────────
	stmt.TableName = ""
	stmt.Alias = ""

	// Return to pool
	updateStmtPool.Put(stmt)
}

// GetDeleteStatement gets a DeleteStatement from the pool
func GetDeleteStatement() *DeleteStatement {
	return deleteStmtPool.Get().(*DeleteStatement)
}

// PutDeleteStatement returns a DeleteStatement to the pool.
//
// Releases every pooled Expression/Statement reachable from the DeleteStatement:
//   - With (CTEs + nested statements + scalar CTE expressions)
//   - Using (TableReference subqueries, TableFunc, Pivot, MatchRecognize, TimeTravel, ForSystemTime)
//   - Where
//   - Returning
func PutDeleteStatement(stmt *DeleteStatement) {
	if stmt == nil {
		return
	}

	// ── WITH clause / CTEs ────────────────────────────────────────────
	if stmt.With != nil {
		for _, cte := range stmt.With.CTEs {
			if cte == nil {
				continue
			}
			releaseStatement(cte.Statement)
			cte.Statement = nil
			PutExpression(cte.ScalarExpr)
			cte.ScalarExpr = nil
		}
		stmt.With.CTEs = nil
		stmt.With = nil
	}

	// ── USING table references (PostgreSQL) ───────────────────────────
	for i := range stmt.Using {
		releaseTableReference(&stmt.Using[i])
	}
	stmt.Using = stmt.Using[:0]

	// ── WHERE ──────────────────────────────────────────────────────────
	PutExpression(stmt.Where)
	stmt.Where = nil

	// ── RETURNING ──────────────────────────────────────────────────────
	for i := range stmt.Returning {
		PutExpression(stmt.Returning[i])
		stmt.Returning[i] = nil
	}
	stmt.Returning = stmt.Returning[:0]

	// ── Scalars ────────────────────────────────────────────────────────
	stmt.TableName = ""
	stmt.Alias = ""

	// Return to pool
	deleteStmtPool.Put(stmt)
}

// GetSelectStatement gets a SelectStatement from the pool
func GetSelectStatement() *SelectStatement {
	stmt := selectStmtPool.Get().(*SelectStatement)
	stmt.Columns = stmt.Columns[:0]
	stmt.OrderBy = stmt.OrderBy[:0]
	return stmt
}

// PutSelectStatement returns a SelectStatement to the pool.
//
// Uses iterative cleanup via PutExpression to handle deeply nested expressions.
// This function MUST release every pooled Expression/Node reachable from the
// SelectStatement; missing fields cause silent pool leaks that defeat the
// 60-80% memory reduction target and degrade hit-rate below 95%.
//
// Coverage (v1.14.0+ — comprehensive audit):
//   - With (CTEs + their nested statements + scalar CTE expressions)
//   - Top.Count
//   - DistinctOnColumns
//   - Columns
//   - From (TableReference.Subquery, TableFunc, Pivot.AggregateFunction, MatchRecognize)
//   - Joins (Left/Right TableRefs, Condition)
//   - ArrayJoin (element Exprs)
//   - PrewhereClause
//   - Sample (no Expressions, but zeroed for hygiene)
//   - Where
//   - GroupBy
//   - Having
//   - Qualify
//   - StartWith / ConnectBy.Condition
//   - Windows (PartitionBy + OrderBy expressions + FrameClause bounds)
//   - OrderBy
//   - Fetch / For (no Expression children, just zero)
//   - Limit / Offset (*int — no release needed)
func PutSelectStatement(stmt *SelectStatement) {
	if stmt == nil {
		return
	}

	// ── WITH clause / CTEs ────────────────────────────────────────────
	if stmt.With != nil {
		for _, cte := range stmt.With.CTEs {
			if cte == nil {
				continue
			}
			releaseStatement(cte.Statement)
			cte.Statement = nil
			PutExpression(cte.ScalarExpr)
			cte.ScalarExpr = nil
		}
		stmt.With.CTEs = nil
		stmt.With = nil
	}

	// ── TOP clause ─────────────────────────────────────────────────────
	if stmt.Top != nil {
		PutExpression(stmt.Top.Count)
		stmt.Top.Count = nil
		stmt.Top = nil
	}

	// ── DISTINCT ON columns ────────────────────────────────────────────
	for i := range stmt.DistinctOnColumns {
		PutExpression(stmt.DistinctOnColumns[i])
		stmt.DistinctOnColumns[i] = nil
	}
	stmt.DistinctOnColumns = stmt.DistinctOnColumns[:0]

	// ── SELECT list columns ────────────────────────────────────────────
	for i := range stmt.Columns {
		PutExpression(stmt.Columns[i])
		stmt.Columns[i] = nil
	}
	stmt.Columns = stmt.Columns[:0]

	// ── FROM table references (Subquery, TableFunc, Pivot, MatchRecognize) ─
	for i := range stmt.From {
		releaseTableReference(&stmt.From[i])
	}
	stmt.From = stmt.From[:0]

	// ── JOINs ──────────────────────────────────────────────────────────
	for i := range stmt.Joins {
		releaseTableReference(&stmt.Joins[i].Left)
		releaseTableReference(&stmt.Joins[i].Right)
		PutExpression(stmt.Joins[i].Condition)
		stmt.Joins[i].Condition = nil
		stmt.Joins[i].Type = ""
	}
	stmt.Joins = stmt.Joins[:0]

	// ── ARRAY JOIN (ClickHouse) ────────────────────────────────────────
	if stmt.ArrayJoin != nil {
		for i := range stmt.ArrayJoin.Elements {
			PutExpression(stmt.ArrayJoin.Elements[i].Expr)
			stmt.ArrayJoin.Elements[i].Expr = nil
			stmt.ArrayJoin.Elements[i].Alias = ""
		}
		stmt.ArrayJoin.Elements = nil
		stmt.ArrayJoin = nil
	}

	// ── PREWHERE / WHERE / HAVING / QUALIFY / START WITH ───────────────
	PutExpression(stmt.PrewhereClause)
	stmt.PrewhereClause = nil
	PutExpression(stmt.Where)
	stmt.Where = nil
	PutExpression(stmt.Having)
	stmt.Having = nil
	PutExpression(stmt.Qualify)
	stmt.Qualify = nil
	PutExpression(stmt.StartWith)
	stmt.StartWith = nil

	// ── CONNECT BY ─────────────────────────────────────────────────────
	if stmt.ConnectBy != nil {
		PutExpression(stmt.ConnectBy.Condition)
		stmt.ConnectBy.Condition = nil
		stmt.ConnectBy = nil
	}

	// ── SAMPLE (no expression children, just drop) ─────────────────────
	stmt.Sample = nil

	// ── GROUP BY ───────────────────────────────────────────────────────
	for i := range stmt.GroupBy {
		PutExpression(stmt.GroupBy[i])
		stmt.GroupBy[i] = nil
	}
	stmt.GroupBy = stmt.GroupBy[:0]

	// ── WINDOWS (PartitionBy, OrderBy, FrameClause bounds) ─────────────
	for i := range stmt.Windows {
		w := &stmt.Windows[i]
		for j := range w.PartitionBy {
			PutExpression(w.PartitionBy[j])
			w.PartitionBy[j] = nil
		}
		w.PartitionBy = w.PartitionBy[:0]
		for j := range w.OrderBy {
			PutExpression(w.OrderBy[j].Expression)
			w.OrderBy[j].Expression = nil
		}
		w.OrderBy = w.OrderBy[:0]
		if w.FrameClause != nil {
			PutExpression(w.FrameClause.Start.Value)
			w.FrameClause.Start.Value = nil
			if w.FrameClause.End != nil {
				PutExpression(w.FrameClause.End.Value)
				w.FrameClause.End.Value = nil
				w.FrameClause.End = nil
			}
			w.FrameClause = nil
		}
		w.Name = ""
	}
	stmt.Windows = stmt.Windows[:0]

	// ── ORDER BY ───────────────────────────────────────────────────────
	for i := range stmt.OrderBy {
		PutExpression(stmt.OrderBy[i].Expression)
		stmt.OrderBy[i].Expression = nil
	}
	stmt.OrderBy = stmt.OrderBy[:0]

	// ── LIMIT / OFFSET (*int - no Expression) ──────────────────────────
	stmt.Limit = nil
	stmt.Offset = nil

	// ── FETCH / FOR (no Expression children) ───────────────────────────
	stmt.Fetch = nil
	stmt.For = nil

	// ── Scalars ────────────────────────────────────────────────────────
	stmt.TableName = ""
	stmt.Distinct = false

	// Return to pool
	selectStmtPool.Put(stmt)
}

// releaseTableReference releases all pooled Expression/Statement references
// reachable from a TableReference. Zero-copies the TableReference back to a
// clean state suitable for pool reuse.
func releaseTableReference(tr *TableReference) {
	if tr == nil {
		return
	}
	// Subquery is itself a *SelectStatement — recurse through the statement
	// dispatcher to release every nested pool reference.
	if tr.Subquery != nil {
		PutSelectStatement(tr.Subquery)
		tr.Subquery = nil
	}
	// TableFunc is a *FunctionCall — release as expression.
	if tr.TableFunc != nil {
		PutExpression(tr.TableFunc)
		tr.TableFunc = nil
	}
	// Pivot.AggregateFunction is an Expression.
	if tr.Pivot != nil {
		PutExpression(tr.Pivot.AggregateFunction)
		tr.Pivot.AggregateFunction = nil
		tr.Pivot = nil
	}
	// Unpivot holds only strings — drop the struct.
	tr.Unpivot = nil
	// MatchRecognize carries PartitionBy / OrderBy / Measures / Definitions.
	if tr.MatchRecognize != nil {
		mr := tr.MatchRecognize
		for i := range mr.PartitionBy {
			PutExpression(mr.PartitionBy[i])
			mr.PartitionBy[i] = nil
		}
		mr.PartitionBy = mr.PartitionBy[:0]
		for i := range mr.OrderBy {
			PutExpression(mr.OrderBy[i].Expression)
			mr.OrderBy[i].Expression = nil
		}
		mr.OrderBy = mr.OrderBy[:0]
		for i := range mr.Measures {
			PutExpression(mr.Measures[i].Expr)
			mr.Measures[i].Expr = nil
			mr.Measures[i].Alias = ""
		}
		mr.Measures = mr.Measures[:0]
		for i := range mr.Definitions {
			PutExpression(mr.Definitions[i].Condition)
			mr.Definitions[i].Condition = nil
			mr.Definitions[i].Name = ""
		}
		mr.Definitions = mr.Definitions[:0]
		tr.MatchRecognize = nil
	}
	// TimeTravel carries Named map of Expressions + Chained clauses.
	if tr.TimeTravel != nil {
		releaseTimeTravelClause(tr.TimeTravel)
		tr.TimeTravel = nil
	}
	// ForSystemTime carries Point/Start/End expressions.
	if tr.ForSystemTime != nil {
		PutExpression(tr.ForSystemTime.Point)
		PutExpression(tr.ForSystemTime.Start)
		PutExpression(tr.ForSystemTime.End)
		tr.ForSystemTime.Point = nil
		tr.ForSystemTime.Start = nil
		tr.ForSystemTime.End = nil
		tr.ForSystemTime = nil
	}
	tr.Name = ""
	tr.Alias = ""
	tr.Lateral = false
	tr.Final = false
	tr.TableHints = nil
}

// ============================================================
// DDL Statement Pool Functions
// ============================================================

// GetCreateTableStatement gets a CreateTableStatement from the pool.
func GetCreateTableStatement() *CreateTableStatement {
	stmt := createTableStmtPool.Get().(*CreateTableStatement)
	stmt.Columns = stmt.Columns[:0]
	stmt.Constraints = stmt.Constraints[:0]
	stmt.Inherits = stmt.Inherits[:0]
	stmt.Options = stmt.Options[:0]
	return stmt
}

// PutCreateTableStatement returns a CreateTableStatement to the pool.
// It recursively releases any nested expressions (column defaults, check constraints, etc.).
func PutCreateTableStatement(stmt *CreateTableStatement) {
	if stmt == nil {
		return
	}

	// Release expressions embedded in column definitions
	for i := range stmt.Columns {
		for j := range stmt.Columns[i].Constraints {
			PutExpression(stmt.Columns[i].Constraints[j].Default)
			PutExpression(stmt.Columns[i].Constraints[j].Check)
			stmt.Columns[i].Constraints[j].Default = nil
			stmt.Columns[i].Constraints[j].Check = nil
			stmt.Columns[i].Constraints[j].References = nil
		}
		stmt.Columns[i].Constraints = stmt.Columns[i].Constraints[:0]
		stmt.Columns[i].Name = ""
		stmt.Columns[i].Type = ""
	}
	stmt.Columns = stmt.Columns[:0]

	// Release expressions in table constraints
	for i := range stmt.Constraints {
		PutExpression(stmt.Constraints[i].Check)
		stmt.Constraints[i].Check = nil
		stmt.Constraints[i].References = nil
		stmt.Constraints[i].Name = ""
		stmt.Constraints[i].Type = ""
		stmt.Constraints[i].Columns = stmt.Constraints[i].Columns[:0]
	}
	stmt.Constraints = stmt.Constraints[:0]

	// Release expressions in PartitionBy
	if stmt.PartitionBy != nil {
		for i, expr := range stmt.PartitionBy.Boundary {
			PutExpression(expr)
			stmt.PartitionBy.Boundary[i] = nil
		}
		stmt.PartitionBy.Boundary = stmt.PartitionBy.Boundary[:0]
		stmt.PartitionBy.Columns = stmt.PartitionBy.Columns[:0]
		stmt.PartitionBy.Type = ""
		stmt.PartitionBy = nil
	}

	// Release expressions in PartitionDefinitions
	for i := range stmt.Partitions {
		for j, expr := range stmt.Partitions[i].Values {
			PutExpression(expr)
			stmt.Partitions[i].Values[j] = nil
		}
		PutExpression(stmt.Partitions[i].LessThan)
		PutExpression(stmt.Partitions[i].From)
		PutExpression(stmt.Partitions[i].To)
		for j, expr := range stmt.Partitions[i].InValues {
			PutExpression(expr)
			stmt.Partitions[i].InValues[j] = nil
		}
		stmt.Partitions[i].Values = stmt.Partitions[i].Values[:0]
		stmt.Partitions[i].InValues = stmt.Partitions[i].InValues[:0]
		stmt.Partitions[i].LessThan = nil
		stmt.Partitions[i].From = nil
		stmt.Partitions[i].To = nil
		stmt.Partitions[i].Name = ""
		stmt.Partitions[i].Type = ""
		stmt.Partitions[i].Tablespace = ""
	}
	stmt.Partitions = stmt.Partitions[:0]

	stmt.Inherits = stmt.Inherits[:0]

	for i := range stmt.Options {
		stmt.Options[i].Name = ""
		stmt.Options[i].Value = ""
	}
	stmt.Options = stmt.Options[:0]

	// Reset scalar fields
	stmt.IfNotExists = false
	stmt.Temporary = false
	stmt.Name = ""

	createTableStmtPool.Put(stmt)
}

// GetAlterTableStatement gets an AlterTableStatement from the pool.
func GetAlterTableStatement() *AlterTableStatement {
	stmt := alterTableStmtPool.Get().(*AlterTableStatement)
	stmt.Actions = stmt.Actions[:0]
	return stmt
}

// PutAlterTableStatement returns an AlterTableStatement to the pool.
// It recursively releases nested expressions in column definitions and constraints.
func PutAlterTableStatement(stmt *AlterTableStatement) {
	if stmt == nil {
		return
	}

	for i := range stmt.Actions {
		// Release nested ColumnDef expressions
		if stmt.Actions[i].ColumnDef != nil {
			for j := range stmt.Actions[i].ColumnDef.Constraints {
				PutExpression(stmt.Actions[i].ColumnDef.Constraints[j].Default)
				PutExpression(stmt.Actions[i].ColumnDef.Constraints[j].Check)
				stmt.Actions[i].ColumnDef.Constraints[j].Default = nil
				stmt.Actions[i].ColumnDef.Constraints[j].Check = nil
				stmt.Actions[i].ColumnDef.Constraints[j].References = nil
			}
			stmt.Actions[i].ColumnDef.Constraints = stmt.Actions[i].ColumnDef.Constraints[:0]
			stmt.Actions[i].ColumnDef = nil
		}
		// Release nested TableConstraint expressions
		if stmt.Actions[i].Constraint != nil {
			PutExpression(stmt.Actions[i].Constraint.Check)
			stmt.Actions[i].Constraint.Check = nil
			stmt.Actions[i].Constraint = nil
		}
		stmt.Actions[i].Type = ""
		stmt.Actions[i].ColumnName = ""
	}
	stmt.Actions = stmt.Actions[:0]
	stmt.Table = ""

	alterTableStmtPool.Put(stmt)
}

// GetMergeStatement gets a MergeStatement from the pool.
func GetMergeStatement() *MergeStatement {
	stmt := mergeStmtPool.Get().(*MergeStatement)
	stmt.WhenClauses = stmt.WhenClauses[:0]
	stmt.Output = stmt.Output[:0]
	return stmt
}

// PutMergeStatement returns a MergeStatement to the pool.
// It recursively releases nested expressions in WHEN clauses and OUTPUT.
func PutMergeStatement(stmt *MergeStatement) {
	if stmt == nil {
		return
	}

	// Release OnCondition
	PutExpression(stmt.OnCondition)
	stmt.OnCondition = nil

	// Release WHEN clause expressions
	for i := range stmt.WhenClauses {
		if stmt.WhenClauses[i] == nil {
			continue
		}
		PutExpression(stmt.WhenClauses[i].Condition)
		stmt.WhenClauses[i].Condition = nil
		if stmt.WhenClauses[i].Action != nil {
			for j := range stmt.WhenClauses[i].Action.SetClauses {
				PutExpression(stmt.WhenClauses[i].Action.SetClauses[j].Value)
				stmt.WhenClauses[i].Action.SetClauses[j].Value = nil
				stmt.WhenClauses[i].Action.SetClauses[j].Column = ""
			}
			stmt.WhenClauses[i].Action.SetClauses = stmt.WhenClauses[i].Action.SetClauses[:0]
			for j, expr := range stmt.WhenClauses[i].Action.Values {
				PutExpression(expr)
				stmt.WhenClauses[i].Action.Values[j] = nil
			}
			stmt.WhenClauses[i].Action.Values = stmt.WhenClauses[i].Action.Values[:0]
			stmt.WhenClauses[i].Action.Columns = stmt.WhenClauses[i].Action.Columns[:0]
			stmt.WhenClauses[i].Action.ActionType = ""
			stmt.WhenClauses[i].Action.DefaultValues = false
			stmt.WhenClauses[i].Action = nil
		}
		stmt.WhenClauses[i].Type = ""
		stmt.WhenClauses[i] = nil
	}
	stmt.WhenClauses = stmt.WhenClauses[:0]

	// Release OUTPUT expressions
	for i, expr := range stmt.Output {
		PutExpression(expr)
		stmt.Output[i] = nil
	}
	stmt.Output = stmt.Output[:0]

	// Reset TargetTable / SourceTable (value types - zero them out)
	stmt.TargetTable = TableReference{}
	stmt.SourceTable = TableReference{}
	stmt.TargetAlias = ""
	stmt.SourceAlias = ""

	mergeStmtPool.Put(stmt)
}

// GetReplaceStatement gets a ReplaceStatement from the pool.
func GetReplaceStatement() *ReplaceStatement {
	stmt := replaceStmtPool.Get().(*ReplaceStatement)
	stmt.Columns = stmt.Columns[:0]
	stmt.Values = stmt.Values[:0]
	return stmt
}

// PutReplaceStatement returns a ReplaceStatement to the pool.
// It recursively releases nested column and value expressions.
func PutReplaceStatement(stmt *ReplaceStatement) {
	if stmt == nil {
		return
	}

	for i := range stmt.Columns {
		PutExpression(stmt.Columns[i])
		stmt.Columns[i] = nil
	}
	stmt.Columns = stmt.Columns[:0]

	for i := range stmt.Values {
		for j := range stmt.Values[i] {
			PutExpression(stmt.Values[i][j])
			stmt.Values[i][j] = nil
		}
		stmt.Values[i] = stmt.Values[i][:0]
	}
	stmt.Values = stmt.Values[:0]

	stmt.TableName = ""

	replaceStmtPool.Put(stmt)
}

// releaseTimeTravelClause walks a TimeTravelClause graph, releasing every
// Expression stored in Named maps and every chained sub-clause. Chained
// cycles are not possible because the parser builds a tree, but we still
// guard against nil to be defensive.
func releaseTimeTravelClause(c *TimeTravelClause) {
	if c == nil {
		return
	}
	for k, v := range c.Named {
		PutExpression(v)
		delete(c.Named, k)
	}
	for _, ch := range c.Chained {
		releaseTimeTravelClause(ch)
	}
	c.Chained = nil
	c.Named = nil
	c.Kind = ""
}
