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

// This file implements comprehensive object pooling for all major AST node types
// using sync.Pool. The pooling system provides 60-80% memory reduction in production
// workloads and 95%+ pool hit rates with proper usage patterns.
//
// IMPORTANT: Always use defer when returning pooled objects to prevent leaks.
// See doc.go for complete pooling documentation and usage examples.
package ast

import (
	"sync"
	"sync/atomic"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

// poolLeakCount counts expressions that exceeded PutExpression's iterative
// work-queue cap and were drained via the recursive fallback. Non-zero values
// mean the AST is pathologically large (>MaxWorkQueueSize nodes in a single
// cleanup) or the queue algorithm needs tuning. Exposed via PoolLeakCount().
var poolLeakCount uint64

// PoolLeakCount returns the number of times PutExpression's iterative cleanup
// exceeded MaxWorkQueueSize and fell back to recursive drain. A non-zero
// return does NOT indicate a leak — the recursive drain still releases every
// node — but it flags that the work-queue cap was hit. Used for diagnostics
// and by leak tests.
func PoolLeakCount() uint64 {
	return atomic.LoadUint64(&poolLeakCount)
}

// ResetPoolLeakCount zeroes the pool-leak counter. Test-only helper.
func ResetPoolLeakCount() {
	atomic.StoreUint64(&poolLeakCount, 0)
}

// Pool configuration constants control cleanup behavior to prevent resource exhaustion.
const (
	// MaxCleanupDepth limits recursion depth to prevent stack overflow during cleanup.
	// Set to 100 based on typical SQL query complexity. Deeply nested expressions
	// use iterative cleanup instead of recursion.
	MaxCleanupDepth = 100

	// MaxWorkQueueSize limits the total number of nodes that the iterative
	// PutExpression cleanup loop will process before resizing protection kicks in.
	// Historically this was 1000 and cleanup silently stopped after that,
	// leaking every remaining node (hundreds per parse for large IN lists).
	//
	// The value is now 100_000, large enough to drain every realistic SQL AST
	// (even a 10k-element IN list or deeply nested CTE forest) in a single
	// pass. The work queue itself is bounded by the live AST size — nodes
	// are pointers already allocated — so this does not materially increase
	// peak memory vs. the AST that already exists.
	//
	// If the cap is ever hit, PutExpression falls back to a depth-limited
	// recursive drain (bounded by MaxCleanupDepth) for the remaining queue
	// so no pooled nodes are silently leaked. See PutExpression for details.
	MaxWorkQueueSize = 100_000
)

var (
	// DDL statement pools
	createTableStmtPool = sync.Pool{
		New: func() interface{} {
			return &CreateTableStatement{
				Columns:     make([]ColumnDef, 0, 4),
				Constraints: make([]TableConstraint, 0, 2),
				Inherits:    make([]string, 0),
				Options:     make([]TableOption, 0),
			}
		},
	}

	alterTableStmtPool = sync.Pool{
		New: func() interface{} {
			return &AlterTableStatement{
				Actions: make([]AlterTableAction, 0, 2),
			}
		},
	}

	createIndexStmtPool = sync.Pool{
		New: func() interface{} {
			return &CreateIndexStatement{
				Columns: make([]IndexColumn, 0, 4),
			}
		},
	}

	mergeStmtPool = sync.Pool{
		New: func() interface{} {
			return &MergeStatement{
				WhenClauses: make([]*MergeWhenClause, 0, 2),
				Output:      make([]Expression, 0, 2),
			}
		},
	}

	createViewStmtPool = sync.Pool{
		New: func() interface{} {
			return &CreateViewStatement{
				Columns: make([]string, 0),
			}
		},
	}

	createMaterializedViewStmtPool = sync.Pool{
		New: func() interface{} {
			return &CreateMaterializedViewStatement{
				Columns: make([]string, 0),
			}
		},
	}

	refreshMaterializedViewStmtPool = sync.Pool{
		New: func() interface{} {
			return &RefreshMaterializedViewStatement{}
		},
	}

	dropStmtPool = sync.Pool{
		New: func() interface{} {
			return &DropStatement{
				Names: make([]string, 0, 2),
			}
		},
	}

	truncateStmtPool = sync.Pool{
		New: func() interface{} {
			return &TruncateStatement{
				Tables: make([]string, 0, 2),
			}
		},
	}

	showStmtPool = sync.Pool{
		New: func() interface{} {
			return &ShowStatement{}
		},
	}

	describeStmtPool = sync.Pool{
		New: func() interface{} {
			return &DescribeStatement{}
		},
	}

	unsupportedStmtPool = sync.Pool{
		New: func() interface{} {
			return &UnsupportedStatement{}
		},
	}

	replaceStmtPool = sync.Pool{
		New: func() interface{} {
			return &ReplaceStatement{
				Columns: make([]Expression, 0, 4),
				Values:  make([][]Expression, 0, 4),
			}
		},
	}

	alterStmtPool = sync.Pool{
		New: func() interface{} {
			return &AlterStatement{}
		},
	}

	// AST node pools
	astPool = sync.Pool{
		New: func() interface{} {
			return &AST{
				Statements: make([]Statement, 0, 8), // Increased initial capacity
			}
		},
	}

	// Statement pools
	selectStmtPool = sync.Pool{
		New: func() interface{} {
			return &SelectStatement{
				Columns: make([]Expression, 0, 4),
				OrderBy: make([]OrderByExpression, 0, 1),
			}
		},
	}

	insertStmtPool = sync.Pool{
		New: func() interface{} {
			return &InsertStatement{
				Columns: make([]Expression, 0, 4),
				Values:  make([][]Expression, 0, 4),
			}
		},
	}

	updateStmtPool = sync.Pool{
		New: func() interface{} {
			return &UpdateStatement{
				Assignments: make([]UpdateExpression, 0, 4),
			}
		},
	}

	deleteStmtPool = sync.Pool{
		New: func() interface{} {
			return &DeleteStatement{}
		},
	}

	// Expression pools
	identifierPool = sync.Pool{
		New: func() interface{} {
			return &Identifier{}
		},
	}

	binaryExprPool = sync.Pool{
		New: func() interface{} {
			return &BinaryExpression{}
		},
	}

	// Add a pool for LiteralValue to reduce allocations
	literalValuePool = sync.Pool{
		New: func() interface{} {
			return &LiteralValue{}
		},
	}

	updateExprPool = sync.Pool{
		New: func() interface{} {
			return &UpdateExpression{}
		},
	}

	// Additional expression pools for common expression types
	functionCallPool = sync.Pool{
		New: func() interface{} {
			return &FunctionCall{
				Arguments: make([]Expression, 0, 4),
			}
		},
	}

	caseExprPool = sync.Pool{
		New: func() interface{} {
			return &CaseExpression{
				WhenClauses: make([]WhenClause, 0, 2),
			}
		},
	}

	betweenExprPool = sync.Pool{
		New: func() interface{} {
			return &BetweenExpression{}
		},
	}

	inExprPool = sync.Pool{
		New: func() interface{} {
			return &InExpression{
				List: make([]Expression, 0, 4),
			}
		},
	}

	tupleExprPool = sync.Pool{
		New: func() interface{} {
			return &TupleExpression{
				Expressions: make([]Expression, 0, 4),
			}
		},
	}

	arrayConstructorPool = sync.Pool{
		New: func() interface{} {
			return &ArrayConstructorExpression{
				Elements: make([]Expression, 0, 4),
			}
		},
	}

	subqueryExprPool = sync.Pool{
		New: func() interface{} {
			return &SubqueryExpression{}
		},
	}

	castExprPool = sync.Pool{
		New: func() interface{} {
			return &CastExpression{}
		},
	}

	intervalExprPool = sync.Pool{
		New: func() interface{} {
			return &IntervalExpression{}
		},
	}

	arraySubscriptExprPool = sync.Pool{
		New: func() interface{} {
			return &ArraySubscriptExpression{
				Indices: make([]Expression, 0, 2), // Most common: 1-2 dimensions
			}
		},
	}

	arraySliceExprPool = sync.Pool{
		New: func() interface{} {
			return &ArraySliceExpression{}
		},
	}

	// Additional expression pools for complete coverage
	existsExprPool = sync.Pool{
		New: func() interface{} {
			return &ExistsExpression{}
		},
	}

	anyExprPool = sync.Pool{
		New: func() interface{} {
			return &AnyExpression{}
		},
	}

	allExprPool = sync.Pool{
		New: func() interface{} {
			return &AllExpression{}
		},
	}

	listExprPool = sync.Pool{
		New: func() interface{} {
			return &ListExpression{
				Values: make([]Expression, 0, 4),
			}
		},
	}

	unaryExprPool = sync.Pool{
		New: func() interface{} {
			return &UnaryExpression{}
		},
	}

	extractExprPool = sync.Pool{
		New: func() interface{} {
			return &ExtractExpression{}
		},
	}

	positionExprPool = sync.Pool{
		New: func() interface{} {
			return &PositionExpression{}
		},
	}

	substringExprPool = sync.Pool{
		New: func() interface{} {
			return &SubstringExpression{}
		},
	}

	aliasedExprPool = sync.Pool{
		New: func() interface{} {
			return &AliasedExpression{}
		},
	}

	// Slice pools
	exprSlicePool = sync.Pool{
		New: func() interface{} {
			s := make([]Expression, 0, 16) // Double capacity for better performance
			return &s
		},
	}

	createSequencePool = sync.Pool{
		New: func() interface{} { return &CreateSequenceStatement{} },
	}

	dropSequencePool = sync.Pool{
		New: func() interface{} { return &DropSequenceStatement{} },
	}

	alterSequencePool = sync.Pool{
		New: func() interface{} { return &AlterSequenceStatement{} },
	}
)

// NewAST retrieves a new AST container from the pool.
//
// NewAST returns a pooled AST container with pre-allocated statement capacity.
// This is the primary entry point for creating AST objects with memory pooling.
//
// Usage Pattern (MANDATORY):
//
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)  // ALWAYS use defer to prevent leaks
//
//	// Use astObj...
//
// The returned AST has:
//   - Empty Statements slice with capacity for 8 statements
//   - Clean state ready for population
//
// Performance:
//   - 95%+ pool hit rate in production workloads
//   - Eliminates allocation overhead for AST containers
//   - Reduces GC pressure by reusing objects
//
// CRITICAL: Always call ReleaseAST() when done, preferably via defer.
// Failure to return objects to the pool causes memory leaks and degrades
// performance by forcing new allocations.
//
// Example:
//
//	func parseQuery(sql string) (*ast.AST, error) {
//	    astObj := ast.NewAST()
//	    defer ast.ReleaseAST(astObj)
//
//	    // Parse and populate AST
//	    stmt := ast.GetSelectStatement()
//	    defer ast.PutSelectStatement(stmt)
//	    // ... build statement ...
//	    astObj.Statements = append(astObj.Statements, stmt)
//
//	    return astObj, nil
//	}
//
// See also: ReleaseAST(), GetSelectStatement(), GetInsertStatement()
func NewAST() *AST {
	metrics.RecordNamedPoolGet("ast")
	return astPool.Get().(*AST)
}

// ReleaseAST returns an AST container to the pool for reuse.
//
// ReleaseAST cleans up and returns the AST to the pool, allowing it to be
// reused in future NewAST() calls. This is critical for memory efficiency
// and performance.
//
// Cleanup Process:
//  1. Returns all statement objects to their respective pools
//  2. Clears all statement references
//  3. Resets the Statements slice (preserves capacity)
//  4. Returns the AST container to astPool
//
// Usage Pattern (MANDATORY):
//
//	astObj := ast.NewAST()
//	defer ast.ReleaseAST(astObj)  // ALWAYS use defer
//
// Parameters:
//   - ast: AST container to return (nil-safe, ignores nil)
//
// The function is nil-safe and will return immediately if passed a nil AST.
//
// CRITICAL: This function must be called for every AST obtained from NewAST().
// Use defer immediately after NewAST() to ensure cleanup even on error paths.
//
// Performance Impact:
//   - Prevents memory leaks by returning objects to pools
//   - Maintains 95%+ pool hit rates
//   - Reduces GC overhead by reusing allocations
//   - Essential for sustained high throughput (1.38M+ ops/sec)
//
// Example - Correct usage:
//
//	func processSQL(sql string) error {
//	    astObj := ast.NewAST()
//	    defer ast.ReleaseAST(astObj)  // Cleanup guaranteed
//
//	    // ... process astObj ...
//	    return nil
//	}
//
// See also: NewAST(), PutSelectStatement(), PutInsertStatement()
func ReleaseAST(ast *AST) {
	if ast == nil {
		return
	}

	// Clean up all statements
	for i := range ast.Statements {
		releaseStatement(ast.Statements[i])
		ast.Statements[i] = nil
	}

	// Reset slice but keep capacity
	ast.Statements = ast.Statements[:0]

	// Reset comments but keep capacity
	if cap(ast.Comments) > 0 {
		ast.Comments = ast.Comments[:0]
	}

	// Return to pool
	metrics.RecordNamedPoolPut("ast")
	astPool.Put(ast)
}

// ReleaseStatements returns a slice of statements back to their respective pools.
// Use this to clean up statements returned by ParseWithRecovery, which returns
// []Statement rather than an *AST.
//
// Example:
//
//	stmts, errs := parser.ParseWithRecovery(tokens)
//	defer ast.ReleaseStatements(stmts)
//	// ... process stmts and errs ...
func ReleaseStatements(stmts []Statement) {
	for i := range stmts {
		if stmts[i] == nil {
			continue
		}
		releaseStatement(stmts[i])
		stmts[i] = nil
	}
}

// releaseStatement returns a single Statement to its pool.
// This is the central dispatch used by both ReleaseAST and ReleaseStatements.
func releaseStatement(stmt Statement) {
	if stmt == nil {
		return
	}
	switch s := stmt.(type) {
	case *SelectStatement:
		PutSelectStatement(s)
	case *InsertStatement:
		PutInsertStatement(s)
	case *UpdateStatement:
		PutUpdateStatement(s)
	case *DeleteStatement:
		PutDeleteStatement(s)
	case *CreateTableStatement:
		PutCreateTableStatement(s)
	case *AlterTableStatement:
		PutAlterTableStatement(s)
	case *CreateIndexStatement:
		PutCreateIndexStatement(s)
	case *MergeStatement:
		PutMergeStatement(s)
	case *CreateViewStatement:
		PutCreateViewStatement(s)
	case *CreateMaterializedViewStatement:
		PutCreateMaterializedViewStatement(s)
	case *RefreshMaterializedViewStatement:
		PutRefreshMaterializedViewStatement(s)
	case *DropStatement:
		PutDropStatement(s)
	case *TruncateStatement:
		PutTruncateStatement(s)
	case *ShowStatement:
		PutShowStatement(s)
	case *DescribeStatement:
		PutDescribeStatement(s)
	case *UnsupportedStatement:
		PutUnsupportedStatement(s)
	case *ReplaceStatement:
		PutReplaceStatement(s)
	case *AlterStatement:
		PutAlterStatement(s)
	}
}

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

// GetUpdateExpression gets an UpdateExpression from the pool
func GetUpdateExpression() *UpdateExpression {
	return updateExprPool.Get().(*UpdateExpression)
}

// PutUpdateExpression returns an UpdateExpression to the pool
func PutUpdateExpression(expr *UpdateExpression) {
	if expr == nil {
		return
	}

	// Clean up expressions
	PutExpression(expr.Column)
	PutExpression(expr.Value)

	// Reset fields
	expr.Column = nil
	expr.Value = nil

	// Return to pool
	updateExprPool.Put(expr)
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

// GetIdentifier gets an Identifier from the pool
func GetIdentifier() *Identifier {
	return identifierPool.Get().(*Identifier)
}

// PutIdentifier returns an Identifier to the pool
func PutIdentifier(ident *Identifier) {
	if ident == nil {
		return
	}
	ident.Name = ""
	identifierPool.Put(ident)
}

// GetBinaryExpression gets a BinaryExpression from the pool
func GetBinaryExpression() *BinaryExpression {
	return binaryExprPool.Get().(*BinaryExpression)
}

// PutBinaryExpression returns a BinaryExpression to the pool
func PutBinaryExpression(expr *BinaryExpression) {
	if expr == nil {
		return
	}
	PutExpression(expr.Left)
	PutExpression(expr.Right)
	expr.Left = nil
	expr.Right = nil
	expr.Operator = ""
	binaryExprPool.Put(expr)
}

// GetExpressionSlice gets a slice of Expression from the pool
func GetExpressionSlice() *[]Expression {
	slice := exprSlicePool.Get().(*[]Expression)
	*slice = (*slice)[:0]
	return slice
}

// PutExpressionSlice returns a slice of Expression to the pool
func PutExpressionSlice(slice *[]Expression) {
	if slice == nil {
		return
	}
	for i := range *slice {
		PutExpression((*slice)[i])
		(*slice)[i] = nil
	}
	exprSlicePool.Put(slice)
}

// GetLiteralValue gets a LiteralValue from the pool
func GetLiteralValue() *LiteralValue {
	return literalValuePool.Get().(*LiteralValue)
}

// PutLiteralValue returns a LiteralValue to the pool
func PutLiteralValue(lit *LiteralValue) {
	if lit == nil {
		return
	}

	// Reset fields (Value is interface{}, use nil as zero value)
	lit.Value = nil
	lit.Type = ""

	// Return to pool
	literalValuePool.Put(lit)
}

// PutExpression returns any Expression to the appropriate pool with iterative cleanup.
//
// PutExpression is the primary function for returning expression nodes to their
// respective pools. It handles all expression types and uses iterative cleanup
// to prevent stack overflow with deeply nested expression trees.
//
// Key Features:
//   - Supports all expression types (30+ pooled types)
//   - Iterative cleanup algorithm (no recursion limits)
//   - Prevents stack overflow for deeply nested expressions
//   - Work queue size limits (MaxWorkQueueSize = 1000)
//   - Nil-safe (ignores nil expressions)
//
// Supported Expression Types:
//   - Identifier, LiteralValue, AliasedExpression
//   - BinaryExpression, UnaryExpression
//   - FunctionCall, CaseExpression
//   - BetweenExpression, InExpression
//   - SubqueryExpression, ExistsExpression, AnyExpression, AllExpression
//   - CastExpression, ExtractExpression, PositionExpression, SubstringExpression
//   - ListExpression
//
// Iterative Cleanup Algorithm:
//  1. Use work queue instead of recursion
//  2. Process expressions breadth-first
//  3. Collect child expressions and add to queue
//  4. Clean and return to pool
//  5. Limit queue size to prevent memory exhaustion
//
// Parameters:
//   - expr: Expression to return to pool (nil-safe)
//
// Usage Pattern:
//
//	expr := ast.GetBinaryExpression()
//	defer ast.PutExpression(expr)
//
//	// Build expression tree...
//
// Example - Cleaning up complex expression:
//
//	// Build: (age > 18 AND status = 'active') OR (role = 'admin')
//	expr := &ast.BinaryExpression{
//	    Left: &ast.BinaryExpression{
//	        Left:     &ast.BinaryExpression{...},
//	        Operator: "AND",
//	        Right:    &ast.BinaryExpression{...},
//	    },
//	    Operator: "OR",
//	    Right: &ast.BinaryExpression{...},
//	}
//
//	// Cleanup all nested expressions
//	ast.PutExpression(expr)  // Handles entire tree iteratively
//
// Performance Characteristics:
//   - O(n) time complexity where n = number of nodes
//   - O(min(n, MaxWorkQueueSize)) space complexity
//   - No stack overflow risk regardless of nesting depth
//   - Efficient for both shallow and deeply nested expressions
//
// Safety Guarantees:
//   - Thread-safe (uses sync.Pool internally)
//   - Nil-safe (gracefully handles nil expressions)
//   - Stack-safe (iterative, not recursive)
//   - Memory-safe (work queue size limits)
//
// IMPORTANT: This function should be used for all expression cleanup.
// Direct pool returns (e.g., binaryExprPool.Put()) bypass the iterative
// cleanup and may leave child expressions unreleased.
//
// See also: GetBinaryExpression(), GetFunctionCall(), GetIdentifier()
func PutExpression(expr Expression) {
	if expr == nil {
		return
	}
	putExpressionImpl(expr, 0)
}

// putExpressionImpl is the internal driver for PutExpression. The depth
// parameter tracks recursive re-entries from the work-queue overflow path
// to prevent stack overflow on pathologically deep ASTs.
func putExpressionImpl(expr Expression, depth int) {
	if expr == nil {
		return
	}

	// Use a work queue for iterative cleanup instead of recursion
	workQueue := make([]Expression, 0, 32)
	workQueue = append(workQueue, expr)

	processed := 0
	for len(workQueue) > 0 && processed < MaxWorkQueueSize {
		// Pop from queue
		current := workQueue[len(workQueue)-1]
		workQueue = workQueue[:len(workQueue)-1]
		processed++

		if current == nil {
			continue
		}

		// Process and collect child expressions
		switch e := current.(type) {
		case *Identifier:
			e.Name = ""
			identifierPool.Put(e)

		case *BinaryExpression:
			if e.Left != nil {
				workQueue = append(workQueue, e.Left)
			}
			if e.Right != nil {
				workQueue = append(workQueue, e.Right)
			}
			e.Left = nil
			e.Right = nil
			e.Operator = ""
			binaryExprPool.Put(e)

		case *LiteralValue:
			e.Value = nil
			e.Type = ""
			literalValuePool.Put(e)

		case *FunctionCall:
			for i := range e.Arguments {
				if e.Arguments[i] != nil {
					workQueue = append(workQueue, e.Arguments[i])
				}
				e.Arguments[i] = nil
			}
			e.Arguments = e.Arguments[:0]
			e.Name = ""
			e.Over = nil
			e.Distinct = false
			e.Filter = nil
			functionCallPool.Put(e)

		case *CaseExpression:
			if e.Value != nil {
				workQueue = append(workQueue, e.Value)
			}
			for i := range e.WhenClauses {
				if e.WhenClauses[i].Condition != nil {
					workQueue = append(workQueue, e.WhenClauses[i].Condition)
				}
				if e.WhenClauses[i].Result != nil {
					workQueue = append(workQueue, e.WhenClauses[i].Result)
				}
			}
			if e.ElseClause != nil {
				workQueue = append(workQueue, e.ElseClause)
			}
			e.Value = nil
			e.WhenClauses = e.WhenClauses[:0]
			e.ElseClause = nil
			caseExprPool.Put(e)

		case *BetweenExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			if e.Lower != nil {
				workQueue = append(workQueue, e.Lower)
			}
			if e.Upper != nil {
				workQueue = append(workQueue, e.Upper)
			}
			e.Expr = nil
			e.Lower = nil
			e.Upper = nil
			e.Not = false
			betweenExprPool.Put(e)

		case *InExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			for i := range e.List {
				if e.List[i] != nil {
					workQueue = append(workQueue, e.List[i])
				}
				e.List[i] = nil
			}
			e.Expr = nil
			e.List = e.List[:0]
			e.Subquery = nil
			e.Not = false
			inExprPool.Put(e)

		case *SubqueryExpression:
			e.Subquery = nil
			subqueryExprPool.Put(e)

		case *CastExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Type = ""
			castExprPool.Put(e)

		case *IntervalExpression:
			e.Value = ""
			intervalExprPool.Put(e)

		case *ArraySubscriptExpression:
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}
			for i := range e.Indices {
				if e.Indices[i] != nil {
					workQueue = append(workQueue, e.Indices[i])
				}
			}
			e.Array = nil
			e.Indices = e.Indices[:0]
			arraySubscriptExprPool.Put(e)

		case *ArraySliceExpression:
			if e.Array != nil {
				workQueue = append(workQueue, e.Array)
			}
			if e.Start != nil {
				workQueue = append(workQueue, e.Start)
			}
			if e.End != nil {
				workQueue = append(workQueue, e.End)
			}
			e.Array = nil
			e.Start = nil
			e.End = nil
			arraySliceExprPool.Put(e)

		case *ExistsExpression:
			e.Subquery = nil
			existsExprPool.Put(e)

		case *AnyExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Subquery = nil
			e.Operator = ""
			anyExprPool.Put(e)

		case *AllExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Subquery = nil
			e.Operator = ""
			allExprPool.Put(e)

		case *ListExpression:
			for i := range e.Values {
				if e.Values[i] != nil {
					workQueue = append(workQueue, e.Values[i])
				}
				e.Values[i] = nil
			}
			e.Values = e.Values[:0]
			listExprPool.Put(e)

		case *TupleExpression:
			for i := range e.Expressions {
				if e.Expressions[i] != nil {
					workQueue = append(workQueue, e.Expressions[i])
				}
				e.Expressions[i] = nil
			}
			e.Expressions = e.Expressions[:0]
			tupleExprPool.Put(e)

		case *ArrayConstructorExpression:
			for i := range e.Elements {
				if e.Elements[i] != nil {
					workQueue = append(workQueue, e.Elements[i])
				}
				e.Elements[i] = nil
			}
			e.Elements = e.Elements[:0]
			e.Subquery = nil
			arrayConstructorPool.Put(e)

		case *UnaryExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Operator = 0 // UnaryOperator is int type
			unaryExprPool.Put(e)

		case *ExtractExpression:
			if e.Source != nil {
				workQueue = append(workQueue, e.Source)
			}
			e.Field = ""
			e.Source = nil
			extractExprPool.Put(e)

		case *PositionExpression:
			if e.Substr != nil {
				workQueue = append(workQueue, e.Substr)
			}
			if e.Str != nil {
				workQueue = append(workQueue, e.Str)
			}
			e.Substr = nil
			e.Str = nil
			positionExprPool.Put(e)

		case *SubstringExpression:
			if e.Str != nil {
				workQueue = append(workQueue, e.Str)
			}
			if e.Start != nil {
				workQueue = append(workQueue, e.Start)
			}
			if e.Length != nil {
				workQueue = append(workQueue, e.Length)
			}
			e.Str = nil
			e.Start = nil
			e.Length = nil
			substringExprPool.Put(e)

		case *AliasedExpression:
			if e.Expr != nil {
				workQueue = append(workQueue, e.Expr)
			}
			e.Expr = nil
			e.Alias = ""
			aliasedExprPool.Put(e)

		// Default case - expression type not pooled, just ignore
		default:
			// Unknown expression type - no pool available
		}
	}

	// OVERFLOW DRAIN: if we hit the work-queue cap, there are still pooled
	// nodes in workQueue that would otherwise leak. Fall back to a recursive
	// drain, depth-limited to prevent stack overflow on deeply nested trees.
	// Each recursive call starts its own fresh work queue of up to
	// MaxWorkQueueSize, so the recursion depth is effectively
	// ceil(total_nodes / MaxWorkQueueSize). MaxCleanupDepth = 100 bounds this
	// at ~10_000_000 total nodes in an AST — far beyond any real SQL query.
	if len(workQueue) > 0 {
		atomic.AddUint64(&poolLeakCount, uint64(len(workQueue)))
		if depth < MaxCleanupDepth {
			for _, remaining := range workQueue {
				putExpressionImpl(remaining, depth+1)
			}
		}
		// If depth exceeded MaxCleanupDepth we accept the leak rather than
		// blow the stack; poolLeakCount records the truncation for diagnostics.
	}
}

// GetFunctionCall gets a FunctionCall from the pool
func GetFunctionCall() *FunctionCall {
	fc := functionCallPool.Get().(*FunctionCall)
	fc.Arguments = fc.Arguments[:0]
	return fc
}

// PutFunctionCall returns a FunctionCall to the pool
func PutFunctionCall(fc *FunctionCall) {
	if fc == nil {
		return
	}
	for i := range fc.Arguments {
		PutExpression(fc.Arguments[i])
		fc.Arguments[i] = nil
	}
	fc.Arguments = fc.Arguments[:0]
	fc.Name = ""
	fc.Over = nil
	fc.Distinct = false
	fc.Filter = nil
	functionCallPool.Put(fc)
}

// GetCaseExpression gets a CaseExpression from the pool
func GetCaseExpression() *CaseExpression {
	ce := caseExprPool.Get().(*CaseExpression)
	ce.WhenClauses = ce.WhenClauses[:0]
	return ce
}

// PutCaseExpression returns a CaseExpression to the pool
func PutCaseExpression(ce *CaseExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce.Value)
	ce.Value = nil
	for i := range ce.WhenClauses {
		PutExpression(ce.WhenClauses[i].Condition)
		PutExpression(ce.WhenClauses[i].Result)
	}
	ce.WhenClauses = ce.WhenClauses[:0]
	PutExpression(ce.ElseClause)
	ce.ElseClause = nil
	caseExprPool.Put(ce)
}

// GetBetweenExpression gets a BetweenExpression from the pool
func GetBetweenExpression() *BetweenExpression {
	return betweenExprPool.Get().(*BetweenExpression)
}

// PutBetweenExpression returns a BetweenExpression to the pool
func PutBetweenExpression(be *BetweenExpression) {
	if be == nil {
		return
	}
	PutExpression(be.Expr)
	PutExpression(be.Lower)
	PutExpression(be.Upper)
	be.Expr = nil
	be.Lower = nil
	be.Upper = nil
	be.Not = false
	betweenExprPool.Put(be)
}

// GetInExpression gets an InExpression from the pool
func GetInExpression() *InExpression {
	ie := inExprPool.Get().(*InExpression)
	ie.List = ie.List[:0]
	return ie
}

// PutInExpression returns an InExpression to the pool
func PutInExpression(ie *InExpression) {
	if ie == nil {
		return
	}
	PutExpression(ie.Expr)
	ie.Expr = nil
	for i := range ie.List {
		PutExpression(ie.List[i])
		ie.List[i] = nil
	}
	ie.List = ie.List[:0]
	ie.Subquery = nil
	ie.Not = false
	inExprPool.Put(ie)
}

// GetTupleExpression gets a TupleExpression from the pool
func GetTupleExpression() *TupleExpression {
	te := tupleExprPool.Get().(*TupleExpression)
	te.Expressions = te.Expressions[:0]
	return te
}

// PutTupleExpression returns a TupleExpression to the pool
func PutTupleExpression(te *TupleExpression) {
	if te == nil {
		return
	}
	for i := range te.Expressions {
		PutExpression(te.Expressions[i])
		te.Expressions[i] = nil
	}
	te.Expressions = te.Expressions[:0]
	tupleExprPool.Put(te)
}

// GetArrayConstructor gets an ArrayConstructorExpression from the pool
func GetArrayConstructor() *ArrayConstructorExpression {
	ac := arrayConstructorPool.Get().(*ArrayConstructorExpression)
	ac.Elements = ac.Elements[:0]
	ac.Subquery = nil
	return ac
}

// PutArrayConstructor returns an ArrayConstructorExpression to the pool
func PutArrayConstructor(ac *ArrayConstructorExpression) {
	if ac == nil {
		return
	}
	for i := range ac.Elements {
		PutExpression(ac.Elements[i])
		ac.Elements[i] = nil
	}
	ac.Elements = ac.Elements[:0]
	ac.Subquery = nil
	arrayConstructorPool.Put(ac)
}

// GetSubqueryExpression gets a SubqueryExpression from the pool
func GetSubqueryExpression() *SubqueryExpression {
	return subqueryExprPool.Get().(*SubqueryExpression)
}

// PutSubqueryExpression returns a SubqueryExpression to the pool
func PutSubqueryExpression(se *SubqueryExpression) {
	if se == nil {
		return
	}
	se.Subquery = nil
	subqueryExprPool.Put(se)
}

// GetCastExpression gets a CastExpression from the pool
func GetCastExpression() *CastExpression {
	return castExprPool.Get().(*CastExpression)
}

// PutCastExpression returns a CastExpression to the pool
func PutCastExpression(ce *CastExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce.Expr)
	ce.Expr = nil
	ce.Type = ""
	castExprPool.Put(ce)
}

// GetIntervalExpression gets an IntervalExpression from the pool
func GetIntervalExpression() *IntervalExpression {
	return intervalExprPool.Get().(*IntervalExpression)
}

// PutIntervalExpression returns an IntervalExpression to the pool
func PutIntervalExpression(ie *IntervalExpression) {
	if ie == nil {
		return
	}
	ie.Value = ""
	intervalExprPool.Put(ie)
}

// GetAliasedExpression retrieves an AliasedExpression from the pool
func GetAliasedExpression() *AliasedExpression {
	return aliasedExprPool.Get().(*AliasedExpression)
}

// PutAliasedExpression returns an AliasedExpression to the pool
func PutAliasedExpression(ae *AliasedExpression) {
	if ae == nil {
		return
	}
	PutExpression(ae.Expr)
	ae.Expr = nil
	ae.Alias = ""
	aliasedExprPool.Put(ae)
}

// GetArraySubscriptExpression gets an ArraySubscriptExpression from the pool
func GetArraySubscriptExpression() *ArraySubscriptExpression {
	return arraySubscriptExprPool.Get().(*ArraySubscriptExpression)
}

// PutArraySubscriptExpression returns an ArraySubscriptExpression to the pool
func PutArraySubscriptExpression(ase *ArraySubscriptExpression) {
	if ase == nil {
		return
	}
	// Clean up array expression
	if ase.Array != nil {
		PutExpression(ase.Array)
		ase.Array = nil
	}
	// Clean up indices
	for i := range ase.Indices {
		if ase.Indices[i] != nil {
			PutExpression(ase.Indices[i])
		}
	}
	ase.Indices = ase.Indices[:0] // Clear slice but keep capacity
	arraySubscriptExprPool.Put(ase)
}

// GetArraySliceExpression gets an ArraySliceExpression from the pool
func GetArraySliceExpression() *ArraySliceExpression {
	return arraySliceExprPool.Get().(*ArraySliceExpression)
}

// PutArraySliceExpression returns an ArraySliceExpression to the pool
func PutArraySliceExpression(ase *ArraySliceExpression) {
	if ase == nil {
		return
	}
	// Clean up array expression
	if ase.Array != nil {
		PutExpression(ase.Array)
		ase.Array = nil
	}
	// Clean up start/end expressions
	if ase.Start != nil {
		PutExpression(ase.Start)
		ase.Start = nil
	}
	if ase.End != nil {
		PutExpression(ase.End)
		ase.End = nil
	}
	arraySliceExprPool.Put(ase)
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

// GetCreateIndexStatement gets a CreateIndexStatement from the pool.
func GetCreateIndexStatement() *CreateIndexStatement {
	stmt := createIndexStmtPool.Get().(*CreateIndexStatement)
	stmt.Columns = stmt.Columns[:0]
	return stmt
}

// PutCreateIndexStatement returns a CreateIndexStatement to the pool.
// It releases the optional WHERE expression.
func PutCreateIndexStatement(stmt *CreateIndexStatement) {
	if stmt == nil {
		return
	}

	PutExpression(stmt.Where)

	for i := range stmt.Columns {
		stmt.Columns[i].Column = ""
		stmt.Columns[i].Collate = ""
		stmt.Columns[i].Direction = ""
		stmt.Columns[i].NullsLast = false
	}
	stmt.Columns = stmt.Columns[:0]

	stmt.Where = nil
	stmt.Unique = false
	stmt.IfNotExists = false
	stmt.Name = ""
	stmt.Table = ""
	stmt.Using = ""

	createIndexStmtPool.Put(stmt)
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

// GetCreateViewStatement gets a CreateViewStatement from the pool.
func GetCreateViewStatement() *CreateViewStatement {
	stmt := createViewStmtPool.Get().(*CreateViewStatement)
	stmt.Columns = stmt.Columns[:0]
	return stmt
}

// PutCreateViewStatement returns a CreateViewStatement to the pool.
// It recursively releases the nested query statement.
func PutCreateViewStatement(stmt *CreateViewStatement) {
	if stmt == nil {
		return
	}

	// Recursively release the nested SELECT query
	releaseStatement(stmt.Query)

	stmt.OrReplace = false
	stmt.Temporary = false
	stmt.IfNotExists = false
	stmt.Name = ""
	stmt.Columns = stmt.Columns[:0]
	stmt.Query = nil
	stmt.WithOption = ""

	createViewStmtPool.Put(stmt)
}

// GetCreateMaterializedViewStatement gets a CreateMaterializedViewStatement from the pool.
func GetCreateMaterializedViewStatement() *CreateMaterializedViewStatement {
	stmt := createMaterializedViewStmtPool.Get().(*CreateMaterializedViewStatement)
	stmt.Columns = stmt.Columns[:0]
	return stmt
}

// PutCreateMaterializedViewStatement returns a CreateMaterializedViewStatement to the pool.
// It recursively releases the nested query statement.
func PutCreateMaterializedViewStatement(stmt *CreateMaterializedViewStatement) {
	if stmt == nil {
		return
	}

	// Recursively release the nested SELECT query
	releaseStatement(stmt.Query)

	stmt.IfNotExists = false
	stmt.Name = ""
	stmt.Columns = stmt.Columns[:0]
	stmt.Query = nil
	stmt.WithData = nil
	stmt.Tablespace = ""

	createMaterializedViewStmtPool.Put(stmt)
}

// GetRefreshMaterializedViewStatement gets a RefreshMaterializedViewStatement from the pool.
func GetRefreshMaterializedViewStatement() *RefreshMaterializedViewStatement {
	return refreshMaterializedViewStmtPool.Get().(*RefreshMaterializedViewStatement)
}

// PutRefreshMaterializedViewStatement returns a RefreshMaterializedViewStatement to the pool.
func PutRefreshMaterializedViewStatement(stmt *RefreshMaterializedViewStatement) {
	if stmt == nil {
		return
	}

	stmt.Concurrently = false
	stmt.Name = ""
	stmt.WithData = nil

	refreshMaterializedViewStmtPool.Put(stmt)
}

// GetDropStatement gets a DropStatement from the pool.
func GetDropStatement() *DropStatement {
	stmt := dropStmtPool.Get().(*DropStatement)
	stmt.Names = stmt.Names[:0]
	return stmt
}

// PutDropStatement returns a DropStatement to the pool.
func PutDropStatement(stmt *DropStatement) {
	if stmt == nil {
		return
	}

	stmt.ObjectType = ""
	stmt.IfExists = false
	stmt.Names = stmt.Names[:0]
	stmt.CascadeType = ""

	dropStmtPool.Put(stmt)
}

// GetTruncateStatement gets a TruncateStatement from the pool.
func GetTruncateStatement() *TruncateStatement {
	stmt := truncateStmtPool.Get().(*TruncateStatement)
	stmt.Tables = stmt.Tables[:0]
	return stmt
}

// PutTruncateStatement returns a TruncateStatement to the pool.
func PutTruncateStatement(stmt *TruncateStatement) {
	if stmt == nil {
		return
	}

	stmt.Tables = stmt.Tables[:0]
	stmt.RestartIdentity = false
	stmt.ContinueIdentity = false
	stmt.CascadeType = ""

	truncateStmtPool.Put(stmt)
}

// GetShowStatement gets a ShowStatement from the pool.
func GetShowStatement() *ShowStatement {
	return showStmtPool.Get().(*ShowStatement)
}

// PutShowStatement returns a ShowStatement to the pool.
func PutShowStatement(stmt *ShowStatement) {
	if stmt == nil {
		return
	}

	stmt.ShowType = ""
	stmt.ObjectName = ""
	stmt.From = ""

	showStmtPool.Put(stmt)
}

// GetDescribeStatement gets a DescribeStatement from the pool.
func GetDescribeStatement() *DescribeStatement {
	return describeStmtPool.Get().(*DescribeStatement)
}

// PutDescribeStatement returns a DescribeStatement to the pool.
func PutDescribeStatement(stmt *DescribeStatement) {
	if stmt == nil {
		return
	}

	stmt.TableName = ""

	describeStmtPool.Put(stmt)
}

// GetUnsupportedStatement gets an UnsupportedStatement from the pool.
func GetUnsupportedStatement() *UnsupportedStatement {
	return unsupportedStmtPool.Get().(*UnsupportedStatement)
}

// PutUnsupportedStatement returns an UnsupportedStatement to the pool.
func PutUnsupportedStatement(stmt *UnsupportedStatement) {
	if stmt == nil {
		return
	}

	stmt.Kind = ""
	stmt.RawSQL = ""

	unsupportedStmtPool.Put(stmt)
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

// GetAlterStatement gets an AlterStatement from the pool.
func GetAlterStatement() *AlterStatement {
	return alterStmtPool.Get().(*AlterStatement)
}

// PutAlterStatement returns an AlterStatement to the pool.
// It zeroes all fields; the Operation interface value is cleared but
// its internal allocations are not recursively pooled (they use custom types).
func PutAlterStatement(stmt *AlterStatement) {
	if stmt == nil {
		return
	}

	stmt.Type = 0
	stmt.Name = ""
	stmt.Operation = nil

	alterStmtPool.Put(stmt)
}

// NewCreateSequenceStatement retrieves a CreateSequenceStatement from the pool.
func NewCreateSequenceStatement() *CreateSequenceStatement {
	return createSequencePool.Get().(*CreateSequenceStatement)
}

// ReleaseCreateSequenceStatement returns a CreateSequenceStatement to the pool.
func ReleaseCreateSequenceStatement(s *CreateSequenceStatement) {
	*s = CreateSequenceStatement{} // zero all fields
	createSequencePool.Put(s)
}

// NewDropSequenceStatement retrieves a DropSequenceStatement from the pool.
func NewDropSequenceStatement() *DropSequenceStatement {
	return dropSequencePool.Get().(*DropSequenceStatement)
}

// ReleaseDropSequenceStatement returns a DropSequenceStatement to the pool.
// Always call this with defer after parsing is complete.
func ReleaseDropSequenceStatement(s *DropSequenceStatement) {
	*s = DropSequenceStatement{} // zero all fields
	dropSequencePool.Put(s)
}

// NewAlterSequenceStatement retrieves an AlterSequenceStatement from the pool.
func NewAlterSequenceStatement() *AlterSequenceStatement {
	return alterSequencePool.Get().(*AlterSequenceStatement)
}

// ReleaseAlterSequenceStatement returns an AlterSequenceStatement to the pool.
func ReleaseAlterSequenceStatement(s *AlterSequenceStatement) {
	*s = AlterSequenceStatement{} // zero all fields
	alterSequencePool.Put(s)
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
