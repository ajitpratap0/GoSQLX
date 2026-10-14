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

// This file provides SQL metadata extraction functions for the gosqlx package.
//
// The extraction functions traverse the Abstract Syntax Tree (AST) to collect
// metadata such as table names, column references, function calls, and qualified
// identifiers. These functions are useful for query analysis, security scanning,
// dependency tracking, and query optimization.
//
// # Extraction Functions Overview
//
// The gosqlx package provides six main extraction functions:
//   - ExtractTables: Simple table names (e.g., "users", "orders")
//   - ExtractTablesQualified: Qualified table names (e.g., "public.users")
//   - ExtractColumns: Simple column names (e.g., "name", "email")
//   - ExtractColumnsQualified: Qualified column names (e.g., "u.name")
//   - ExtractFunctions: Function names (e.g., "COUNT", "SUM")
//   - ExtractMetadata: All metadata in one call (convenience function)
//
// All extraction functions are thread-safe and can be called concurrently on
// different AST instances. They return deduplicated results, so each identifier
// appears only once in the output regardless of how many times it appears in the query.
//
// # Performance Characteristics
//
// Extraction functions are optimized for performance:
//   - Single AST traversal per extraction call
//   - O(N) time complexity where N is the number of AST nodes
//   - HashMap-based deduplication for O(1) lookup
//   - Minimal memory allocation (reuses visitor pattern)
//
// For large ASTs (1000+ nodes), expect extraction times <100μs on modern hardware.
//
// # Supported Expression Types
//
// The extraction functions correctly traverse all standard expression types
// including: CASE (simple and searched), CAST, IN, BETWEEN, EXTRACT,
// SUBSTRING, POSITION, subqueries, recursive CTEs with JOINs, window
// functions, and all arithmetic/logical operators.
//
// If you encounter parsing issues with SQL queries that should be supported,
// please report them at: https://github.com/ajitpratap0/GoSQLX/issues
package gosqlx

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// QualifiedName represents a fully qualified table or column name with optional schema.
//
// This type supports various levels of qualification commonly found in SQL queries:
//   - Single-part: "users" (just Name)
//   - Two-part: "public.users" (Schema.Name) or "u.name" (Table.Name)
//   - Three-part: "db.public.users" (Schema.Table.Name)
//
// The interpretation of fields depends on context:
//   - For tables: Schema typically represents database/schema, Name represents table
//   - For columns: Table represents table/alias, Name represents column
//   - For three-part names: Schema.Table.Name covers all levels
//
// Thread Safety: QualifiedName is a simple struct and safe to use concurrently.
// The String() and FullName() methods are read-only and safe for concurrent calls.
//
// Example - Table qualification:
//
//	// Simple table
//	QualifiedName{Name: "users"}  // "users"
//
//	// Schema-qualified table
//	QualifiedName{Schema: "public", Name: "users"}  // "public.users"
//
//	// Database-schema-table (PostgreSQL)
//	QualifiedName{Schema: "mydb", Table: "public", Name: "users"}  // "mydb.public.users"
//
// Example - Column qualification:
//
//	// Simple column
//	QualifiedName{Name: "email"}  // "email"
//
//	// Table-qualified column
//	QualifiedName{Table: "u", Name: "email"}  // "u.email"
//
//	// Fully qualified column
//	QualifiedName{Schema: "public", Table: "users", Name: "email"}  // "public.users.email"
//
// Use String() to get the full qualified name, or FullName() to get the name
// without the schema component (useful for working with qualified identifiers
// in a single database context).
type QualifiedName struct {
	// Schema is the optional schema or database name (first qualifier).
	// Examples: "public", "mydb", "information_schema"
	Schema string

	// Table is the table name or middle qualifier.
	// For tables: may be the schema when Schema and Name are both set
	// For columns: typically the table name or alias
	Table string

	// Name is the primary identifier (final qualifier).
	// For tables: the table name
	// For columns: the column name
	Name string
}

// String returns the qualified name as a string.
func (q QualifiedName) String() string {
	parts := make([]string, 0, 3)
	if q.Schema != "" {
		parts = append(parts, q.Schema)
	}
	if q.Table != "" {
		parts = append(parts, q.Table)
	}
	if q.Name != "" {
		parts = append(parts, q.Name)
	}
	return strings.Join(parts, ".")
}

// FullName returns the full name without schema qualifier.
// This method strips the schema component and returns the meaningful identifier.
//
// Behavior:
//   - For 3-part names (schema.table.column): Returns table.column (drops schema)
//   - For 2-part names (table.column OR schema.table): Returns table.column
//   - For single-part names: Returns the name
//
// Examples:
//   - QualifiedName{Schema: "db", Table: "public", Name: "users"} → "public.users"
//   - QualifiedName{Table: "users", Name: "id"} → "users.id"
//   - QualifiedName{Name: "id"} → "id"
//   - QualifiedName{Schema: "public", Name: "users"} → "users"
//   - QualifiedName{Table: "users"} → "users"
func (q QualifiedName) FullName() string {
	// 3-part qualified name (schema.table.column): return table.column (drop schema)
	if q.Schema != "" && q.Table != "" && q.Name != "" {
		return q.Table + "." + q.Name
	}
	// 2-part qualified name: table.column OR schema.table
	if q.Table != "" && q.Name != "" {
		return q.Table + "." + q.Name
	}
	// Single part: just name (column or table)
	if q.Name != "" {
		return q.Name
	}
	// Fallback: just table name
	return q.Table
}

// ExtractTables extracts all table names from an AST.
//
// This function traverses the AST and collects all table references from:
//   - FROM clauses
//   - JOIN clauses
//   - Subqueries and CTEs
//   - INSERT/UPDATE/DELETE statements
//
// Returns a deduplicated slice of table names, sorted in ascending byte order.
//
// Example:
//
//	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
//	ast, _ := gosqlx.Parse(sql)
//	tables := gosqlx.ExtractTables(ast)
//	// tables = ["orders", "users"]
func ExtractTables(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	c := &metadataCollector{want: extractTables, tables: make(map[string]struct{})}
	c.collect(astNode)
	return stringSetToSlice(c.tables)
}

// ExtractTablesQualified extracts all table names with their qualifiers (schema.table).
//
// This function is similar to ExtractTables but preserves schema information
// when present in the original query.
//
// Returns a deduplicated slice of QualifiedName objects, sorted by Schema,
// then Table, then Name.
//
// Example:
//
//	sql := "SELECT * FROM public.users JOIN app.orders ON users.id = orders.user_id"
//	ast, _ := gosqlx.Parse(sql)
//	tables := gosqlx.ExtractTablesQualified(ast)
//	// tables contains QualifiedName{Schema: "public", Name: "users"} and
//	// QualifiedName{Schema: "app", Name: "orders"}
func ExtractTablesQualified(astNode *ast.AST) []QualifiedName {
	if astNode == nil {
		return nil
	}

	c := &metadataCollector{want: extractTablesQualified, tablesQualified: make(map[QualifiedName]struct{})}
	c.collect(astNode)
	return qualifiedSetToSlice(c.tablesQualified)
}

// ExtractColumns extracts all column references from an AST.
//
// This function traverses the AST and collects column references from:
//   - SELECT lists
//   - WHERE conditions
//   - GROUP BY clauses
//   - ORDER BY clauses
//   - JOIN conditions
//   - HAVING clauses
//
// Returns a deduplicated slice of column names (without table qualifiers),
// sorted in ascending byte order.
//
// Example:
//
//	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true ORDER BY u.created_at"
//	ast, _ := gosqlx.Parse(sql)
//	columns := gosqlx.ExtractColumns(ast)
//	// columns = ["active", "created_at", "email", "name"]
func ExtractColumns(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	c := &metadataCollector{want: extractColumns, columns: make(map[string]struct{})}
	c.collect(astNode)
	return stringSetToSlice(c.columns)
}

// ExtractColumnsQualified extracts all column references with their table qualifiers.
//
// This function is similar to ExtractColumns but preserves table qualifier information
// when present in the original query. It collects column references from:
//   - SELECT lists
//   - WHERE conditions
//   - GROUP BY clauses
//   - ORDER BY clauses
//   - JOIN conditions
//   - HAVING clauses
//
// Returns a deduplicated slice of QualifiedName objects representing columns,
// sorted by Schema, then Table, then Name.
// A multi-part reference is split at its last qualifier: db.t.col yields
// QualifiedName{Schema: "db", Table: "t", Name: "col"}, and c.s.t.col yields
// Schema "c.s".
//
// Example:
//
//	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true"
//	ast, _ := gosqlx.Parse(sql)
//	columns := gosqlx.ExtractColumnsQualified(ast)
//	// columns contains QualifiedName{Table: "u", Name: "name"},
//	// QualifiedName{Table: "u", Name: "email"}, QualifiedName{Table: "u", Name: "active"}
func ExtractColumnsQualified(astNode *ast.AST) []QualifiedName {
	if astNode == nil {
		return nil
	}

	c := &metadataCollector{want: extractColumnsQualified, columnsQualified: make(map[QualifiedName]struct{})}
	c.collect(astNode)
	return qualifiedSetToSlice(c.columnsQualified)
}

// ExtractFunctions extracts all function calls from an AST.
//
// This function traverses the AST and collects all function names, including:
//   - Aggregate functions (COUNT, SUM, AVG, etc.)
//   - Window functions (ROW_NUMBER, RANK, etc.)
//   - Scalar functions (UPPER, LOWER, NOW, etc.)
//
// Returns a deduplicated slice of function names, sorted in ascending byte order.
//
// Example:
//
//	sql := "SELECT COUNT(*), UPPER(name) FROM users"
//	ast, _ := gosqlx.Parse(sql)
//	functions := gosqlx.ExtractFunctions(ast)
//	// functions = ["COUNT", "UPPER"]
func ExtractFunctions(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	c := &metadataCollector{want: extractFunctions, functions: make(map[string]struct{})}
	c.collect(astNode)
	return stringSetToSlice(c.functions)
}

// extractKind is a bitmask selecting which outputs a metadataCollector gathers.
type extractKind uint8

const (
	extractTables extractKind = 1 << iota
	extractTablesQualified
	extractColumns
	extractColumnsQualified
	extractFunctions

	extractAll = extractTables | extractTablesQualified | extractColumns |
		extractColumnsQualified | extractFunctions

	// extractExprKinds is the subset of kinds that require walking expressions.
	extractExprKinds = extractColumns | extractColumnsQualified | extractFunctions
)

// parseQualifiedTableName splits a dotted table name into a QualifiedName.
//
// Semantics: 1 part -> Name; 2 parts -> Schema.Name; 3 parts -> Schema.Table.Name;
// 4 or more parts -> the whole string as Name. Empty parts are preserved.
// It does not allocate; the returned strings alias name (qualifiedSetToSlice
// copies them before they reach the caller).
func parseQualifiedTableName(name string) QualifiedName {
	schema, rest, ok := strings.Cut(name, ".")
	if !ok {
		return QualifiedName{Name: name}
	}
	table, last, ok := strings.Cut(rest, ".")
	if !ok {
		return QualifiedName{Schema: schema, Name: rest}
	}
	if strings.IndexByte(last, '.') >= 0 {
		return QualifiedName{Name: name}
	}
	return QualifiedName{Schema: schema, Table: table, Name: last}
}

// metadataCollector gathers any combination of tables, columns and functions
// in a single AST traversal. Maps for kinds that were not requested stay nil
// and are never written to.
type metadataCollector struct {
	want             extractKind
	tables           map[string]struct{}
	tablesQualified  map[QualifiedName]struct{}
	columns          map[string]struct{}
	columnsQualified map[QualifiedName]struct{}
	functions        map[string]struct{}
}

func (c *metadataCollector) collect(astNode *ast.AST) {
	for _, stmt := range astNode.Statements {
		c.collectFromNode(stmt)
	}
}

func (c *metadataCollector) addTable(name string) {
	if name == "" {
		return
	}
	if c.want&extractTables != 0 {
		c.tables[name] = struct{}{}
	}
	if c.want&extractTablesQualified != 0 {
		c.tablesQualified[parseQualifiedTableName(name)] = struct{}{}
	}
}

func (c *metadataCollector) addColumn(table, name string, want extractKind) {
	if name == "" || name == "*" {
		return
	}
	if want&extractColumns != 0 {
		c.columns[name] = struct{}{}
	}
	if want&extractColumnsQualified != 0 {
		q := QualifiedName{Table: table, Name: name}
		// A multi-part reference (db.t.col) carries "db.t" as its qualifier;
		// split it at the last dot so the column's Schema/Table match
		// ExtractTablesQualified's {Schema: "db", Name: "t"} for table db.t.
		if dot := strings.LastIndexByte(table, '.'); dot >= 0 {
			q.Schema, q.Table = table[:dot], table[dot+1:]
		}
		c.columnsQualified[q] = struct{}{}
	}
}

func (c *metadataCollector) addFunction(name string) {
	if name != "" {
		c.functions[name] = struct{}{}
	}
}

func (c *metadataCollector) collectFromNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.Identifier:
		c.addColumn(n.Table, n.Name, c.want)
	case *ast.SelectStatement:
		for _, from := range n.From {
			c.addTable(from.Name)
		}
		for _, join := range n.Joins {
			c.addTable(join.Right.Name)
		}
		for _, col := range n.Columns {
			c.collectFromExpression(col, c.want)
		}
		c.collectFromExpression(n.Where, c.want)
		for _, gb := range n.GroupBy {
			c.collectFromExpression(gb, c.want)
		}
		c.collectFromExpression(n.Having, c.want)
		for _, ob := range n.OrderBy {
			c.collectFromExpression(ob.Expression, c.want)
		}
		if n.With != nil {
			c.collectFromNode(n.With)
		}
	case *ast.InsertStatement:
		c.addTable(n.TableName)
		for _, col := range n.Columns {
			c.collectFromExpression(col, c.want&^extractFunctions)
		}
		for _, row := range n.Values {
			for _, val := range row {
				c.collectFromExpression(val, c.want&extractFunctions)
			}
		}
		if n.Query != nil {
			c.collectFromNode(n.Query)
		}
		if n.With != nil {
			c.collectFromNode(n.With)
		}
	case *ast.UpdateStatement:
		c.addTable(n.TableName)
		for _, from := range n.From {
			c.addTable(from.Name)
		}
		for i := range n.Assignments {
			c.collectFromNode(&n.Assignments[i])
		}
		c.collectFromExpression(n.Where, c.want)
		if n.With != nil {
			c.collectFromNode(n.With)
		}
	case *ast.DeleteStatement:
		c.addTable(n.TableName)
		for _, using := range n.Using {
			c.addTable(using.Name)
		}
		c.collectFromExpression(n.Where, c.want)
		if n.With != nil {
			c.collectFromNode(n.With)
		}
	case *ast.UpdateExpression:
		c.collectFromExpression(n.Column, c.want&^extractFunctions)
		c.collectFromExpression(n.Value, c.want)
	case *ast.WithClause:
		for _, cte := range n.CTEs {
			c.collectFromNode(cte)
		}
	case *ast.CommonTableExpr:
		c.collectFromNode(n.Statement)
	case *ast.SetOperation:
		c.collectFromNode(n.Left)
		c.collectFromNode(n.Right)
	}

	// Recursively collect from children
	for _, child := range node.Children() {
		c.collectFromNode(child)
	}
}

// collectFromExpression walks an expression tree collecting the kinds in want
// (restricted to the expression-level kinds).
func (c *metadataCollector) collectFromExpression(expr ast.Expression, want extractKind) {
	want &= extractExprKinds
	if expr == nil || want == 0 {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		c.addColumn(e.Table, e.Name, want)
	case *ast.BinaryExpression:
		c.collectFromExpression(e.Left, want)
		c.collectFromExpression(e.Right, want)
	case *ast.FunctionCall:
		if want&extractFunctions != 0 {
			c.addFunction(e.Name)
		}
		for _, arg := range e.Arguments {
			c.collectFromExpression(arg, want)
		}
		if e.Filter != nil {
			c.collectFromExpression(e.Filter, want)
		}
	case *ast.UnaryExpression:
		c.collectFromExpression(e.Expr, want)
	case *ast.ParenthesizedExpression:
		c.collectFromExpression(e.Expr, want)
	case *ast.InExpression:
		c.collectFromExpression(e.Expr, want)
		for _, item := range e.List {
			c.collectFromExpression(item, want)
		}
	case *ast.BetweenExpression:
		c.collectFromExpression(e.Expr, want)
		c.collectFromExpression(e.Lower, want)
		c.collectFromExpression(e.Upper, want)
	case *ast.CaseExpression:
		if e.Value != nil {
			c.collectFromExpression(e.Value, want)
		}
		for _, when := range e.WhenClauses {
			c.collectFromExpression(when.Condition, want)
			c.collectFromExpression(when.Result, want)
		}
		if e.ElseClause != nil {
			c.collectFromExpression(e.ElseClause, want)
		}
	case *ast.CastExpression:
		c.collectFromExpression(e.Expr, want)
	case *ast.SubstringExpression:
		c.collectFromExpression(e.Str, want)
		c.collectFromExpression(e.Start, want)
		if e.Length != nil {
			c.collectFromExpression(e.Length, want)
		}
	case *ast.ExtractExpression:
		c.collectFromExpression(e.Source, want)
	case *ast.PositionExpression:
		c.collectFromExpression(e.Substr, want)
		c.collectFromExpression(e.Str, want)
	case *ast.ListExpression:
		for _, v := range e.Values {
			c.collectFromExpression(v, want)
		}
	case *ast.AliasedExpression:
		// Unwrap the aliased expression and collect from inner expression
		c.collectFromExpression(e.Expr, want)
	}
}

// stringSetToSlice returns the keys of m as independent strings. AST values
// are substrings of the parsed SQL, so returning them as-is would let a
// caller that keeps only a table name keep the whole input alive. Each
// distinct value is copied once, into a single allocation shared by the
// result (see detachStrings). The keys are returned in ascending byte order
// so the output is deterministic regardless of map iteration order (#619).
func stringSetToSlice(m map[string]struct{}) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	slices.Sort(result)
	detachStrings(result)
	return result
}

// compareQualifiedName is a total order over all three fields: Schema, then
// Table, then Name.
func compareQualifiedName(a, b QualifiedName) int {
	return cmp.Or(
		strings.Compare(a.Schema, b.Schema),
		strings.Compare(a.Table, b.Table),
		strings.Compare(a.Name, b.Name),
	)
}

// qualifiedSetToSlice returns the keys of m with every part copied; see
// stringSetToSlice. The result is sorted by (Schema, Table, Name) so the
// output is deterministic regardless of map iteration order (#619).
func qualifiedSetToSlice(m map[QualifiedName]struct{}) []QualifiedName {
	result := make([]QualifiedName, 0, len(m))
	parts := 0
	for k := range m {
		result = append(result, k)
		parts += len(k.Schema) + len(k.Table) + len(k.Name)
	}
	slices.SortFunc(result, compareQualifiedName)
	if parts == 0 {
		return result
	}
	var b strings.Builder
	b.Grow(parts)
	for _, q := range result {
		b.WriteString(q.Schema)
		b.WriteString(q.Table)
		b.WriteString(q.Name)
	}
	arena, off := b.String(), 0
	next := func(s string) string {
		s, off = arena[off:off+len(s)], off+len(s)
		return s
	}
	for i := range result {
		q := &result[i]
		q.Schema, q.Table, q.Name = next(q.Schema), next(q.Table), next(q.Name)
	}
	return result
}

// detachStrings rewrites each element of ss to an equal string backed by one
// fresh allocation holding all of them, so none aliases the parsed SQL.
func detachStrings(ss []string) {
	n := 0
	for _, s := range ss {
		n += len(s)
	}
	if n == 0 {
		return
	}
	var b strings.Builder
	b.Grow(n)
	for _, s := range ss {
		b.WriteString(s)
	}
	arena, off := b.String(), 0
	for i, s := range ss {
		ss[i], off = arena[off:off+len(s)], off+len(s)
	}
}

// ExtractMetadata extracts comprehensive metadata from an AST in a single call.
//
// This is a convenience function that calls all extraction functions (ExtractTables,
// ExtractTablesQualified, ExtractColumns, ExtractColumnsQualified, ExtractFunctions)
// and returns the results in a structured Metadata object.
//
// Performance: This function performs a single AST traversal that gathers every
// metadata kind at once. Calling the individual extraction functions is only
// useful when you need fewer outputs.
//
// Thread Safety: This function is thread-safe and can be called concurrently on
// different AST instances.
//
// Use Cases:
//   - Query analysis: Understanding what resources a query uses
//   - Security scanning: Identifying accessed tables and columns
//   - Query optimization: Analyzing function usage and access patterns
//   - Documentation: Generating query metadata for documentation
//   - Testing: Validating query structure in tests
//
// Example - Basic metadata extraction:
//
//	sql := "SELECT COUNT(*), u.name FROM users u WHERE u.active = true"
//	ast, _ := gosqlx.Parse(sql)
//	metadata := gosqlx.ExtractMetadata(ast)
//	fmt.Printf("Tables: %v, Columns: %v, Functions: %v\n",
//	    metadata.Tables, metadata.Columns, metadata.Functions)
//	// Output: Tables: [users], Columns: [active name], Functions: [COUNT]
//
// Example - Query dependency analysis:
//
//	sql := `SELECT u.name, COUNT(o.id) as order_count
//	    FROM users u
//	    LEFT JOIN orders o ON u.id = o.user_id
//	    GROUP BY u.name`
//	ast, _ := gosqlx.Parse(sql)
//	metadata := gosqlx.ExtractMetadata(ast)
//	fmt.Printf("Query depends on tables: %v\n", metadata.Tables)
//	// Output: Query depends on tables: [orders users]
//
// Example - Security analysis:
//
//	sql := "SELECT password, ssn FROM users WHERE admin = true"
//	ast, _ := gosqlx.Parse(sql)
//	metadata := gosqlx.ExtractMetadata(ast)
//
//	sensitiveColumns := []string{"password", "ssn", "credit_card"}
//	for _, col := range metadata.Columns {
//	    for _, sensitive := range sensitiveColumns {
//	        if col == sensitive {
//	            fmt.Printf("WARNING: Query accesses sensitive column: %s\n", col)
//	        }
//	    }
//	}
//
// Example - PostgreSQL v1.6.0 features:
//
//	sql := `SELECT data->>'name' as name,
//	    COUNT(*) FILTER (WHERE status = 'active')
//	    FROM users u
//	    LATERAL JOIN orders o ON o.user_id = u.id`
//	ast, _ := gosqlx.Parse(sql)
//	metadata := gosqlx.ExtractMetadata(ast)
//	// Captures JSON operators, FILTER clause, LATERAL joins
//
// See also: Individual extraction functions for targeted metadata retrieval.
func ExtractMetadata(astNode *ast.AST) *Metadata {
	if astNode == nil {
		return &Metadata{}
	}

	c := &metadataCollector{
		want:             extractAll,
		tables:           make(map[string]struct{}),
		tablesQualified:  make(map[QualifiedName]struct{}),
		columns:          make(map[string]struct{}),
		columnsQualified: make(map[QualifiedName]struct{}),
		functions:        make(map[string]struct{}),
	}
	c.collect(astNode)

	return &Metadata{
		Tables:           stringSetToSlice(c.tables),
		TablesQualified:  qualifiedSetToSlice(c.tablesQualified),
		Columns:          stringSetToSlice(c.columns),
		ColumnsQualified: qualifiedSetToSlice(c.columnsQualified),
		Functions:        stringSetToSlice(c.functions),
	}
}

// Metadata contains comprehensive metadata extracted from a SQL query's AST.
//
// This type aggregates all extractable metadata from a SQL query, including tables,
// columns, and function calls. It provides both simple (unqualified) and qualified
// versions of identifiers for maximum flexibility in query analysis.
//
// All slices in Metadata are deduplicated - each identifier appears only once
// regardless of how many times it appears in the original query.
//
// Ordering: every slice is sorted, so repeated calls on the same AST return
// identical slices. String slices are in ascending byte order (as by
// slices.Sort, so upper case sorts before lower case). QualifiedName slices
// are ordered by Schema, then Table, then Name.
//
// Thread Safety: Metadata instances are safe to read concurrently but should not
// be modified after creation.
//
// Example - Analyzing query complexity:
//
//	metadata := gosqlx.ExtractMetadata(ast)
//	complexity := len(metadata.Tables) * len(metadata.Columns) * len(metadata.Functions)
//	fmt.Printf("Query complexity score: %d\n", complexity)
//
// Example - Validating query against schema:
//
//	metadata := gosqlx.ExtractMetadata(ast)
//	for _, table := range metadata.Tables {
//	    if !schema.TableExists(table) {
//	        return fmt.Errorf("table %s does not exist", table)
//	    }
//	}
//
// Example - Query impact analysis:
//
//	metadata := gosqlx.ExtractMetadata(ast)
//	fmt.Printf("Query Impact Analysis:\n")
//	fmt.Printf("  Tables accessed: %d (%v)\n", len(metadata.Tables), metadata.Tables)
//	fmt.Printf("  Columns referenced: %d (%v)\n", len(metadata.Columns), metadata.Columns)
//	fmt.Printf("  Functions used: %d (%v)\n", len(metadata.Functions), metadata.Functions)
type Metadata struct {
	// Tables contains simple (unqualified) table names extracted from the query.
	// Example: ["orders", "products", "users"]
	//
	// This includes tables from:
	//   - FROM clauses
	//   - JOIN clauses
	//   - INSERT/UPDATE/DELETE statements
	//   - Subqueries and CTEs
	Tables []string

	// TablesQualified contains fully qualified table names with schema information.
	// Example: [QualifiedName{Schema: "public", Name: "users"}]
	//
	// Use this when you need to preserve schema qualifiers from the original query.
	// For queries without schema qualifiers, Schema field will be empty.
	TablesQualified []QualifiedName

	// Columns contains simple (unqualified) column names extracted from the query.
	// Example: ["created_at", "email", "name"]
	//
	// This includes columns from:
	//   - SELECT lists
	//   - WHERE conditions
	//   - GROUP BY clauses
	//   - ORDER BY clauses
	//   - JOIN conditions
	//   - HAVING clauses
	Columns []string

	// ColumnsQualified contains qualified column names with table/alias information.
	// Example: [QualifiedName{Table: "u", Name: "name"}]
	//
	// Use this when you need to preserve table qualifiers (e.g., "u.name" vs "name").
	// For unqualified columns, Table field will be empty.
	ColumnsQualified []QualifiedName

	// Functions contains all function names used in the query.
	// Example: ["COUNT", "NOW", "SUM", "UPPER"]
	//
	// This includes:
	//   - Aggregate functions (COUNT, SUM, AVG, MIN, MAX)
	//   - Window functions (ROW_NUMBER, RANK, DENSE_RANK, LAG, LEAD)
	//   - Scalar functions (UPPER, LOWER, SUBSTRING, COALESCE)
	//   - Date/time functions (NOW, CURRENT_TIMESTAMP, DATE_TRUNC)
	//   - JSON functions (JSON_EXTRACT, JSONB_BUILD_OBJECT)
	//   - PostgreSQL aggregate functions with FILTER clause (v1.6.0)
	Functions []string
}

// String returns a human-readable representation of the metadata.
func (m *Metadata) String() string {
	return fmt.Sprintf("Tables: %v, Columns: %v, Functions: %v",
		m.Tables, m.Columns, m.Functions)
}
