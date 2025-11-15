// Package gosqlx provides convenient high-level functions for SQL parsing and extraction.
package gosqlx

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// QualifiedName represents a fully qualified table or column name.
// It can represent schema.table, table.column, or schema.table.column.
type QualifiedName struct {
	Schema string // Optional schema name
	Table  string // Table name (or middle qualifier)
	Name   string // Column or table name
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

// FullName returns the full name without schema.
func (q QualifiedName) FullName() string {
	if q.Table != "" && q.Name != "" {
		return q.Table + "." + q.Name
	}
	if q.Name != "" {
		return q.Name
	}
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
// Returns a deduplicated slice of table names.
//
// Example:
//
//	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
//	ast, _ := gosqlx.Parse(sql)
//	tables := gosqlx.ExtractTables(ast)
//	// tables = ["users", "orders"]
func ExtractTables(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	collector := &tableCollector{
		tables: make(map[string]bool),
	}

	for _, stmt := range astNode.Statements {
		collector.collectFromNode(stmt)
	}

	return collector.toSlice()
}

// ExtractTablesQualified extracts all table names with their qualifiers (schema.table).
//
// This function is similar to ExtractTables but preserves schema information
// when present in the original query.
//
// Returns a deduplicated slice of QualifiedName objects.
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

	collector := &qualifiedTableCollector{
		tables: make(map[string]QualifiedName),
	}

	for _, stmt := range astNode.Statements {
		collector.collectFromNode(stmt)
	}

	return collector.toSlice()
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
// Returns a deduplicated slice of column names (without table qualifiers).
//
// Example:
//
//	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true ORDER BY u.created_at"
//	ast, _ := gosqlx.Parse(sql)
//	columns := gosqlx.ExtractColumns(ast)
//	// columns = ["name", "email", "active", "created_at"]
func ExtractColumns(astNode *ast.AST) []string {
	if astNode == nil {
		return nil
	}

	collector := &columnCollector{
		columns: make(map[string]bool),
	}

	for _, stmt := range astNode.Statements {
		collector.collectFromNode(stmt)
	}

	return collector.toSlice()
}

// ExtractFunctions extracts all function calls from an AST.
//
// This function traverses the AST and collects all function names, including:
//   - Aggregate functions (COUNT, SUM, AVG, etc.)
//   - Window functions (ROW_NUMBER, RANK, etc.)
//   - Scalar functions (UPPER, LOWER, NOW, etc.)
//
// Returns a deduplicated slice of function names.
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

	collector := &functionCollector{
		functions: make(map[string]bool),
	}

	for _, stmt := range astNode.Statements {
		collector.collectFromNode(stmt)
	}

	return collector.toSlice()
}

// tableCollector collects table names from AST nodes
type tableCollector struct {
	tables map[string]bool
}

func (tc *tableCollector) collectFromNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.SelectStatement:
		for _, from := range n.From {
			if from.Name != "" {
				tc.tables[from.Name] = true
			}
		}
		for _, join := range n.Joins {
			if join.Right.Name != "" {
				tc.tables[join.Right.Name] = true
			}
		}
		if n.With != nil {
			tc.collectFromNode(n.With)
		}
	case *ast.InsertStatement:
		if n.TableName != "" {
			tc.tables[n.TableName] = true
		}
		if n.Query != nil {
			tc.collectFromNode(n.Query)
		}
		if n.With != nil {
			tc.collectFromNode(n.With)
		}
	case *ast.UpdateStatement:
		if n.TableName != "" {
			tc.tables[n.TableName] = true
		}
		for _, from := range n.From {
			if from.Name != "" {
				tc.tables[from.Name] = true
			}
		}
		if n.With != nil {
			tc.collectFromNode(n.With)
		}
	case *ast.DeleteStatement:
		if n.TableName != "" {
			tc.tables[n.TableName] = true
		}
		for _, using := range n.Using {
			if using.Name != "" {
				tc.tables[using.Name] = true
			}
		}
		if n.With != nil {
			tc.collectFromNode(n.With)
		}
	case *ast.WithClause:
		for _, cte := range n.CTEs {
			tc.collectFromNode(cte)
		}
	case *ast.CommonTableExpr:
		tc.collectFromNode(n.Statement)
	case *ast.SetOperation:
		tc.collectFromNode(n.Left)
		tc.collectFromNode(n.Right)
	}

	// Recursively collect from children
	for _, child := range node.Children() {
		tc.collectFromNode(child)
	}
}

func (tc *tableCollector) toSlice() []string {
	result := make([]string, 0, len(tc.tables))
	for table := range tc.tables {
		result = append(result, table)
	}
	return result
}

// qualifiedTableCollector collects qualified table names
type qualifiedTableCollector struct {
	tables map[string]QualifiedName
}

func (qtc *qualifiedTableCollector) collectFromNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.SelectStatement:
		for _, from := range n.From {
			if from.Name != "" {
				qtc.addTable(from.Name)
			}
		}
		for _, join := range n.Joins {
			if join.Right.Name != "" {
				qtc.addTable(join.Right.Name)
			}
		}
		if n.With != nil {
			qtc.collectFromNode(n.With)
		}
	case *ast.InsertStatement:
		if n.TableName != "" {
			qtc.addTable(n.TableName)
		}
		if n.Query != nil {
			qtc.collectFromNode(n.Query)
		}
		if n.With != nil {
			qtc.collectFromNode(n.With)
		}
	case *ast.UpdateStatement:
		if n.TableName != "" {
			qtc.addTable(n.TableName)
		}
		for _, from := range n.From {
			if from.Name != "" {
				qtc.addTable(from.Name)
			}
		}
		if n.With != nil {
			qtc.collectFromNode(n.With)
		}
	case *ast.DeleteStatement:
		if n.TableName != "" {
			qtc.addTable(n.TableName)
		}
		for _, using := range n.Using {
			if using.Name != "" {
				qtc.addTable(using.Name)
			}
		}
		if n.With != nil {
			qtc.collectFromNode(n.With)
		}
	case *ast.WithClause:
		for _, cte := range n.CTEs {
			qtc.collectFromNode(cte)
		}
	case *ast.CommonTableExpr:
		qtc.collectFromNode(n.Statement)
	case *ast.SetOperation:
		qtc.collectFromNode(n.Left)
		qtc.collectFromNode(n.Right)
	}

	// Recursively collect from children
	for _, child := range node.Children() {
		qtc.collectFromNode(child)
	}
}

func (qtc *qualifiedTableCollector) addTable(name string) {
	// Parse the table name to extract schema if present
	parts := strings.Split(name, ".")
	var qn QualifiedName

	switch len(parts) {
	case 1:
		qn = QualifiedName{Name: parts[0]}
	case 2:
		qn = QualifiedName{Schema: parts[0], Name: parts[1]}
	case 3:
		qn = QualifiedName{Schema: parts[0], Table: parts[1], Name: parts[2]}
	default:
		qn = QualifiedName{Name: name}
	}

	qtc.tables[qn.String()] = qn
}

func (qtc *qualifiedTableCollector) toSlice() []QualifiedName {
	result := make([]QualifiedName, 0, len(qtc.tables))
	for _, table := range qtc.tables {
		result = append(result, table)
	}
	return result
}

// columnCollector collects column names from AST nodes
type columnCollector struct {
	columns map[string]bool
}

func (cc *columnCollector) collectFromNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.Identifier:
		if n.Name != "" && n.Name != "*" {
			cc.columns[n.Name] = true
		}
	case *ast.SelectStatement:
		for _, col := range n.Columns {
			cc.collectFromExpression(col)
		}
		if n.Where != nil {
			cc.collectFromExpression(n.Where)
		}
		for _, gb := range n.GroupBy {
			cc.collectFromExpression(gb)
		}
		if n.Having != nil {
			cc.collectFromExpression(n.Having)
		}
		for _, ob := range n.OrderBy {
			cc.collectFromExpression(ob)
		}
		if n.With != nil {
			cc.collectFromNode(n.With)
		}
	case *ast.InsertStatement:
		for _, col := range n.Columns {
			cc.collectFromExpression(col)
		}
		if n.Query != nil {
			cc.collectFromNode(n.Query)
		}
		if n.With != nil {
			cc.collectFromNode(n.With)
		}
	case *ast.UpdateStatement:
		for _, update := range n.Updates {
			cc.collectFromNode(&update)
		}
		for _, assignment := range n.Assignments {
			cc.collectFromNode(&assignment)
		}
		if n.Where != nil {
			cc.collectFromExpression(n.Where)
		}
		if n.With != nil {
			cc.collectFromNode(n.With)
		}
	case *ast.DeleteStatement:
		if n.Where != nil {
			cc.collectFromExpression(n.Where)
		}
		if n.With != nil {
			cc.collectFromNode(n.With)
		}
	case *ast.UpdateExpression:
		cc.collectFromExpression(n.Column)
		cc.collectFromExpression(n.Value)
	case *ast.WithClause:
		for _, cte := range n.CTEs {
			cc.collectFromNode(cte)
		}
	case *ast.CommonTableExpr:
		cc.collectFromNode(n.Statement)
	case *ast.SetOperation:
		cc.collectFromNode(n.Left)
		cc.collectFromNode(n.Right)
	}

	// Recursively collect from children
	for _, child := range node.Children() {
		cc.collectFromNode(child)
	}
}

func (cc *columnCollector) collectFromExpression(expr ast.Expression) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Name != "" && e.Name != "*" {
			cc.columns[e.Name] = true
		}
	case *ast.BinaryExpression:
		cc.collectFromExpression(e.Left)
		cc.collectFromExpression(e.Right)
	case *ast.FunctionCall:
		for _, arg := range e.Arguments {
			cc.collectFromExpression(arg)
		}
		if e.Filter != nil {
			cc.collectFromExpression(e.Filter)
		}
	case *ast.UnaryExpression:
		cc.collectFromExpression(e.Expr)
	case *ast.InExpression:
		cc.collectFromExpression(e.Expr)
		for _, item := range e.List {
			cc.collectFromExpression(item)
		}
	case *ast.BetweenExpression:
		cc.collectFromExpression(e.Expr)
		cc.collectFromExpression(e.Lower)
		cc.collectFromExpression(e.Upper)
	case *ast.CaseExpression:
		if e.Value != nil {
			cc.collectFromExpression(e.Value)
		}
		for _, when := range e.WhenClauses {
			cc.collectFromExpression(when.Condition)
			cc.collectFromExpression(when.Result)
		}
		if e.ElseClause != nil {
			cc.collectFromExpression(e.ElseClause)
		}
	case *ast.CastExpression:
		cc.collectFromExpression(e.Expr)
	case *ast.SubstringExpression:
		cc.collectFromExpression(e.Str)
		cc.collectFromExpression(e.Start)
		if e.Length != nil {
			cc.collectFromExpression(e.Length)
		}
	case *ast.ExtractExpression:
		cc.collectFromExpression(e.Source)
	case *ast.PositionExpression:
		cc.collectFromExpression(e.Substr)
		cc.collectFromExpression(e.Str)
	case *ast.ListExpression:
		for _, v := range e.Values {
			cc.collectFromExpression(v)
		}
	}
}

func (cc *columnCollector) toSlice() []string {
	result := make([]string, 0, len(cc.columns))
	for column := range cc.columns {
		result = append(result, column)
	}
	return result
}

// functionCollector collects function names from AST nodes
type functionCollector struct {
	functions map[string]bool
}

func (fc *functionCollector) collectFromNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.SelectStatement:
		for _, col := range n.Columns {
			fc.collectFromExpression(col)
		}
		if n.Where != nil {
			fc.collectFromExpression(n.Where)
		}
		for _, gb := range n.GroupBy {
			fc.collectFromExpression(gb)
		}
		if n.Having != nil {
			fc.collectFromExpression(n.Having)
		}
		for _, ob := range n.OrderBy {
			fc.collectFromExpression(ob)
		}
		if n.With != nil {
			fc.collectFromNode(n.With)
		}
	case *ast.InsertStatement:
		for _, val := range n.Values {
			fc.collectFromExpression(val)
		}
		if n.Query != nil {
			fc.collectFromNode(n.Query)
		}
		if n.With != nil {
			fc.collectFromNode(n.With)
		}
	case *ast.UpdateStatement:
		for _, update := range n.Updates {
			fc.collectFromNode(&update)
		}
		for _, assignment := range n.Assignments {
			fc.collectFromNode(&assignment)
		}
		if n.Where != nil {
			fc.collectFromExpression(n.Where)
		}
		if n.With != nil {
			fc.collectFromNode(n.With)
		}
	case *ast.DeleteStatement:
		if n.Where != nil {
			fc.collectFromExpression(n.Where)
		}
		if n.With != nil {
			fc.collectFromNode(n.With)
		}
	case *ast.UpdateExpression:
		fc.collectFromExpression(n.Value)
	case *ast.WithClause:
		for _, cte := range n.CTEs {
			fc.collectFromNode(cte)
		}
	case *ast.CommonTableExpr:
		fc.collectFromNode(n.Statement)
	case *ast.SetOperation:
		fc.collectFromNode(n.Left)
		fc.collectFromNode(n.Right)
	}

	// Recursively collect from children
	for _, child := range node.Children() {
		fc.collectFromNode(child)
	}
}

func (fc *functionCollector) collectFromExpression(expr ast.Expression) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.FunctionCall:
		if e.Name != "" {
			fc.functions[e.Name] = true
		}
		for _, arg := range e.Arguments {
			fc.collectFromExpression(arg)
		}
		if e.Filter != nil {
			fc.collectFromExpression(e.Filter)
		}
	case *ast.BinaryExpression:
		fc.collectFromExpression(e.Left)
		fc.collectFromExpression(e.Right)
	case *ast.UnaryExpression:
		fc.collectFromExpression(e.Expr)
	case *ast.InExpression:
		fc.collectFromExpression(e.Expr)
		for _, item := range e.List {
			fc.collectFromExpression(item)
		}
	case *ast.BetweenExpression:
		fc.collectFromExpression(e.Expr)
		fc.collectFromExpression(e.Lower)
		fc.collectFromExpression(e.Upper)
	case *ast.CaseExpression:
		if e.Value != nil {
			fc.collectFromExpression(e.Value)
		}
		for _, when := range e.WhenClauses {
			fc.collectFromExpression(when.Condition)
			fc.collectFromExpression(when.Result)
		}
		if e.ElseClause != nil {
			fc.collectFromExpression(e.ElseClause)
		}
	case *ast.CastExpression:
		fc.collectFromExpression(e.Expr)
	case *ast.SubstringExpression:
		fc.collectFromExpression(e.Str)
		fc.collectFromExpression(e.Start)
		if e.Length != nil {
			fc.collectFromExpression(e.Length)
		}
	case *ast.ExtractExpression:
		fc.collectFromExpression(e.Source)
	case *ast.PositionExpression:
		fc.collectFromExpression(e.Substr)
		fc.collectFromExpression(e.Str)
	case *ast.ListExpression:
		for _, v := range e.Values {
			fc.collectFromExpression(v)
		}
	}
}

func (fc *functionCollector) toSlice() []string {
	result := make([]string, 0, len(fc.functions))
	for function := range fc.functions {
		result = append(result, function)
	}
	return result
}

// ExtractMetadata extracts comprehensive metadata from an AST.
//
// This is a convenience function that calls all extraction functions
// and returns the results in a structured format.
//
// Example:
//
//	sql := "SELECT COUNT(*), u.name FROM users u WHERE u.active = true"
//	ast, _ := gosqlx.Parse(sql)
//	metadata := gosqlx.ExtractMetadata(ast)
//	fmt.Printf("Tables: %v, Columns: %v, Functions: %v\n",
//	    metadata.Tables, metadata.Columns, metadata.Functions)
func ExtractMetadata(astNode *ast.AST) *Metadata {
	return &Metadata{
		Tables:          ExtractTables(astNode),
		TablesQualified: ExtractTablesQualified(astNode),
		Columns:         ExtractColumns(astNode),
		Functions:       ExtractFunctions(astNode),
	}
}

// Metadata contains all extracted metadata from a SQL query.
type Metadata struct {
	Tables          []string        // Simple table names
	TablesQualified []QualifiedName // Qualified table names
	Columns         []string        // Column names
	Functions       []string        // Function names
}

// String returns a human-readable representation of the metadata.
func (m *Metadata) String() string {
	return fmt.Sprintf("Tables: %v, Columns: %v, Functions: %v",
		m.Tables, m.Columns, m.Functions)
}
