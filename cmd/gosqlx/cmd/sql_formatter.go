package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// SQLFormatter provides AST-based SQL formatting with configurable rules
type SQLFormatter struct {
	indent       string
	newlineLevel int
	compact      bool
	uppercaseKw  bool
	alignColumns bool
	builder      strings.Builder
}

// FormatterOptions configures the SQL formatter behavior
type FormatterOptions struct {
	Indent       string // "  " for 2 spaces, "\t" for tab, etc.
	Compact      bool   // Single-line formatting
	UppercaseKw  bool   // Uppercase SQL keywords
	AlignColumns bool   // Align column lists vertically
}

// NewSQLFormatter creates a new AST-based SQL formatter
func NewSQLFormatter(opts FormatterOptions) *SQLFormatter {
	indent := opts.Indent
	if indent == "" {
		indent = "  " // Default to 2 spaces
	}

	return &SQLFormatter{
		indent:       indent,
		compact:      opts.Compact,
		uppercaseKw:  opts.UppercaseKw,
		alignColumns: opts.AlignColumns,
	}
}

// Format formats an AST into properly indented SQL
func (f *SQLFormatter) Format(astObj *ast.AST) (string, error) {
	f.builder.Reset()
	f.newlineLevel = 0

	for i, stmt := range astObj.Statements {
		if i > 0 {
			if f.compact {
				f.builder.WriteString("; ")
			} else {
				f.builder.WriteString(";\n\n")
			}
		}

		if err := f.formatStatement(stmt); err != nil {
			return "", fmt.Errorf("failed to format statement: %w", err)
		}
	}

	return f.builder.String(), nil
}

// formatStatement formats individual SQL statements
func (f *SQLFormatter) formatStatement(stmt ast.Statement) error {
	switch s := stmt.(type) {
	case *ast.SelectStatement:
		return f.formatSelect(s)
	case *ast.InsertStatement:
		return f.formatInsert(s)
	case *ast.UpdateStatement:
		return f.formatUpdate(s)
	case *ast.DeleteStatement:
		return f.formatDelete(s)
	case *ast.CreateTableStatement:
		return f.formatCreateTable(s)
	case *ast.CreateIndexStatement:
		return f.formatCreateIndex(s)
	case *ast.AlterTableStatement:
		return f.formatAlterTable(s)
	case *ast.AlterStatement:
		return f.formatAlterStatement(s)
	case *ast.DropStatement:
		return f.formatDrop(s)
	case *ast.CreateViewStatement:
		return f.formatCreateView(s)
	case *ast.CreateMaterializedViewStatement:
		return f.formatCreateMaterializedView(s)
	case *ast.RefreshMaterializedViewStatement:
		return f.formatRefreshMaterializedView(s)
	case *ast.SetOperation:
		return f.formatSetOperation(s)
	case *ast.MergeStatement:
		return f.formatMergeStatement(s)
	default:
		return fmt.Errorf("unsupported statement type: %T", stmt)
	}
}

// formatSelect formats SELECT statements with proper indentation and alignment
func (f *SQLFormatter) formatSelect(stmt *ast.SelectStatement) error {
	// WITH clause
	if stmt.With != nil {
		if err := f.formatWithClause(stmt.With); err != nil {
			return err
		}
		f.writeNewline()
	}

	// SELECT keyword and columns
	f.writeKeyword("SELECT")
	if stmt.Distinct {
		f.builder.WriteString(" ")
		f.writeKeyword("DISTINCT")
	}

	if f.compact {
		f.builder.WriteString(" ")
		f.formatExpressionList(stmt.Columns, ", ")
	} else {
		f.writeNewline()
		f.increaseIndent()
		f.formatExpressionList(stmt.Columns, ",\n"+f.currentIndent())
		f.decreaseIndent()
	}

	// FROM clause
	if len(stmt.From) > 0 {
		f.writeNewline()
		f.writeKeyword("FROM")
		f.builder.WriteString(" ")
		f.formatTableReferences(stmt.From)
	}

	// JOINs
	for _, join := range stmt.Joins {
		join := join // G601: Create local copy to avoid memory aliasing
		f.writeNewline()
		if err := f.formatJoin(&join); err != nil {
			return err
		}
	}

	// WHERE clause
	if stmt.Where != nil {
		f.writeNewline()
		f.writeKeyword("WHERE")
		f.builder.WriteString(" ")
		if err := f.formatExpression(stmt.Where); err != nil {
			return err
		}
	}

	// GROUP BY clause
	if len(stmt.GroupBy) > 0 {
		f.writeNewline()
		f.writeKeyword("GROUP BY")
		f.builder.WriteString(" ")
		f.formatExpressionList(stmt.GroupBy, ", ")
	}

	// HAVING clause
	if stmt.Having != nil {
		f.writeNewline()
		f.writeKeyword("HAVING")
		f.builder.WriteString(" ")
		if err := f.formatExpression(stmt.Having); err != nil {
			return err
		}
	}

	// ORDER BY clause
	if len(stmt.OrderBy) > 0 {
		f.writeNewline()
		f.writeKeyword("ORDER BY")
		f.builder.WriteString(" ")
		for i, orderBy := range stmt.OrderBy {
			if i > 0 {
				f.builder.WriteString(", ")
			}
			if orderBy.Expression != nil {
				if err := f.formatExpression(orderBy.Expression); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to format ORDER BY expression: %v\n", err)
				}
			}
			// Add ASC/DESC
			if !orderBy.Ascending {
				f.builder.WriteString(" DESC")
			}
			// Add NULLS FIRST/LAST if specified
			if orderBy.NullsFirst != nil {
				if *orderBy.NullsFirst {
					f.builder.WriteString(" NULLS FIRST")
				} else {
					f.builder.WriteString(" NULLS LAST")
				}
			}
		}
	}

	// LIMIT clause
	if stmt.Limit != nil {
		f.writeNewline()
		f.writeKeyword("LIMIT")
		f.builder.WriteString(fmt.Sprintf(" %d", *stmt.Limit))
	}

	// OFFSET clause
	if stmt.Offset != nil {
		f.writeNewline()
		f.writeKeyword("OFFSET")
		f.builder.WriteString(fmt.Sprintf(" %d", *stmt.Offset))
	}

	return nil
}

// formatSetOperation formats UNION, EXCEPT, INTERSECT statements
func (f *SQLFormatter) formatSetOperation(stmt *ast.SetOperation) error {
	// Format left statement
	if err := f.formatStatement(stmt.Left); err != nil {
		return fmt.Errorf("failed to format left side of %s: %w", stmt.Operator, err)
	}

	// Add newline and operator
	f.writeNewline()
	f.writeKeyword(stmt.Operator)
	if stmt.All {
		f.builder.WriteString(" ")
		f.writeKeyword("ALL")
	}
	f.writeNewline()

	// Format right statement
	if err := f.formatStatement(stmt.Right); err != nil {
		return fmt.Errorf("failed to format right side of %s: %w", stmt.Operator, err)
	}

	return nil
}

// formatInsert formats INSERT statements
func (f *SQLFormatter) formatInsert(stmt *ast.InsertStatement) error {
	f.writeKeyword("INSERT INTO")
	f.builder.WriteString(" " + stmt.TableName)

	if len(stmt.Columns) > 0 {
		f.builder.WriteString(" (")
		f.formatExpressionList(stmt.Columns, ", ")
		f.builder.WriteString(")")
	}

	if len(stmt.Values) > 0 {
		f.writeNewline()
		f.writeKeyword("VALUES")
		for i, row := range stmt.Values {
			if i > 0 {
				f.builder.WriteString(",")
			}
			f.builder.WriteString(" (")
			f.formatExpressionList(row, ", ")
			f.builder.WriteString(")")
		}
	}

	if stmt.Query != nil {
		f.writeNewline()
		if sel, ok := stmt.Query.(*ast.SelectStatement); ok {
			return f.formatSelect(sel)
		}
		// For SetOperation or other statement types, use Format if available
		if fmtable, ok := stmt.Query.(interface {
			Format(ast.FormatOptions) string
		}); ok {
			f.builder.WriteString(fmtable.Format(ast.FormatOptions{}))
		}
	}

	return nil
}

// formatUpdate formats UPDATE statements
func (f *SQLFormatter) formatUpdate(stmt *ast.UpdateStatement) error {
	f.writeKeyword("UPDATE")
	f.builder.WriteString(" " + stmt.TableName)

	if stmt.Alias != "" {
		f.builder.WriteString(" " + stmt.Alias)
	}

	if len(stmt.Assignments) > 0 {
		f.writeNewline()
		f.writeKeyword("SET")
		f.builder.WriteString(" ")

		for i, update := range stmt.Assignments {
			update := update // G601: Create local copy to avoid memory aliasing
			if i > 0 {
				f.builder.WriteString(", ")
			}
			if err := f.formatUpdateExpression(&update); err != nil {
				return err
			}
		}
	}

	if stmt.Where != nil {
		f.writeNewline()
		f.writeKeyword("WHERE")
		f.builder.WriteString(" ")
		if err := f.formatExpression(stmt.Where); err != nil {
			return err
		}
	}

	return nil
}

// formatDelete formats DELETE statements
func (f *SQLFormatter) formatDelete(stmt *ast.DeleteStatement) error {
	f.writeKeyword("DELETE FROM")
	f.builder.WriteString(" " + stmt.TableName)

	if stmt.Alias != "" {
		f.builder.WriteString(" " + stmt.Alias)
	}

	if stmt.Where != nil {
		f.writeNewline()
		f.writeKeyword("WHERE")
		f.builder.WriteString(" ")
		if err := f.formatExpression(stmt.Where); err != nil {
			return err
		}
	}

	return nil
}

// formatCreateTable formats CREATE TABLE statements
func (f *SQLFormatter) formatCreateTable(stmt *ast.CreateTableStatement) error {
	f.writeKeyword("CREATE")
	if stmt.Temporary {
		f.builder.WriteString(" ")
		f.writeKeyword("TEMPORARY")
	}
	f.builder.WriteString(" ")
	f.writeKeyword("TABLE")

	if stmt.IfNotExists {
		f.builder.WriteString(" ")
		f.writeKeyword("IF NOT EXISTS")
	}

	f.builder.WriteString(" " + stmt.Name + " (")

	if !f.compact {
		f.writeNewline()
		f.increaseIndent()
	}

	for i, col := range stmt.Columns {
		col := col // G601: Create local copy to avoid memory aliasing
		if i > 0 {
			f.builder.WriteString(",")
			if !f.compact {
				f.writeNewline()
			} else {
				f.builder.WriteString(" ")
			}
		}
		if !f.compact {
			f.builder.WriteString(f.currentIndent())
		}
		f.formatColumnDef(&col)
	}

	if !f.compact {
		f.decreaseIndent()
		f.writeNewline()
	}
	f.builder.WriteString(")")

	return nil
}

// formatCreateIndex formats CREATE INDEX statements
func (f *SQLFormatter) formatCreateIndex(stmt *ast.CreateIndexStatement) error {
	f.writeKeyword("CREATE")
	if stmt.Unique {
		f.builder.WriteString(" ")
		f.writeKeyword("UNIQUE")
	}
	f.builder.WriteString(" ")
	f.writeKeyword("INDEX")

	if stmt.IfNotExists {
		f.builder.WriteString(" ")
		f.writeKeyword("IF NOT EXISTS")
	}

	f.builder.WriteString(" " + stmt.Name)
	f.builder.WriteString(" ")
	f.writeKeyword("ON")
	f.builder.WriteString(" " + stmt.Table + " (")

	for i, col := range stmt.Columns {
		if i > 0 {
			f.builder.WriteString(", ")
		}
		f.builder.WriteString(col.Column)
		if col.Direction != "" {
			f.builder.WriteString(" " + col.Direction)
		}
	}
	f.builder.WriteString(")")

	return nil
}

// formatAlterTable formats ALTER TABLE statements
func (f *SQLFormatter) formatAlterTable(stmt *ast.AlterTableStatement) error {
	f.writeKeyword("ALTER TABLE")
	f.builder.WriteString(" " + stmt.Table)

	for i, action := range stmt.Actions {
		action := action // G601: Create local copy to avoid memory aliasing
		if i > 0 {
			f.builder.WriteString(",")
		}
		f.writeNewline()
		f.increaseIndent()
		f.builder.WriteString(f.currentIndent())
		f.formatAlterTableAction(&action)
		f.decreaseIndent()
	}

	return nil
}

// formatAlterStatement formats the generic ALTER statement (from alter.go)
func (f *SQLFormatter) formatAlterStatement(stmt *ast.AlterStatement) error {
	// Format ALTER TABLE if it's a table alteration
	if stmt.Type == ast.AlterTypeTable {
		f.writeKeyword("ALTER TABLE")
		f.builder.WriteString(" " + stmt.Name)

		// Format the operation if present
		if stmt.Operation != nil {
			if op, ok := stmt.Operation.(*ast.AlterTableOperation); ok {
				f.writeNewline()
				f.increaseIndent()
				f.builder.WriteString(f.currentIndent())
				f.formatAlterTableOperation(op)
				f.decreaseIndent()
			}
		}
		return nil
	}

	// For other ALTER types, provide a basic format
	f.writeKeyword("ALTER")
	switch stmt.Type {
	case ast.AlterTypeRole:
		f.builder.WriteString(" ")
		f.writeKeyword("ROLE")
	case ast.AlterTypePolicy:
		f.builder.WriteString(" ")
		f.writeKeyword("POLICY")
	case ast.AlterTypeConnector:
		f.builder.WriteString(" ")
		f.writeKeyword("CONNECTOR")
	}
	f.builder.WriteString(" " + stmt.Name)

	return nil
}

// formatAlterTableOperation formats a single ALTER TABLE operation
func (f *SQLFormatter) formatAlterTableOperation(op *ast.AlterTableOperation) {
	switch op.Type {
	case ast.AddColumn:
		f.writeKeyword("ADD")
		if op.ColumnKeyword {
			f.builder.WriteString(" ")
			f.writeKeyword("COLUMN")
		}
		if op.ColumnDef != nil {
			f.builder.WriteString(" " + op.ColumnDef.Name)
			if op.ColumnDef.Type != "" {
				f.builder.WriteString(" " + op.ColumnDef.Type)
			}
		}
	case ast.DropColumn:
		f.writeKeyword("DROP")
		if op.ColumnKeyword {
			f.builder.WriteString(" ")
			f.writeKeyword("COLUMN")
		}
		if op.ColumnDef != nil {
			f.builder.WriteString(" " + op.ColumnDef.Name)
		}
	case ast.AddConstraint:
		f.writeKeyword("ADD CONSTRAINT")
		if op.Constraint != nil && op.Constraint.Name != "" {
			f.builder.WriteString(" " + op.Constraint.Name)
		}
	case ast.DropConstraint:
		f.writeKeyword("DROP CONSTRAINT")
		if op.ConstraintName != nil {
			f.builder.WriteString(" " + op.ConstraintName.String())
		}
	case ast.RenameColumn:
		f.writeKeyword("RENAME COLUMN")
		if op.OldColumnName != nil {
			f.builder.WriteString(" " + op.OldColumnName.String())
		}
		f.builder.WriteString(" ")
		f.writeKeyword("TO")
		if op.NewColumnName != nil {
			f.builder.WriteString(" " + op.NewColumnName.String())
		}
	default:
		// Fallback for unsupported operations
		f.builder.WriteString("...")
	}
}

// formatWithClause formats WITH (CTE) clauses
func (f *SQLFormatter) formatWithClause(with *ast.WithClause) error {
	f.writeKeyword("WITH")
	if with.Recursive {
		f.builder.WriteString(" ")
		f.writeKeyword("RECURSIVE")
	}
	f.builder.WriteString(" ")

	for i, cte := range with.CTEs {
		if i > 0 {
			f.builder.WriteString(", ")
		}
		f.builder.WriteString(cte.Name)

		if len(cte.Columns) > 0 {
			f.builder.WriteString(" (")
			for j, col := range cte.Columns {
				if j > 0 {
					f.builder.WriteString(", ")
				}
				f.builder.WriteString(col)
			}
			f.builder.WriteString(")")
		}

		f.builder.WriteString(" ")
		f.writeKeyword("AS")
		f.builder.WriteString(" (")

		if !f.compact {
			f.writeNewline()
			f.increaseIndent()
		}

		if err := f.formatStatement(cte.Statement); err != nil {
			return err
		}

		if !f.compact {
			f.decreaseIndent()
			f.writeNewline()
		}
		f.builder.WriteString(")")
	}

	return nil
}

// formatJoin formats JOIN clauses
func (f *SQLFormatter) formatJoin(join *ast.JoinClause) error {
	if join.Type != "" {
		f.writeKeyword(join.Type)
		f.builder.WriteString(" ")
	}
	f.writeKeyword("JOIN")
	f.builder.WriteString(" ")
	f.formatTableReference(&join.Right)

	if join.Condition != nil {
		f.builder.WriteString(" ")
		f.writeKeyword("ON")
		f.builder.WriteString(" ")
		if err := f.formatExpression(join.Condition); err != nil {
			return err
		}
	}

	return nil
}

// formatExpression formats SQL expressions
func (f *SQLFormatter) formatExpression(expr ast.Expression) error {
	switch e := expr.(type) {
	case *ast.Identifier:
		if e.Table != "" {
			f.builder.WriteString(e.Table + ".")
		}
		f.builder.WriteString(e.Name)
	case *ast.LiteralValue:
		// Handle string literals with proper quoting
		switch e.Type {
		case "string", "STRING":
			// Escape single quotes in the string value and wrap in quotes
			// Use type assertion for efficiency instead of fmt.Sprintf
			var strVal string
			if str, ok := e.Value.(string); ok {
				strVal = str
			} else {
				strVal = fmt.Sprintf("%v", e.Value)
			}
			escaped := strings.ReplaceAll(strVal, "'", "''")
			f.builder.WriteString("'")
			f.builder.WriteString(escaped)
			f.builder.WriteString("'")
		case "null", "NULL":
			f.writeKeyword("NULL")
		default:
			// For non-string types, use type assertions for common types
			switch v := e.Value.(type) {
			case string:
				f.builder.WriteString(v)
			case int:
				f.builder.WriteString(strconv.Itoa(v))
			case int64:
				f.builder.WriteString(strconv.FormatInt(v, 10))
			case float64:
				f.builder.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			case bool:
				if v {
					f.writeKeyword("TRUE")
				} else {
					f.writeKeyword("FALSE")
				}
			default:
				f.builder.WriteString(fmt.Sprintf("%v", e.Value))
			}
		}
	case *ast.BinaryExpression:
		// Handle IS NULL / IS NOT NULL specially
		if e.Operator == "IS NULL" {
			if err := f.formatExpression(e.Left); err != nil {
				return err
			}
			if e.Not {
				f.builder.WriteString(" IS NOT NULL")
			} else {
				f.builder.WriteString(" IS NULL")
			}
			return nil
		}
		// Handle LIKE operator
		if e.Operator == "LIKE" {
			if err := f.formatExpression(e.Left); err != nil {
				return err
			}
			if e.Not {
				f.builder.WriteString(" NOT LIKE ")
			} else {
				f.builder.WriteString(" LIKE ")
			}
			if err := f.formatExpression(e.Right); err != nil {
				return err
			}
			return nil
		}
		// Standard binary expression
		if err := f.formatExpression(e.Left); err != nil {
			return err
		}
		f.builder.WriteString(" " + e.Operator + " ")
		if err := f.formatExpression(e.Right); err != nil {
			return err
		}
	case *ast.FunctionCall:
		f.builder.WriteString(e.Name + "(")
		if e.Distinct {
			f.writeKeyword("DISTINCT")
			f.builder.WriteString(" ")
		}
		f.formatExpressionList(e.Arguments, ", ")

		// ORDER BY inside aggregate functions (STRING_AGG, ARRAY_AGG, etc.)
		if len(e.OrderBy) > 0 {
			f.builder.WriteString(" ")
			f.writeKeyword("ORDER BY")
			f.builder.WriteString(" ")
			for i, orderBy := range e.OrderBy {
				if i > 0 {
					f.builder.WriteString(", ")
				}
				if err := f.formatExpression(orderBy.Expression); err != nil {
					return err
				}
				if !orderBy.Ascending {
					f.builder.WriteString(" ")
					f.writeKeyword("DESC")
				}
				if orderBy.NullsFirst != nil {
					f.builder.WriteString(" ")
					f.writeKeyword("NULLS")
					f.builder.WriteString(" ")
					if *orderBy.NullsFirst {
						f.writeKeyword("FIRST")
					} else {
						f.writeKeyword("LAST")
					}
				}
			}
		}

		f.builder.WriteString(")")

		// Filter clause (SQL:2003 T612)
		if e.Filter != nil {
			f.builder.WriteString(" ")
			f.writeKeyword("FILTER")
			f.builder.WriteString(" (")
			f.writeKeyword("WHERE")
			f.builder.WriteString(" ")
			if err := f.formatExpression(e.Filter); err != nil {
				return err
			}
			f.builder.WriteString(")")
		}

		// Window function (OVER clause)
		if e.Over != nil {
			f.builder.WriteString(" ")
			f.writeKeyword("OVER")
			f.builder.WriteString(" (")
			if err := f.formatWindowSpec(e.Over); err != nil {
				return err
			}
			f.builder.WriteString(")")
		}
	case *ast.CaseExpression:
		f.writeKeyword("CASE")
		if e.Value != nil {
			f.builder.WriteString(" ")
			if err := f.formatExpression(e.Value); err != nil {
				return err
			}
		}

		for _, when := range e.WhenClauses {
			f.builder.WriteString(" ")
			f.writeKeyword("WHEN")
			f.builder.WriteString(" ")
			if err := f.formatExpression(when.Condition); err != nil {
				return err
			}
			f.builder.WriteString(" ")
			f.writeKeyword("THEN")
			f.builder.WriteString(" ")
			if err := f.formatExpression(when.Result); err != nil {
				return err
			}
		}

		if e.ElseClause != nil {
			f.builder.WriteString(" ")
			f.writeKeyword("ELSE")
			f.builder.WriteString(" ")
			if err := f.formatExpression(e.ElseClause); err != nil {
				return err
			}
		}
		f.builder.WriteString(" ")
		f.writeKeyword("END")
	case *ast.BetweenExpression:
		// Handle BETWEEN expr AND expr
		if err := f.formatExpression(e.Expr); err != nil {
			return err
		}
		if e.Not {
			f.builder.WriteString(" ")
			f.writeKeyword("NOT BETWEEN")
		} else {
			f.builder.WriteString(" ")
			f.writeKeyword("BETWEEN")
		}
		f.builder.WriteString(" ")
		if err := f.formatExpression(e.Lower); err != nil {
			return err
		}
		f.builder.WriteString(" ")
		f.writeKeyword("AND")
		f.builder.WriteString(" ")
		if err := f.formatExpression(e.Upper); err != nil {
			return err
		}
	case *ast.InExpression:
		// Handle IN (values) or IN (subquery)
		if err := f.formatExpression(e.Expr); err != nil {
			return err
		}
		if e.Not {
			f.builder.WriteString(" ")
			f.writeKeyword("NOT IN")
		} else {
			f.builder.WriteString(" ")
			f.writeKeyword("IN")
		}
		f.builder.WriteString(" (")
		if e.Subquery != nil {
			// IN (SELECT ...)
			if selectStmt, ok := e.Subquery.(*ast.SelectStatement); ok {
				if err := f.formatSelect(selectStmt); err != nil {
					return err
				}
			}
		} else {
			// IN (value1, value2, ...)
			f.formatExpressionList(e.List, ", ")
		}
		f.builder.WriteString(")")
	case *ast.ExistsExpression:
		// Handle EXISTS (subquery) - NOT EXISTS is handled via UnaryExpression
		f.writeKeyword("EXISTS")
		f.builder.WriteString(" (")
		if selectStmt, ok := e.Subquery.(*ast.SelectStatement); ok {
			if err := f.formatSelect(selectStmt); err != nil {
				return err
			}
		}
		f.builder.WriteString(")")
	case *ast.SubqueryExpression:
		// Handle scalar subquery (SELECT ...)
		f.builder.WriteString("(")
		if selectStmt, ok := e.Subquery.(*ast.SelectStatement); ok {
			if err := f.formatSelect(selectStmt); err != nil {
				return err
			}
		}
		f.builder.WriteString(")")
	case *ast.UnaryExpression:
		// Handle NOT expr, - expr, etc.
		f.builder.WriteString(e.Operator.String())
		f.builder.WriteString(" ")
		if err := f.formatExpression(e.Expr); err != nil {
			return err
		}
	case *ast.AliasedExpression:
		// Handle expr AS alias
		if err := f.formatExpression(e.Expr); err != nil {
			return err
		}
		f.builder.WriteString(" ")
		f.writeKeyword("AS")
		f.builder.WriteString(" ")
		// Quote alias if it contains special characters or is a reserved keyword
		f.formatIdentifier(e.Alias)
	default:
		// Fallback for unsupported expressions
		f.builder.WriteString(expr.TokenLiteral())
	}

	return nil
}

// formatWindowSpec formats window specifications for window functions
func (f *SQLFormatter) formatWindowSpec(spec *ast.WindowSpec) error {
	if len(spec.PartitionBy) > 0 {
		f.writeKeyword("PARTITION BY")
		f.builder.WriteString(" ")
		f.formatExpressionList(spec.PartitionBy, ", ")
	}

	if len(spec.OrderBy) > 0 {
		if len(spec.PartitionBy) > 0 {
			f.builder.WriteString(" ")
		}
		f.writeKeyword("ORDER BY")
		f.builder.WriteString(" ")
		for i, orderBy := range spec.OrderBy {
			if i > 0 {
				f.builder.WriteString(", ")
			}
			if orderBy.Expression != nil {
				if err := f.formatExpression(orderBy.Expression); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: failed to format window ORDER BY expression: %v\n", err)
				}
			}
			if !orderBy.Ascending {
				f.builder.WriteString(" DESC")
			}
			if orderBy.NullsFirst != nil {
				if *orderBy.NullsFirst {
					f.builder.WriteString(" NULLS FIRST")
				} else {
					f.builder.WriteString(" NULLS LAST")
				}
			}
		}
	}

	if spec.FrameClause != nil {
		if len(spec.PartitionBy) > 0 || len(spec.OrderBy) > 0 {
			f.builder.WriteString(" ")
		}
		f.writeKeyword(spec.FrameClause.Type)
		f.builder.WriteString(" ")
		f.writeKeyword("BETWEEN")
		f.builder.WriteString(" ")
		f.builder.WriteString(spec.FrameClause.Start.Type)
		if spec.FrameClause.End != nil {
			f.builder.WriteString(" ")
			f.writeKeyword("AND")
			f.builder.WriteString(" " + spec.FrameClause.End.Type)
		}
	}

	return nil
}

// Helper methods for formatting
func (f *SQLFormatter) formatExpressionList(exprs []ast.Expression, separator string) {
	for i, expr := range exprs {
		if i > 0 {
			f.builder.WriteString(separator)
		}
		if err := f.formatExpression(expr); err != nil {
			// Log error but continue formatting to avoid breaking output
			fmt.Fprintf(os.Stderr, "Warning: failed to format expression: %v\n", err)
		}
	}
}

func (f *SQLFormatter) formatTableReferences(tables []ast.TableReference) {
	for i, table := range tables {
		table := table // G601: Create local copy to avoid memory aliasing
		if i > 0 {
			f.builder.WriteString(", ")
		}
		f.formatTableReference(&table)
	}
}

func (f *SQLFormatter) formatTableReference(table *ast.TableReference) {
	// Output LATERAL keyword if set
	if table.Lateral {
		f.writeKeyword("LATERAL")
		f.builder.WriteString(" ")
	}

	if table.Subquery != nil {
		// Format derived table (subquery)
		f.builder.WriteString("(")
		if err := f.formatSelect(table.Subquery); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to format derived table: %v\n", err)
		}
		f.builder.WriteString(")")
	} else {
		// Format regular table name
		f.builder.WriteString(table.Name)
	}
	if table.Alias != "" {
		f.builder.WriteString(" ")
		f.writeKeyword("AS")
		f.builder.WriteString(" " + table.Alias)
	}
}

func (f *SQLFormatter) formatUpdateExpression(update *ast.UpdateExpression) error {
	if err := f.formatExpression(update.Column); err != nil {
		return err
	}
	f.builder.WriteString(" = ")
	return f.formatExpression(update.Value)
}

func (f *SQLFormatter) formatColumnDef(col *ast.ColumnDef) {
	f.builder.WriteString(col.Name + " " + col.Type)
	for _, constraint := range col.Constraints {
		f.builder.WriteString(" ")
		f.writeKeyword(constraint.Type)
		// Format DEFAULT value if present
		if constraint.Type == "DEFAULT" && constraint.Default != nil {
			f.builder.WriteString(" ")
			if err := f.formatExpression(constraint.Default); err != nil {
				// Fallback to token literal on error
				f.builder.WriteString(constraint.Default.TokenLiteral())
			}
		}
		// Format CHECK expression if present
		if constraint.Type == "CHECK" && constraint.Check != nil {
			f.builder.WriteString(" (")
			if err := f.formatExpression(constraint.Check); err != nil {
				f.builder.WriteString(constraint.Check.TokenLiteral())
			}
			f.builder.WriteString(")")
		}
		// Format REFERENCES if present
		if constraint.Type == "REFERENCES" && constraint.References != nil {
			f.builder.WriteString(" ")
			f.builder.WriteString(constraint.References.Table)
			if len(constraint.References.Columns) > 0 {
				f.builder.WriteString("(")
				f.builder.WriteString(strings.Join(constraint.References.Columns, ", "))
				f.builder.WriteString(")")
			}
			if constraint.References.OnDelete != "" {
				f.builder.WriteString(" ")
				f.writeKeyword("ON DELETE")
				f.builder.WriteString(" ")
				f.writeKeyword(constraint.References.OnDelete)
			}
			if constraint.References.OnUpdate != "" {
				f.builder.WriteString(" ")
				f.writeKeyword("ON UPDATE")
				f.builder.WriteString(" ")
				f.writeKeyword(constraint.References.OnUpdate)
			}
		}
	}
}

func (f *SQLFormatter) formatAlterTableAction(action *ast.AlterTableAction) {
	f.builder.WriteString(action.Type)
	if action.ColumnName != "" {
		f.builder.WriteString(" " + action.ColumnName)
	}
	if action.ColumnDef != nil {
		f.builder.WriteString(" ")
		f.formatColumnDef(action.ColumnDef)
	}
}

// Indentation and formatting helpers
func (f *SQLFormatter) writeKeyword(keyword string) {
	if f.uppercaseKw {
		f.builder.WriteString(strings.ToUpper(keyword))
	} else {
		f.builder.WriteString(strings.ToLower(keyword))
	}
}

// formatIdentifier formats an identifier, quoting it if it contains special characters
// or is a reserved keyword
func (f *SQLFormatter) formatIdentifier(ident string) {
	if f.needsQuoting(ident) {
		f.builder.WriteString("\"")
		// Escape any existing double quotes by doubling them
		escaped := strings.ReplaceAll(ident, "\"", "\"\"")
		f.builder.WriteString(escaped)
		f.builder.WriteString("\"")
	} else {
		f.builder.WriteString(ident)
	}
}

// needsQuoting returns true if the identifier needs to be quoted
func (f *SQLFormatter) needsQuoting(ident string) bool {
	if len(ident) == 0 {
		return true
	}
	// Check if it starts with a digit
	if ident[0] >= '0' && ident[0] <= '9' {
		return true
	}
	// Check for special characters (allow only letters, digits, and underscore)
	for _, c := range ident {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return true
		}
	}
	// Check for common SQL reserved keywords that might be used as aliases
	reserved := map[string]bool{
		"SELECT": true, "FROM": true, "WHERE": true, "AND": true, "OR": true,
		"ORDER": true, "BY": true, "GROUP": true, "HAVING": true, "JOIN": true,
		"LEFT": true, "RIGHT": true, "INNER": true, "OUTER": true, "ON": true,
		"AS": true, "TABLE": true, "INDEX": true, "CREATE": true, "DROP": true,
		"INSERT": true, "UPDATE": true, "DELETE": true, "INTO": true, "VALUES": true,
		"SET": true, "NULL": true, "NOT": true, "IN": true, "LIKE": true,
		"BETWEEN": true, "EXISTS": true, "CASE": true, "WHEN": true, "THEN": true,
		"ELSE": true, "END": true, "DISTINCT": true, "ALL": true, "UNION": true,
	}
	return reserved[strings.ToUpper(ident)]
}

func (f *SQLFormatter) writeNewline() {
	if !f.compact {
		f.builder.WriteString("\n")
	} else {
		f.builder.WriteString(" ")
	}
}

func (f *SQLFormatter) increaseIndent() {
	f.newlineLevel++
}

func (f *SQLFormatter) decreaseIndent() {
	if f.newlineLevel > 0 {
		f.newlineLevel--
	}
}

func (f *SQLFormatter) currentIndent() string {
	if f.compact {
		return ""
	}
	return strings.Repeat(f.indent, f.newlineLevel)
}

// formatDrop formats DROP statements
func (f *SQLFormatter) formatDrop(stmt *ast.DropStatement) error {
	f.writeKeyword("DROP")
	f.builder.WriteString(" ")
	f.writeKeyword(stmt.ObjectType)

	if stmt.IfExists {
		f.builder.WriteString(" ")
		f.writeKeyword("IF EXISTS")
	}

	for i, name := range stmt.Names {
		if i > 0 {
			f.builder.WriteString(",")
		}
		f.builder.WriteString(" " + name)
	}

	if stmt.CascadeType != "" {
		f.builder.WriteString(" ")
		f.writeKeyword(stmt.CascadeType)
	}

	return nil
}

// formatCreateView formats CREATE VIEW statements
func (f *SQLFormatter) formatCreateView(stmt *ast.CreateViewStatement) error {
	f.writeKeyword("CREATE")
	if stmt.OrReplace {
		f.builder.WriteString(" ")
		f.writeKeyword("OR REPLACE")
	}
	if stmt.Temporary {
		f.builder.WriteString(" ")
		f.writeKeyword("TEMPORARY")
	}
	f.builder.WriteString(" ")
	f.writeKeyword("VIEW")

	if stmt.IfNotExists {
		f.builder.WriteString(" ")
		f.writeKeyword("IF NOT EXISTS")
	}

	f.builder.WriteString(" " + stmt.Name)

	if len(stmt.Columns) > 0 {
		f.builder.WriteString(" (")
		for i, col := range stmt.Columns {
			if i > 0 {
				f.builder.WriteString(", ")
			}
			f.builder.WriteString(col)
		}
		f.builder.WriteString(")")
	}

	f.builder.WriteString(" ")
	f.writeKeyword("AS")
	f.writeNewline()
	f.increaseIndent()
	if err := f.formatStatement(stmt.Query); err != nil {
		return err
	}
	f.decreaseIndent()

	return nil
}

// formatCreateMaterializedView formats CREATE MATERIALIZED VIEW statements
func (f *SQLFormatter) formatCreateMaterializedView(stmt *ast.CreateMaterializedViewStatement) error {
	f.writeKeyword("CREATE MATERIALIZED VIEW")

	if stmt.IfNotExists {
		f.builder.WriteString(" ")
		f.writeKeyword("IF NOT EXISTS")
	}

	f.builder.WriteString(" " + stmt.Name)

	if len(stmt.Columns) > 0 {
		f.builder.WriteString(" (")
		for i, col := range stmt.Columns {
			if i > 0 {
				f.builder.WriteString(", ")
			}
			f.builder.WriteString(col)
		}
		f.builder.WriteString(")")
	}

	f.builder.WriteString(" ")
	f.writeKeyword("AS")
	f.writeNewline()
	f.increaseIndent()
	if err := f.formatStatement(stmt.Query); err != nil {
		return err
	}
	f.decreaseIndent()

	if stmt.WithData != nil {
		f.writeNewline()
		if *stmt.WithData {
			f.writeKeyword("WITH DATA")
		} else {
			f.writeKeyword("WITH NO DATA")
		}
	}

	return nil
}

// formatRefreshMaterializedView formats REFRESH MATERIALIZED VIEW statements
func (f *SQLFormatter) formatRefreshMaterializedView(stmt *ast.RefreshMaterializedViewStatement) error {
	f.writeKeyword("REFRESH MATERIALIZED VIEW")

	if stmt.Concurrently {
		f.builder.WriteString(" ")
		f.writeKeyword("CONCURRENTLY")
	}

	f.builder.WriteString(" " + stmt.Name)

	if stmt.WithData != nil {
		f.builder.WriteString(" ")
		if *stmt.WithData {
			f.writeKeyword("WITH DATA")
		} else {
			f.writeKeyword("WITH NO DATA")
		}
	}

	return nil
}

// formatMergeStatement formats MERGE statements with proper indentation
func (f *SQLFormatter) formatMergeStatement(stmt *ast.MergeStatement) error {
	// MERGE INTO target_table
	f.writeKeyword("MERGE INTO")
	f.builder.WriteString(" ")
	f.formatTableReference(&stmt.TargetTable)
	if stmt.TargetAlias != "" {
		f.builder.WriteString(" " + stmt.TargetAlias)
	}

	// USING source_table
	f.writeNewline()
	f.writeKeyword("USING")
	f.builder.WriteString(" ")
	f.formatTableReference(&stmt.SourceTable)
	if stmt.SourceAlias != "" {
		f.builder.WriteString(" " + stmt.SourceAlias)
	}

	// ON condition
	if stmt.OnCondition != nil {
		f.writeNewline()
		f.writeKeyword("ON")
		f.builder.WriteString(" ")
		if err := f.formatExpression(stmt.OnCondition); err != nil {
			return fmt.Errorf("failed to format ON condition: %w", err)
		}
	}

	// WHEN clauses
	for _, whenClause := range stmt.WhenClauses {
		if err := f.formatMergeWhenClause(whenClause); err != nil {
			return fmt.Errorf("failed to format WHEN clause: %w", err)
		}
	}

	return nil
}

// formatMergeWhenClause formats a WHEN clause in a MERGE statement
func (f *SQLFormatter) formatMergeWhenClause(when *ast.MergeWhenClause) error {
	f.writeNewline()
	f.writeKeyword("WHEN")
	f.builder.WriteString(" ")

	// Format the match type
	switch when.Type {
	case "MATCHED":
		f.writeKeyword("MATCHED")
	case "NOT_MATCHED":
		f.writeKeyword("NOT MATCHED")
	case "NOT_MATCHED_BY_SOURCE":
		f.writeKeyword("NOT MATCHED BY SOURCE")
	default:
		f.writeKeyword(when.Type)
	}

	// Format optional AND condition
	if when.Condition != nil {
		f.builder.WriteString(" ")
		f.writeKeyword("AND")
		f.builder.WriteString(" ")
		if err := f.formatExpression(when.Condition); err != nil {
			return fmt.Errorf("failed to format WHEN condition: %w", err)
		}
	}

	// Format THEN action
	f.builder.WriteString(" ")
	f.writeKeyword("THEN")
	f.writeNewline()
	f.increaseIndent()
	f.builder.WriteString(f.currentIndent())
	if err := f.formatMergeAction(when.Action); err != nil {
		return fmt.Errorf("failed to format MERGE action: %w", err)
	}
	f.decreaseIndent()

	return nil
}

// formatMergeAction formats the action part of a WHEN clause (UPDATE/INSERT/DELETE)
func (f *SQLFormatter) formatMergeAction(action *ast.MergeAction) error {
	if action == nil {
		return nil
	}

	switch action.ActionType {
	case "UPDATE":
		f.writeKeyword("UPDATE SET")
		if len(action.SetClauses) > 0 {
			f.builder.WriteString(" ")
			for i, setClause := range action.SetClauses {
				if i > 0 {
					f.builder.WriteString(", ")
				}
				f.builder.WriteString(setClause.Column)
				f.builder.WriteString(" = ")
				if err := f.formatExpression(setClause.Value); err != nil {
					return fmt.Errorf("failed to format SET clause value: %w", err)
				}
			}
		}

	case "INSERT":
		f.writeKeyword("INSERT")
		if action.DefaultValues {
			f.builder.WriteString(" ")
			f.writeKeyword("DEFAULT VALUES")
		} else if len(action.Columns) > 0 {
			f.builder.WriteString(" (")
			for i, col := range action.Columns {
				if i > 0 {
					f.builder.WriteString(", ")
				}
				f.builder.WriteString(col)
			}
			f.builder.WriteString(")")
			if len(action.Values) > 0 {
				f.writeNewline()
				f.builder.WriteString(f.currentIndent())
				f.writeKeyword("VALUES")
				f.builder.WriteString(" (")
				f.formatExpressionList(action.Values, ", ")
				f.builder.WriteString(")")
			}
		} else if len(action.Values) > 0 {
			f.builder.WriteString(" ")
			f.writeKeyword("VALUES")
			f.builder.WriteString(" (")
			f.formatExpressionList(action.Values, ", ")
			f.builder.WriteString(")")
		}

	case "DELETE":
		f.writeKeyword("DELETE")

	default:
		return fmt.Errorf("unsupported merge action type: %s", action.ActionType)
	}

	return nil
}
