package cmd

import (
	"fmt"
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
		f.formatExpressionList(stmt.OrderBy, ", ")
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
		f.builder.WriteString(" (")
		f.formatExpressionList(stmt.Values, ", ")
		f.builder.WriteString(")")
	}

	if stmt.Query != nil {
		f.writeNewline()
		return f.formatSelect(stmt.Query)
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

	if len(stmt.Updates) > 0 || len(stmt.Assignments) > 0 {
		f.writeNewline()
		f.writeKeyword("SET")
		f.builder.WriteString(" ")

		updates := stmt.Updates
		if len(stmt.Assignments) > 0 {
			updates = stmt.Assignments
		}

		for i, update := range updates {
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
		f.builder.WriteString(e.TokenLiteral())
	case *ast.BinaryExpression:
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
		f.builder.WriteString(")")

		// Window function
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
		f.formatExpressionList(spec.OrderBy, ", ")
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
		f.formatExpression(expr)
	}
}

func (f *SQLFormatter) formatTableReferences(tables []ast.TableReference) {
	for i, table := range tables {
		if i > 0 {
			f.builder.WriteString(", ")
		}
		f.formatTableReference(&table)
	}
}

func (f *SQLFormatter) formatTableReference(table *ast.TableReference) {
	f.builder.WriteString(table.Name)
	if table.Alias != "" {
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
		f.builder.WriteString(" " + constraint.Type)
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
