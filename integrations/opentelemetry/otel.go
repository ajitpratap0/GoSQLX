// Package gosqlxotel provides OpenTelemetry instrumentation for GoSQLX.
// It wraps gosqlx.Parse() and emits a span with SQL metadata attributes.
package gosqlxotel

import (
	"context"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/ajitpratap0/GoSQLX"

// InstrumentedParse parses SQL and records a span with statement metadata.
// The returned AST is the same as gosqlx.Parse(); the span is recorded on tp.
// If parsing fails, the error is recorded on the span and returned to the caller.
func InstrumentedParse(ctx context.Context, tp trace.TracerProvider, sql string) (*ast.AST, error) {
	tracer := tp.Tracer(tracerName)
	ctx, span := tracer.Start(ctx, "gosqlx.parse")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "gosqlx"),
		attribute.String("db.statement", sql),
	)

	tree, err := gosqlx.Parse(sql)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Extract statement type from the first statement.
	if len(tree.Statements) > 0 {
		stmtType := statementType(tree.Statements[0])
		span.SetAttributes(attribute.String("db.statement.type", stmtType))
	}

	// Extract table names using the parsed AST.
	tables := gosqlx.ExtractTables(tree)
	if len(tables) > 0 {
		span.SetAttributes(attribute.String("db.sql.tables", strings.Join(tables, ",")))
	}

	// Extract column references using the parsed AST.
	columns := gosqlx.ExtractColumns(tree)
	if len(columns) > 0 {
		span.SetAttributes(attribute.String("db.sql.columns", strings.Join(columns, ",")))
	}

	span.SetStatus(codes.Ok, "")
	return tree, nil
}

// statementType returns the SQL statement type string (SELECT, INSERT, etc.)
func statementType(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.InsertStatement:
		return "INSERT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	case *ast.CreateTableStatement:
		return "CREATE TABLE"
	case *ast.DropStatement:
		return "DROP"
	case *ast.AlterTableStatement:
		return "ALTER TABLE"
	default:
		return fmt.Sprintf("%T", stmt)
	}
}
