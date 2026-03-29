package gosqlxotel_test

import (
	"context"
	"testing"

	gosqlxotel "github.com/ajitpratap0/GoSQLX/integrations/opentelemetry"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInstrumentParse_CreatesSpan(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(trace.WithSyncer(exporter))

	ctx := context.Background()
	_, err := gosqlxotel.InstrumentedParse(ctx, tp, "SELECT id, name FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("InstrumentedParse: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}
	span := spans[0]
	if span.Name != "gosqlx.parse" {
		t.Errorf("span name: got %q want gosqlx.parse", span.Name)
	}
	// Check attributes
	attrs := make(map[string]string)
	for _, attr := range span.Attributes {
		attrs[string(attr.Key)] = attr.Value.AsString()
	}
	if attrs["db.system"] != "gosqlx" {
		t.Errorf("db.system: got %q want gosqlx", attrs["db.system"])
	}
	if attrs["db.statement.type"] != "SELECT" {
		t.Errorf("db.statement.type: got %q want SELECT", attrs["db.statement.type"])
	}
}

func TestInstrumentParse_SetsErrorOnBadSQL(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(trace.WithSyncer(exporter))

	ctx := context.Background()
	_, err := gosqlxotel.InstrumentedParse(ctx, tp, "NOT VALID SQL !!!")
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}

	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected span even on error")
	}
	span := spans[0]
	// Span should have status Error
	if span.Status.Code.String() != "Error" {
		t.Errorf("span status: got %q want Error", span.Status.Code.String())
	}
}

func TestRecordQueryAttributes_ExtractsTablesAndColumns(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(trace.WithSyncer(exporter))

	ctx := context.Background()
	sql := "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.id = 42"
	_, err := gosqlxotel.InstrumentedParse(ctx, tp, sql)
	if err != nil {
		t.Fatalf("InstrumentedParse: %v", err)
	}

	span := exporter.GetSpans()[0]
	attrs := make(map[string]string)
	for _, attr := range span.Attributes {
		attrs[string(attr.Key)] = attr.Value.AsString()
	}
	if attrs["db.sql.tables"] == "" {
		t.Error("expected db.sql.tables to be set")
	}
}
