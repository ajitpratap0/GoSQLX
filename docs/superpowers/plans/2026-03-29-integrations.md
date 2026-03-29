# OTel + GORM Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship two optional integration sub-modules — `integrations/opentelemetry/` and `integrations/gorm/` — each with its own `go.mod` so users who don't need them pay zero dependency cost.

**Architecture:** Each integration lives under `integrations/<name>/` with its own `go.mod` (pointing back to the root module via `replace` directive during development). OTel integration wraps `gosqlx.Parse()` and emits a span with SQL metadata attributes. GORM integration adds a plugin (`gorm.io/gorm/plugin` interface) that parses each executed query with GoSQLX and attaches extracted table/column metadata to GORM callbacks.

**Tech Stack:** `go.opentelemetry.io/otel v1.26+` (tracing + attributes), `go.opentelemetry.io/otel/sdk` (test SDK), `gorm.io/gorm v2`, `gorm.io/driver/sqlite` (pure-Go, for testing without Docker), `github.com/ajitpratap0/GoSQLX` (root module).

---

### Task 1: OpenTelemetry integration — failing test

**Files:**
- Create: `integrations/opentelemetry/go.mod`
- Create: `integrations/opentelemetry/otel.go`
- Create: `integrations/opentelemetry/otel_test.go`

- [ ] **Step 1: Create go.mod for OTel integration**

```
// integrations/opentelemetry/go.mod
module github.com/ajitpratap0/GoSQLX/integrations/opentelemetry

go 1.23

require (
    github.com/ajitpratap0/GoSQLX v1.13.0
    go.opentelemetry.io/otel v1.26.0
    go.opentelemetry.io/otel/sdk v1.26.0
    go.opentelemetry.io/otel/trace v1.26.0
)

replace github.com/ajitpratap0/GoSQLX => ../../
```

- [ ] **Step 2: Write the test (it will fail — package doesn't exist)**

```go
// integrations/opentelemetry/otel_test.go
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
```

- [ ] **Step 3: Run test — verify it fails**

```bash
cd integrations/opentelemetry && go test ./... -v -run TestInstrument
```
Expected: compile error — `gosqlxotel` package not found.

---

### Task 2: Implement OpenTelemetry integration

**Files:**
- Create: `integrations/opentelemetry/otel.go`

- [ ] **Step 1: Implement InstrumentedParse**

```go
// integrations/opentelemetry/otel.go
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

	// Extract statement type
	if len(tree.Statements) > 0 {
		stmtType := statementType(tree.Statements[0])
		span.SetAttributes(attribute.String("db.statement.type", stmtType))
	}

	// Extract table names
	tables := gosqlx.ExtractTables(sql)
	if len(tables) > 0 {
		span.SetAttributes(attribute.String("db.sql.tables", strings.Join(tables, ",")))
	}

	// Extract column references
	columns := gosqlx.ExtractColumns(sql)
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
```

- [ ] **Step 2: Run tests**

```bash
cd integrations/opentelemetry && go mod tidy && go test ./... -v -run TestInstrument
```
Expected: PASS.

- [ ] **Step 3: Run race detector**

```bash
cd integrations/opentelemetry && go test -race ./... -timeout 60s
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add integrations/opentelemetry/
git commit -m "feat(integrations): OpenTelemetry instrumentation for gosqlx.Parse"
```

---

### Task 3: GORM integration — failing test

**Files:**
- Create: `integrations/gorm/go.mod`
- Create: `integrations/gorm/plugin_test.go`

- [ ] **Step 1: Create go.mod for GORM integration**

```
// integrations/gorm/go.mod
module github.com/ajitpratap0/GoSQLX/integrations/gorm

go 1.23

require (
    github.com/ajitpratap0/GoSQLX v1.13.0
    gorm.io/gorm v1.25.10
    gorm.io/driver/sqlite v1.5.6
    modernc.org/sqlite v1.30.1
)

replace github.com/ajitpratap0/GoSQLX => ../../
```

- [ ] **Step 2: Write the test**

```go
// integrations/gorm/plugin_test.go
package gosqlxgorm_test

import (
	"testing"

	gosqlxgorm "github.com/ajitpratap0/GoSQLX/integrations/gorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type User struct {
	gorm.Model
	Name  string
	Email string
}

type Order struct {
	gorm.Model
	UserID uint
	Total  float64
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open gorm db: %v", err)
	}
	_ = db.AutoMigrate(&User{}, &Order{})
	return db
}

func TestPlugin_Name(t *testing.T) {
	plugin := gosqlxgorm.NewPlugin()
	if plugin.Name() != "gosqlx" {
		t.Errorf("plugin name: got %q want gosqlx", plugin.Name())
	}
}

func TestPlugin_Initialize_NoError(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	if err := db.Use(plugin); err != nil {
		t.Fatalf("Use plugin: %v", err)
	}
}

func TestPlugin_RecordsQueriesOnQuery(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	if err := db.Use(plugin); err != nil {
		t.Fatal(err)
	}

	var users []User
	db.Find(&users)

	stats := plugin.Stats()
	if stats.TotalQueries == 0 {
		t.Error("expected at least one recorded query")
	}
}

func TestPlugin_RecordsTableName(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	_ = db.Use(plugin)

	var users []User
	db.Where("name = ?", "alice").Find(&users)

	stats := plugin.Stats()
	found := false
	for _, q := range stats.Queries {
		for _, tbl := range q.Tables {
			if tbl == "users" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected 'users' in recorded table names; got %+v", stats.Queries)
	}
}

func TestPlugin_ParseErrorDoesNotPanic(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	_ = db.Use(plugin)

	// Raw SQL that might not parse perfectly — plugin must not panic
	db.Raw("SELECT 1 + 1").Scan(nil)

	// No panic = success
}
```

- [ ] **Step 3: Run test — verify it fails**

```bash
cd integrations/gorm && go test ./... -v -run TestPlugin
```
Expected: compile error — package `gosqlxgorm` not found.

---

### Task 4: Implement GORM plugin

**Files:**
- Create: `integrations/gorm/plugin.go`

- [ ] **Step 1: Implement the plugin**

```go
// integrations/gorm/plugin.go
package gosqlxgorm

import (
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"gorm.io/gorm"
)

// QueryRecord holds metadata about a single recorded GORM query.
type QueryRecord struct {
	SQL     string
	Tables  []string
	Columns []string
	Type    string // SELECT, INSERT, UPDATE, DELETE, ...
	ParseOK bool
}

// PluginStats is the aggregate of all queries observed since initialization.
type PluginStats struct {
	TotalQueries int
	ParseErrors  int
	Queries      []QueryRecord
}

// Plugin is a GORM plugin that parses each executed query with GoSQLX
// and records extracted metadata (tables, columns, statement type).
type Plugin struct {
	mu      sync.Mutex
	queries []QueryRecord
}

// NewPlugin returns a new GoSQLX GORM plugin.
func NewPlugin() *Plugin { return &Plugin{} }

// Name implements gorm.Plugin.
func (p *Plugin) Name() string { return "gosqlx" }

// Initialize implements gorm.Plugin by registering callbacks.
func (p *Plugin) Initialize(db *gorm.DB) error {
	// After Query
	db.Callback().Query().After("gorm:query").Register("gosqlx:after_query", p.afterStatement)
	// After Create
	db.Callback().Create().After("gorm:create").Register("gosqlx:after_create", p.afterStatement)
	// After Update
	db.Callback().Update().After("gorm:update").Register("gosqlx:after_update", p.afterStatement)
	// After Delete
	db.Callback().Delete().After("gorm:delete").Register("gosqlx:after_delete", p.afterStatement)
	// After Raw
	db.Callback().Raw().After("gorm:raw").Register("gosqlx:after_raw", p.afterStatement)
	return nil
}

func (p *Plugin) afterStatement(db *gorm.DB) {
	if db.Statement == nil {
		return
	}
	sql := db.Statement.SQL.String()
	if sql == "" {
		return
	}
	rec := QueryRecord{SQL: sql}

	tree, err := gosqlx.Parse(sql)
	if err != nil {
		rec.ParseOK = false
	} else {
		rec.ParseOK = true
		rec.Tables = gosqlx.ExtractTables(sql)
		rec.Columns = gosqlx.ExtractColumns(sql)
		if tree != nil && len(tree.Statements) > 0 {
			rec.Type = stmtTypeName(tree.Statements[0])
		}
	}

	p.mu.Lock()
	p.queries = append(p.queries, rec)
	p.mu.Unlock()
}

// Stats returns a snapshot of all recorded queries.
func (p *Plugin) Stats() PluginStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errCount int
	for _, q := range p.queries {
		if !q.ParseOK {
			errCount++
		}
	}
	qs := make([]QueryRecord, len(p.queries))
	copy(qs, p.queries)
	return PluginStats{
		TotalQueries: len(p.queries),
		ParseErrors:  errCount,
		Queries:      qs,
	}
}

// Reset clears all recorded queries.
func (p *Plugin) Reset() {
	p.mu.Lock()
	p.queries = p.queries[:0]
	p.mu.Unlock()
}

func stmtTypeName(stmt interface{}) string {
	switch stmt.(type) {
	default:
		return "UNKNOWN"
	}
}
```

**Note:** `stmtTypeName` needs the ast import to do the type switch. Update it:

```go
import (
    "sync"
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
    "gorm.io/gorm"
)

func stmtTypeName(stmt ast.Statement) string {
    switch stmt.(type) {
    case *ast.SelectStatement:
        return "SELECT"
    case *ast.InsertStatement:
        return "INSERT"
    case *ast.UpdateStatement:
        return "UPDATE"
    case *ast.DeleteStatement:
        return "DELETE"
    default:
        return "OTHER"
    }
}
```

- [ ] **Step 2: Run GORM tests**

```bash
cd integrations/gorm && go mod tidy && go test ./... -v -run TestPlugin
```
Expected: PASS.

- [ ] **Step 3: Run race detector**

```bash
cd integrations/gorm && go test -race ./... -timeout 60s
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add integrations/gorm/
git commit -m "feat(integrations): GORM plugin for query introspection with GoSQLX"
```

---

### Task 5: Add CI workflow for integrations sub-modules

**Files:**
- Create: `.github/workflows/integrations.yml`

- [ ] **Step 1: Write workflow**

```yaml
# .github/workflows/integrations.yml
name: Integrations

on:
  push:
    paths:
      - 'integrations/**'
      - '.github/workflows/integrations.yml'
  pull_request:
    paths:
      - 'integrations/**'
      - '.github/workflows/integrations.yml'

jobs:
  opentelemetry:
    name: OpenTelemetry Integration
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: integrations/opentelemetry
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - run: go mod tidy
      - run: go test -race -timeout 60s ./...

  gorm:
    name: GORM Integration
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: integrations/gorm
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - run: go mod tidy
      - run: go test -race -timeout 60s ./...
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/integrations.yml
git commit -m "ci: add integrations workflow for OTel and GORM sub-modules"
```

---

### Task 6: Documentation and issue closure

- [ ] **Step 1: Add CHANGELOG entries**

Under `[Unreleased]` in `CHANGELOG.md`:

```markdown
### Added
- `integrations/opentelemetry/` sub-module: `InstrumentedParse()` wraps `gosqlx.Parse()` with OpenTelemetry spans including `db.system`, `db.statement.type`, `db.sql.tables`, `db.sql.columns` attributes
- `integrations/gorm/` sub-module: GORM plugin that records executed query metadata (tables, columns, statement type) via GoSQLX parsing; exposes `Stats()` and `Reset()` APIs
- CI workflow for integration sub-modules (`.github/workflows/integrations.yml`)
```

- [ ] **Step 2: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add OTel and GORM integrations to CHANGELOG"
```

- [ ] **Step 3: Close GitHub issues**

```bash
gh issue close 451 --comment "Implemented as integrations/opentelemetry sub-module. See docs/superpowers/plans/2026-03-29-integrations.md."
gh issue close 452 --comment "Implemented as integrations/gorm sub-module. See docs/superpowers/plans/2026-03-29-integrations.md."
```
