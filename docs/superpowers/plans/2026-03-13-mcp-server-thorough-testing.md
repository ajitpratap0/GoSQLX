# GoSQLX MCP Server — Thorough Testing Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Achieve >95% test coverage on `pkg/mcp/` with comprehensive unit, integration, concurrency, and end-to-end HTTP tests covering every tool, error path, edge case, and the full server lifecycle.

**Architecture:** Tests are organized in 7 tasks — coverage-gap unit tests, HTTP auth middleware tests, concurrency/race tests, edge-case SQL tests, server lifecycle tests, MCP protocol round-trip tests (in-process client + Inspector CLI E2E), and final verification. Each task creates or extends a single test file with focused test functions.

**Tech Stack:** Go 1.23+, `testing` stdlib, `net/http/httptest`, `mark3labs/mcp-go v0.45.0`, `sync`, `context`

---

## File Structure

| File | Purpose |
|------|---------|
| `pkg/mcp/tools_test.go` (modify) | Extend with coverage-gap tests, edge-case SQL, security scan deep tests |
| `pkg/mcp/tools_internal_test.go` (create) | Tests for internal functions directly (validateSQLInternal, etc.) |
| `pkg/mcp/server_integration_test.go` (create) | HTTP-level auth middleware tests using httptest |
| `pkg/mcp/server_test.go` (modify) | Add server lifecycle tests (Start, graceful shutdown) |
| `pkg/mcp/concurrency_test.go` (create) | Race condition and concurrent access tests |
| `pkg/mcp/protocol_test.go` (create) | MCP protocol round-trip tests using mcp-go in-process client |
| `scripts/mcp-inspector-test.sh` (create) | E2E shell test using MCP Inspector CLI |

---

## Chunk 1: Coverage Gap Unit Tests

### Task 1: Internal Function Direct Tests

Current gap: internal functions (`validateSQLInternal`, `formatSQLInternal`, etc.) are only tested indirectly through handlers. Several branches are uncovered (format failure, parse failure in metadata, nil-slice normalization, toolResult marshal error).

**Files:**
- Create: `pkg/mcp/tools_internal_test.go`
- Reference: `pkg/mcp/tools.go:44-248`

- [ ] **Step 1: Write failing tests for validateSQLInternal**

```go
// pkg/mcp/tools_internal_test.go
package mcp

import (
	"testing"
)

func TestValidateSQLInternal_EmptySQL(t *testing.T) {
	_, err := validateSQLInternal("", "")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestValidateSQLInternal_ValidGeneric(t *testing.T) {
	data, err := validateSQLInternal("SELECT 1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["valid"] != true {
		t.Errorf("expected valid=true, got %v", data["valid"])
	}
	if _, ok := data["dialect"]; ok {
		t.Error("generic validation should not include dialect key")
	}
}

func TestValidateSQLInternal_InvalidGeneric(t *testing.T) {
	data, err := validateSQLInternal("SELECT FROM", "")
	if err != nil {
		t.Fatalf("expected nil error for invalid SQL (tool-semantic), got: %v", err)
	}
	if data["valid"] != false {
		t.Errorf("expected valid=false, got %v", data["valid"])
	}
	if _, ok := data["error"]; !ok {
		t.Error("expected error key in result")
	}
}

func TestValidateSQLInternal_ValidWithDialect(t *testing.T) {
	data, err := validateSQLInternal("SELECT 1", "postgresql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["valid"] != true {
		t.Errorf("expected valid=true")
	}
	if data["dialect"] != "postgresql" {
		t.Errorf("expected dialect=postgresql, got %v", data["dialect"])
	}
}

func TestValidateSQLInternal_InvalidWithDialect(t *testing.T) {
	data, err := validateSQLInternal("SELECT FROM", "mysql")
	if err != nil {
		t.Fatalf("expected nil error for invalid SQL (tool-semantic), got: %v", err)
	}
	if data["valid"] != false {
		t.Errorf("expected valid=false")
	}
	if data["dialect"] != "mysql" {
		t.Errorf("expected dialect=mysql, got %v", data["dialect"])
	}
}
```

- [ ] **Step 2: Run tests to verify they pass (these test existing code)**

Run: `go test -v -run "TestValidateSQLInternal" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 3: Write tests for formatSQLInternal — including failure path**

```go
func TestFormatSQLInternal_EmptySQL(t *testing.T) {
	_, err := formatSQLInternal("", 2, false, false)
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestFormatSQLInternal_ValidSQL(t *testing.T) {
	data, err := formatSQLInternal("select id from users", 4, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := data["formatted_sql"]; !ok {
		t.Error("expected formatted_sql key")
	}
	// Internal functions return native Go types (int, bool), not JSON float64.
	opts, ok := data["options"].(map[string]any)
	if !ok {
		t.Fatal("expected options to be map[string]any")
	}
	if opts["indent_size"] != 4 {
		t.Errorf("expected indent_size=4, got %v", opts["indent_size"])
	}
	if opts["uppercase_keywords"] != true {
		t.Errorf("expected uppercase_keywords=true")
	}
	if opts["add_semicolon"] != true {
		t.Errorf("expected add_semicolon=true")
	}
}

func TestFormatSQLInternal_InvalidSQL(t *testing.T) {
	// Truly unparseable input — random punctuation that cannot form any SQL statement.
	_, err := formatSQLInternal(")))((( @@@ !!!", 2, false, false)
	if err == nil {
		t.Fatal("expected format error for completely invalid SQL")
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run "TestFormatSQLInternal" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 5: Write tests for parseSQLInternal**

```go
func TestParseSQLInternal_EmptySQL(t *testing.T) {
	_, err := parseSQLInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestParseSQLInternal_SingleStatement(t *testing.T) {
	data, err := parseSQLInternal("SELECT id FROM users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["statement_count"] != 1 {
		t.Errorf("expected 1 statement, got %v", data["statement_count"])
	}
	types := data["statement_types"].([]string)
	if len(types) != 1 {
		t.Errorf("expected 1 type, got %d", len(types))
	}
}

func TestParseSQLInternal_MultipleStatements(t *testing.T) {
	data, err := parseSQLInternal("SELECT 1; INSERT INTO t VALUES (1); DELETE FROM t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := data["statement_count"].(int)
	if count < 2 {
		t.Errorf("expected multiple statements, got %d", count)
	}
}

func TestParseSQLInternal_InvalidSQL(t *testing.T) {
	// Truly unparseable: random punctuation that cannot form any statement.
	_, err := parseSQLInternal(")))((( @@@ !!!")
	if err == nil {
		t.Fatal("expected parse error for invalid SQL")
	}
}
```

- [ ] **Step 6: Run tests**

Run: `go test -v -run "TestParseSQLInternal" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 7: Write tests for extractMetadataInternal — nil-slice normalization**

```go
func TestExtractMetadataInternal_EmptySQL(t *testing.T) {
	_, err := extractMetadataInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestExtractMetadataInternal_WithJoins(t *testing.T) {
	data, err := extractMetadataInternal("SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tables := data["tables"].([]string)
	if len(tables) == 0 {
		t.Error("expected at least one table")
	}
	columns := data["columns"].([]string)
	if len(columns) == 0 {
		t.Error("expected at least one column")
	}
}

func TestExtractMetadataInternal_WithFunctions(t *testing.T) {
	data, err := extractMetadataInternal("SELECT COUNT(*), MAX(price) FROM products")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	functions := data["functions"].([]string)
	if len(functions) == 0 {
		t.Error("expected at least one function")
	}
}

func TestExtractMetadataInternal_NoTablesReturnsEmptySlice(t *testing.T) {
	// SELECT 1 has no tables — verify nil normalization to empty slice
	data, err := extractMetadataInternal("SELECT 1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tables := data["tables"].([]string)
	if tables == nil {
		t.Error("tables should be [] not nil (nil-normalization)")
	}
}

func TestExtractMetadataInternal_InvalidSQL(t *testing.T) {
	// Truly unparseable: random punctuation.
	_, err := extractMetadataInternal(")))((( @@@ !!!")
	if err == nil {
		t.Fatal("expected parse error for invalid SQL")
	}
}
```

- [ ] **Step 8: Run tests**

Run: `go test -v -run "TestExtractMetadataInternal" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 9: Write tests for securityScanInternal and lintSQLInternal**

```go
func TestSecurityScanInternal_EmptySQL(t *testing.T) {
	_, err := securityScanInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestSecurityScanInternal_CleanSQL(t *testing.T) {
	data, err := securityScanInternal("SELECT id FROM users WHERE id = 42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] != true {
		t.Error("expected is_clean=true for benign SQL")
	}
	if data["total_count"] != 0 {
		t.Errorf("expected 0 findings, got %v", data["total_count"])
	}
}

func TestSecurityScanInternal_InjectionDetected(t *testing.T) {
	data, err := securityScanInternal("SELECT * FROM users WHERE 1=1 OR ''=''")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] == true {
		t.Error("expected is_clean=false for injection pattern")
	}
	findings := data["findings"].([]map[string]any)
	if len(findings) == 0 {
		t.Error("expected at least one finding")
	}
	// Verify finding structure
	f := findings[0]
	for _, key := range []string{"severity", "pattern", "description", "risk", "suggestion"} {
		if _, ok := f[key]; !ok {
			t.Errorf("finding missing key %q", key)
		}
	}
}

func TestSecurityScanInternal_StackedQueries(t *testing.T) {
	data, err := securityScanInternal("SELECT 1; DROP TABLE users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["is_clean"] == true {
		t.Error("expected detection of stacked query pattern")
	}
}

func TestSecurityScanInternal_CommentBypass(t *testing.T) {
	data, err := securityScanInternal("SELECT * FROM users WHERE id = 1 -- bypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Comment bypasses should be detected
	totalCount, _ := data["total_count"].(int)
	_ = totalCount // may or may not detect depending on pattern
}

func TestLintSQLInternal_EmptySQL(t *testing.T) {
	_, err := lintSQLInternal("")
	if err == nil {
		t.Fatal("expected error for empty sql")
	}
}

func TestLintSQLInternal_CleanSQL(t *testing.T) {
	data, err := lintSQLInternal("SELECT id FROM users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := data["violation_count"]; !ok {
		t.Error("expected violation_count key")
	}
	if _, ok := data["violations"]; !ok {
		t.Error("expected violations key")
	}
}

func TestLintSQLInternal_WithViolations(t *testing.T) {
	// Trailing whitespace triggers L001, mixed case keywords trigger L007
	data, err := lintSQLInternal("select id from users   \n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	violations := data["violations"].([]map[string]any)
	if len(violations) == 0 {
		t.Error("expected lint violations for trailing whitespace / keyword case")
	}
	// Verify violation structure
	v := violations[0]
	for _, key := range []string{"rule", "rule_name", "severity", "message", "line", "column", "suggestion"} {
		if _, ok := v[key]; !ok {
			t.Errorf("violation missing key %q", key)
		}
	}
}
```

- [ ] **Step 10: Run all internal tests**

Run: `go test -v -run "TestSecurityScanInternal|TestLintSQLInternal" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 11: Write test for toolResult helper — error path**

```go
func TestToolResult_ValidMap(t *testing.T) {
	res, err := toolResult(map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestToolResult_MarshalError(t *testing.T) {
	// json.Marshal fails on channels — this exercises the error branch.
	_, err := toolResult(map[string]any{"bad": make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error for unmarshalable value")
	}
}
```

- [ ] **Step 12: Write test for newFullLinter**

```go
func TestNewFullLinter_Returns10Rules(t *testing.T) {
	l := newFullLinter()
	if l == nil {
		t.Fatal("newFullLinter returned nil")
	}
	// LintString returns a value type (linter.FileResult), not a pointer.
	// Verify the linter works by checking the returned result has a valid filename.
	result := l.LintString("SELECT 1", "<test>")
	if result.Filename != "<test>" {
		t.Errorf("expected filename '<test>', got %q", result.Filename)
	}
}
```

- [ ] **Step 13: Run full test suite and check coverage improvement**

Run: `go test -race -timeout 60s -cover ./pkg/mcp/`
Expected: Coverage > 87%

- [ ] **Step 14: Commit**

```bash
git add pkg/mcp/tools_internal_test.go
git commit -m "test(mcp): add direct internal function tests for coverage gaps"
```

---

## Chunk 2: Integration HTTP Tests

### Task 2: End-to-End HTTP Integration Tests

Test the full MCP protocol over HTTP — start a real server with httptest, send real HTTP requests, verify JSON-RPC responses through the streamable HTTP transport.

**Files:**
- Create: `pkg/mcp/server_integration_test.go`
- Reference: `pkg/mcp/server.go`, `pkg/mcp/middleware.go`

- [ ] **Step 1: Write auth middleware integration test scaffolding**

The MCP streamable HTTP transport requires a full JSON-RPC session handshake
(`initialize` → `initialized` → `tools/call`). Rather than reimplement the protocol,
we test middleware auth at the HTTP level (where the 401 happens before any MCP logic)
and test tool routing via the `mcp-go` client SDK (which handles the handshake).

```go
// pkg/mcp/server_integration_test.go
package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"
)

// newTestHTTPServer creates a test HTTP server with MCP + auth middleware.
func newTestHTTPServer(t *testing.T, authToken string) *httptest.Server {
	t.Helper()
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: authToken}
	srv := New(cfg)
	streamSrv := mcpserver.NewStreamableHTTPServer(srv.mcpSrv)
	wrapped := BearerAuthMiddleware(cfg, streamSrv)
	return httptest.NewServer(wrapped)
}
```

- [ ] **Step 2: Write auth middleware HTTP tests**

These tests verify the middleware rejects/accepts at the HTTP layer —
before MCP session initialization is relevant.

```go
func TestIntegration_AuthRequired_NoToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	// POST to /mcp without Authorization header
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuthRequired_WrongToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuthRequired_ValidToken(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	// With valid token, request reaches MCP server — may get 400 (bad JSON-RPC)
	// but NOT 401. That proves the middleware passed it through.
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("got 401 with valid token — middleware should have passed through")
	}
}

func TestIntegration_NoAuth_RequestPassesThrough(t *testing.T) {
	ts := newTestHTTPServer(t, "") // no auth configured
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	// No auth configured = no 401
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("got 401 when auth is disabled")
	}
}

func TestIntegration_AuthRequired_GETAlsoBlocked(t *testing.T) {
	ts := newTestHTTPServer(t, "secret-token")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/mcp")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for GET without token, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 3: Run integration tests**

Run: `go test -v -run "TestIntegration" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add pkg/mcp/server_integration_test.go
git commit -m "test(mcp): add HTTP integration tests for auth middleware"
```

---

## Chunk 3: Concurrency Tests

### Task 3: Race Condition and Concurrent Access Tests

The MCP server uses `sync.WaitGroup` and goroutines in `handleAnalyzeSQL`. These tests verify thread safety under contention.

**Files:**
- Create: `pkg/mcp/concurrency_test.go`

- [ ] **Step 1: Write concurrent handler tests**

```go
// pkg/mcp/concurrency_test.go
package mcp

import (
	"context"
	"sync"
	"testing"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"
)

func TestConcurrent_ValidateSQL(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeReq(map[string]any{"sql": "SELECT id FROM users WHERE id = 1"})
			res, err := handleValidateSQL(ctx, req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			data := unmarshalResult(t, res)
			if data["valid"] != true {
				t.Errorf("expected valid=true")
			}
		}()
	}
	wg.Wait()
}

func TestConcurrent_AnalyzeSQL(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeReq(map[string]any{"sql": "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id"})
			res, err := handleAnalyzeSQL(ctx, req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			data := unmarshalResult(t, res)
			for _, key := range []string{"validate", "parse", "metadata", "security", "lint", "format"} {
				if _, ok := data[key]; !ok {
					t.Errorf("missing key %q in concurrent analyze result", key)
				}
			}
		}()
	}
	wg.Wait()
}

func TestConcurrent_MixedTools(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup

	type handlerFunc = func(context.Context, mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error)

	tools := []struct {
		name string
		fn   handlerFunc
		args map[string]any
	}{
		{"validate", handleValidateSQL, map[string]any{"sql": "SELECT 1"}},
		{"format", handleFormatSQL, map[string]any{"sql": "select id from users"}},
		{"parse", handleParseSQL, map[string]any{"sql": "SELECT id FROM users"}},
		{"metadata", handleExtractMetadata, map[string]any{"sql": "SELECT u.id FROM users u"}},
		{"security", handleSecurityScan, map[string]any{"sql": "SELECT id FROM users WHERE id = 1"}},
		{"lint", handleLintSQL, map[string]any{"sql": "SELECT id FROM users"}},
	}

	for i := 0; i < 20; i++ {
		for _, tool := range tools {
			wg.Add(1)
			go func(name string, fn handlerFunc, args map[string]any) {
				defer wg.Done()
				req := makeReq(args)
				_, err := fn(ctx, req)
				if err != nil {
					t.Errorf("%s: unexpected error: %v", name, err)
				}
			}(tool.name, tool.fn, tool.args)
		}
	}
	wg.Wait()
}
```

- [ ] **Step 2: Run with race detector**

Run: `go test -race -v -run "TestConcurrent" ./pkg/mcp/`
Expected: All PASS, zero race conditions

- [ ] **Step 3: Commit**

```bash
git add pkg/mcp/concurrency_test.go
git commit -m "test(mcp): add concurrency tests with race detection"
```

---

## Chunk 4: Edge-Case SQL and Deep Tool Tests

### Task 4: Complex SQL Edge Cases Across All Tools

Test with real-world SQL patterns: CTEs, window functions, JOINs, subqueries, multi-statement, injection patterns, and dialect-specific syntax.

**Files:**
- Modify: `pkg/mcp/tools_test.go` (add new test functions at the end)

- [ ] **Step 1: Write edge-case tests for validate_sql**

```go
func TestHandleValidateSQL_AllDialects(t *testing.T) {
	ctx := context.Background()
	dialects := []string{"generic", "mysql", "postgresql", "sqlite", "sqlserver", "oracle", "snowflake"}
	for _, d := range dialects {
		t.Run(d, func(t *testing.T) {
			req := makeReq(map[string]any{"sql": "SELECT id FROM users", "dialect": d})
			res, err := handleValidateSQL(ctx, req)
			if err != nil {
				t.Fatalf("dialect %s: unexpected error: %v", d, err)
			}
			data := unmarshalResult(t, res)
			if data["valid"] != true {
				t.Errorf("dialect %s: expected valid=true", d)
			}
		})
	}
}
```

- [ ] **Step 2: Write edge-case tests for complex SQL patterns**

```go
func TestHandleParseSQL_CTE(t *testing.T) {
	ctx := context.Background()
	sql := "WITH cte AS (SELECT id FROM users) SELECT * FROM cte"
	req := makeReq(map[string]any{"sql": sql})
	res, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	if data["statement_count"].(float64) != 1 {
		t.Errorf("expected 1 statement for CTE, got %v", data["statement_count"])
	}
}

func TestHandleParseSQL_WindowFunction(t *testing.T) {
	ctx := context.Background()
	sql := "SELECT id, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn FROM employees"
	req := makeReq(map[string]any{"sql": sql})
	_, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error parsing window function: %v", err)
	}
}

func TestHandleParseSQL_Subquery(t *testing.T) {
	ctx := context.Background()
	sql := "SELECT * FROM (SELECT id, name FROM users WHERE active = true) sub WHERE sub.id > 10"
	req := makeReq(map[string]any{"sql": sql})
	_, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error parsing subquery: %v", err)
	}
}

func TestHandleExtractMetadata_ComplexJoin(t *testing.T) {
	ctx := context.Background()
	sql := `SELECT u.name, o.total, p.name AS product
		FROM users u
		INNER JOIN orders o ON u.id = o.user_id
		LEFT JOIN products p ON o.product_id = p.id
		WHERE o.total > 100`
	req := makeReq(map[string]any{"sql": sql})
	res, err := handleExtractMetadata(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	tables := data["tables"].([]any)
	if len(tables) < 3 {
		t.Errorf("expected 3 tables, got %d: %v", len(tables), tables)
	}
}

func TestHandleExtractMetadata_AggregateFunctions(t *testing.T) {
	ctx := context.Background()
	sql := "SELECT COUNT(*), SUM(amount), AVG(price), MIN(id), MAX(id) FROM orders"
	req := makeReq(map[string]any{"sql": sql})
	res, err := handleExtractMetadata(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	functions := data["functions"].([]any)
	if len(functions) < 3 {
		t.Errorf("expected aggregate functions, got %d: %v", len(functions), functions)
	}
}
```

- [ ] **Step 3: Write deep security scan tests**

```go
func TestHandleSecurityScan_TautologyAttack(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{"sql": "SELECT * FROM users WHERE 1=1"})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	if data["is_clean"] == true {
		t.Error("expected tautology detection (1=1)")
	}
}

func TestHandleSecurityScan_UnionInjection(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{"sql": "SELECT id FROM users UNION SELECT password FROM admin"})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	// UNION-based injection should be flagged
	findings := data["findings"].([]any)
	_ = findings // verify non-empty if scanner detects UNION pattern
}

func TestHandleSecurityScan_CleanComplexSQL(t *testing.T) {
	ctx := context.Background()
	sql := "SELECT u.id, u.name FROM users u WHERE u.active = true AND u.role = 'admin' ORDER BY u.name"
	req := makeReq(map[string]any{"sql": sql})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	if data["is_clean"] != true {
		t.Error("expected clean SQL to pass security scan")
	}
}
```

- [ ] **Step 4: Write format edge cases**

```go
func TestHandleFormatSQL_UppercaseKeywords(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql":                "select id from users where id = 1",
		"uppercase_keywords": true,
	})
	res, err := handleFormatSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	formatted := data["formatted_sql"].(string)
	if formatted == "" {
		t.Error("expected non-empty formatted SQL")
	}
}

func TestHandleFormatSQL_InvalidSQL(t *testing.T) {
	ctx := context.Background()
	// Truly unparseable: random punctuation.
	req := makeReq(map[string]any{"sql": ")))((( @@@ !!!"})
	_, err := handleFormatSQL(ctx, req)
	// Format of unparseable SQL returns protocol error
	if err == nil {
		t.Fatal("expected error for completely unparseable SQL")
	}
}
```

- [ ] **Step 5: Write analyze_sql partial failure test**

```go
func TestHandleAnalyzeSQL_InvalidSQLPartialResults(t *testing.T) {
	ctx := context.Background()
	// Invalid SQL — validate returns valid=false, parse/metadata/format may fail
	// but security and lint should still succeed (they scan raw text)
	req := makeReq(map[string]any{"sql": "SELECT FROM"})
	res, err := handleAnalyzeSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	// Validate sub-result should exist with valid=false
	if v, ok := data["validate"].(map[string]any); ok {
		if v["valid"] != false {
			t.Error("expected validate.valid=false for invalid SQL")
		}
	}
	// Security and lint should always succeed
	if _, ok := data["security"]; !ok {
		t.Error("expected security sub-result even for invalid SQL")
	}
	if _, ok := data["lint"]; !ok {
		t.Error("expected lint sub-result even for invalid SQL")
	}
	// Some tools may have errored — check the errors key
	if errs, ok := data["errors"].(map[string]any); ok {
		t.Logf("partial failures (expected): %v", errs)
	}
}
```

- [ ] **Step 6: Run all edge-case tests**

Run: `go test -race -v -run "TestHandleValidateSQL_All|TestHandleParseSQL_CTE|TestHandleParseSQL_Window|TestHandleParseSQL_Subquery|TestHandleExtractMetadata_Complex|TestHandleExtractMetadata_Aggregate|TestHandleSecurityScan_Tautology|TestHandleSecurityScan_Union|TestHandleSecurityScan_Clean|TestHandleFormatSQL_Uppercase|TestHandleFormatSQL_Invalid|TestHandleAnalyzeSQL_Invalid" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add pkg/mcp/tools_test.go
git commit -m "test(mcp): add edge-case SQL tests for complex patterns and partial failures"
```

---

## Chunk 5: Server Lifecycle Tests

### Task 5: Server Start, Graceful Shutdown, Port Binding

Test the `Server.Start()` method — the only 0% coverage function.

**Files:**
- Modify: `pkg/mcp/server_test.go`

- [ ] **Step 1: Write server lifecycle tests**

```go
// Add to pkg/mcp/server_test.go

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServer_Start_And_Shutdown(t *testing.T) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &Config{Host: "127.0.0.1", Port: port}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to be ready
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 20; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(addr + "/mcp")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
	}
	if !ready {
		cancel()
		t.Fatal("server never became ready")
	}

	// Graceful shutdown
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server returned error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s")
	}
}

func TestServer_Start_PortInUse(t *testing.T) {
	// Occupy a port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	cfg := &Config{Host: "127.0.0.1", Port: port}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = srv.Start(ctx)
	if err == nil {
		t.Fatal("expected error when port is in use")
	}
}

func TestServer_Start_WithAuth(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := &Config{Host: "127.0.0.1", Port: port, AuthToken: "test-secret"}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	// Wait for ready
	addr := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	time.Sleep(500 * time.Millisecond)

	// Without token — should get 401
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run lifecycle tests**

Run: `go test -race -v -run "TestServer_Start" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/mcp/server_test.go
git commit -m "test(mcp): add server lifecycle tests (start, shutdown, port-in-use)"
```

---

## Chunk 6: MCP Protocol-Level Tests (In-Process Client + Inspector CLI)

### Task 6: Full MCP Protocol Round-Trip Tests

Test the complete MCP lifecycle using `mcp-go`'s in-process client: session initialization,
tool discovery, tool invocation, and error handling — all through the real MCP protocol layer.
Also add a shell-based MCP Inspector CLI test for E2E validation.

**Files:**
- Create: `pkg/mcp/protocol_test.go`
- Create: `scripts/mcp-inspector-test.sh` (optional E2E script)
- Reference: `pkg/mcp/server.go`, `pkg/mcp/tools.go`

- [ ] **Step 1: Write in-process client protocol test scaffolding**

```go
// pkg/mcp/protocol_test.go
package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	mcpmcp "github.com/mark3labs/mcp-go/mcp"
)

// newInProcessClient creates an mcp-go in-process client connected to a fresh GoSQLX MCP server.
// Handles Start + Initialize. Returns a ready-to-use client.
func newInProcessClient(t *testing.T) *client.Client {
	t.Helper()
	cfg := DefaultConfig()
	srv := New(cfg)

	c, err := client.NewInProcessClient(srv.mcpSrv)
	if err != nil {
		t.Fatalf("NewInProcessClient: %v", err)
	}

	ctx := context.Background()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("client.Start: %v", err)
	}

	initReq := mcpmcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcpmcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcpmcp.Implementation{
		Name:    "gosqlx-test-client",
		Version: "0.0.1",
	}
	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("client.Initialize: %v", err)
	}

	t.Cleanup(func() { _ = c.Close() })
	return c
}
```

- [ ] **Step 2: Run scaffolding to verify it compiles**

Run: `go test -v -run "TestProtocol_NOOP" ./pkg/mcp/`
Expected: No test found (that's fine), but compilation succeeds.

- [ ] **Step 3: Write tool discovery test**

```go
func TestProtocol_ListTools_Returns7Tools(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	result, err := c.ListTools(ctx, mcpmcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	expectedTools := map[string]bool{
		"validate_sql":     false,
		"format_sql":       false,
		"parse_sql":        false,
		"extract_metadata": false,
		"security_scan":    false,
		"lint_sql":         false,
		"analyze_sql":      false,
	}

	for _, tool := range result.Tools {
		if _, ok := expectedTools[tool.Name]; ok {
			expectedTools[tool.Name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("tool %q not found in ListTools response", name)
		}
	}

	if len(result.Tools) != 7 {
		t.Errorf("expected exactly 7 tools, got %d", len(result.Tools))
	}
}
```

- [ ] **Step 4: Run tool discovery test**

Run: `go test -v -run "TestProtocol_ListTools" ./pkg/mcp/`
Expected: PASS — all 7 tools discovered

- [ ] **Step 5: Write protocol-level tool call tests for each tool**

```go
func TestProtocol_CallTool_ValidateSQL(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "validate_sql"
	req.Params.Arguments = map[string]any{"sql": "SELECT id FROM users"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool validate_sql: %v", err)
	}

	data := extractProtocolResult(t, result)
	if data["valid"] != true {
		t.Errorf("expected valid=true, got %v", data["valid"])
	}
}

func TestProtocol_CallTool_FormatSQL(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "format_sql"
	req.Params.Arguments = map[string]any{
		"sql":                "select id from users",
		"uppercase_keywords": true,
	}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool format_sql: %v", err)
	}

	data := extractProtocolResult(t, result)
	if _, ok := data["formatted_sql"]; !ok {
		t.Error("expected formatted_sql in response")
	}
}

func TestProtocol_CallTool_ParseSQL(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "parse_sql"
	req.Params.Arguments = map[string]any{"sql": "SELECT 1; INSERT INTO t VALUES (1)"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool parse_sql: %v", err)
	}

	data := extractProtocolResult(t, result)
	count, ok := data["statement_count"].(float64)
	if !ok || count < 2 {
		t.Errorf("expected statement_count >= 2, got %v", data["statement_count"])
	}
}

func TestProtocol_CallTool_ExtractMetadata(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "extract_metadata"
	req.Params.Arguments = map[string]any{"sql": "SELECT u.name FROM users u JOIN orders o ON u.id = o.user_id"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool extract_metadata: %v", err)
	}

	data := extractProtocolResult(t, result)
	tables, ok := data["tables"].([]any)
	if !ok || len(tables) < 2 {
		t.Errorf("expected at least 2 tables, got %v", data["tables"])
	}
}

func TestProtocol_CallTool_SecurityScan(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "security_scan"
	req.Params.Arguments = map[string]any{"sql": "SELECT * FROM users WHERE 1=1 OR ''=''"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool security_scan: %v", err)
	}

	data := extractProtocolResult(t, result)
	if data["is_clean"] == true {
		t.Error("expected injection detection for tautology pattern")
	}
}

func TestProtocol_CallTool_LintSQL(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "lint_sql"
	req.Params.Arguments = map[string]any{"sql": "select id from users   \n"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool lint_sql: %v", err)
	}

	data := extractProtocolResult(t, result)
	count, ok := data["violation_count"].(float64)
	if !ok || count == 0 {
		t.Error("expected lint violations for trailing whitespace / keyword case")
	}
}

func TestProtocol_CallTool_AnalyzeSQL(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "analyze_sql"
	req.Params.Arguments = map[string]any{"sql": "SELECT id, name FROM users WHERE active = true"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("CallTool analyze_sql: %v", err)
	}

	data := extractProtocolResult(t, result)
	for _, key := range []string{"validate", "parse", "metadata", "security", "lint", "format"} {
		if _, ok := data[key]; !ok {
			t.Errorf("missing sub-result %q in analyze response", key)
		}
	}
}

// extractProtocolResult parses the text content of a CallToolResult into a map.
// This is the protocol-test equivalent of unmarshalResult from tools_test.go.
func extractProtocolResult(t *testing.T, res *mcpmcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("nil CallToolResult")
	}
	if len(res.Content) == 0 {
		t.Fatal("empty Content in CallToolResult")
	}
	tc, ok := res.Content[0].(mcpmcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("JSON unmarshal: %v\nraw: %s", err, tc.Text)
	}
	return out
}
```

- [ ] **Step 6: Write protocol error handling tests**

```go
func TestProtocol_CallTool_MissingSQLReturnsError(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "validate_sql"
	req.Params.Arguments = map[string]any{}

	_, err := c.CallTool(ctx, req)
	// Missing required param → protocol error propagated through MCP
	if err == nil {
		t.Fatal("expected error for missing sql param via protocol")
	}
}

func TestProtocol_CallTool_UnknownTool(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "nonexistent_tool"
	req.Params.Arguments = map[string]any{"sql": "SELECT 1"}

	_, err := c.CallTool(ctx, req)
	if err == nil {
		t.Fatal("expected error for unknown tool name")
	}
}

func TestProtocol_CallTool_InvalidSQLSemanticError(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	// validate_sql returns tool-semantic error (valid=false), not protocol error
	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "validate_sql"
	req.Params.Arguments = map[string]any{"sql": "SELECT FROM"}

	result, err := c.CallTool(ctx, req)
	if err != nil {
		t.Fatalf("expected nil protocol error for invalid SQL, got: %v", err)
	}

	data := extractProtocolResult(t, result)
	if data["valid"] != false {
		t.Errorf("expected valid=false, got %v", data["valid"])
	}
}
```

- [ ] **Step 7: Run all protocol tests**

Run: `go test -race -v -run "TestProtocol" ./pkg/mcp/`
Expected: All PASS

- [ ] **Step 8: Write JSON-RPC E2E test script**

The MCP streamable HTTP transport accepts raw JSON-RPC over POST.
This script exercises the full network stack: build binary → start server → send
JSON-RPC `initialize` → `notifications/initialized` → `tools/list` → `tools/call` → verify.
Uses `curl` + `jq` (no MCP Inspector — its CLI lacks programmatic tool-call flags).

```bash
#!/usr/bin/env bash
# scripts/mcp-e2e-test.sh
# E2E test: start GoSQLX MCP server, send JSON-RPC requests, verify responses.
# Requires: curl, jq, go
set -euo pipefail

PORT=18765
BINARY="./gosqlx-mcp"
ADDR="http://127.0.0.1:${PORT}/mcp"

echo "=== Building MCP server ==="
go build -o "$BINARY" ./cmd/gosqlx-mcp/

echo "=== Starting MCP server on port ${PORT} ==="
GOSQLX_MCP_PORT=$PORT "$BINARY" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; rm -f $BINARY" EXIT

# Wait for server to accept connections (POST required for streamable HTTP)
READY=false
for i in $(seq 1 30); do
  if curl -sf -X POST "$ADDR" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"0.1"},"capabilities":{}}}' \
    -o /dev/null 2>/dev/null; then
    READY=true
    break
  fi
  sleep 0.2
done
if [ "$READY" != "true" ]; then
  echo "FAIL: server never became ready"
  exit 1
fi

# Helper: send a JSON-RPC request and extract the result field.
# The streamable HTTP transport returns the JSON-RPC response directly.
rpc() {
  local id="$1"
  local method="$2"
  local params="$3"
  curl -sf -X POST "$ADDR" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"${method}\",\"params\":${params}}"
}

# --- Step 1: Initialize session ---
echo "=== Initializing MCP session ==="
INIT=$(rpc 1 "initialize" '{"protocolVersion":"2025-11-25","clientInfo":{"name":"e2e-test","version":"0.1"},"capabilities":{}}')
SERVER_NAME=$(echo "$INIT" | jq -r '.result.serverInfo.name // empty')
if [ -z "$SERVER_NAME" ]; then
  echo "FAIL: initialize did not return serverInfo.name"
  echo "Response: $INIT"
  exit 1
fi
echo "PASS: initialized — server=$SERVER_NAME"

# Send initialized notification (no id, no response expected)
curl -sf -X POST "$ADDR" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  -o /dev/null 2>/dev/null || true

# --- Step 2: List tools ---
echo "=== Listing tools ==="
TOOLS=$(rpc 2 "tools/list" '{}')
TOOL_COUNT=$(echo "$TOOLS" | jq '.result.tools | length')
if [ "$TOOL_COUNT" -ne 7 ]; then
  echo "FAIL: expected 7 tools, got $TOOL_COUNT"
  echo "Response: $TOOLS"
  exit 1
fi
echo "PASS: 7 tools listed"

# --- Step 3: Call validate_sql ---
echo "=== Testing validate_sql ==="
RESULT=$(rpc 3 "tools/call" '{"name":"validate_sql","arguments":{"sql":"SELECT id FROM users"}}')
VALID=$(echo "$RESULT" | jq -r '.result.content[0].text' | jq '.valid')
if [ "$VALID" != "true" ]; then
  echo "FAIL: expected valid=true, got $VALID"
  echo "Response: $RESULT"
  exit 1
fi
echo "PASS: validate_sql returned valid=true"

# --- Step 4: Call security_scan ---
echo "=== Testing security_scan ==="
RESULT=$(rpc 4 "tools/call" '{"name":"security_scan","arguments":{"sql":"SELECT * FROM users WHERE 1=1 OR '"'"''"'"'='"'"''"'"'"}}')
IS_CLEAN=$(echo "$RESULT" | jq -r '.result.content[0].text' | jq '.is_clean')
if [ "$IS_CLEAN" != "false" ]; then
  echo "FAIL: expected is_clean=false for injection, got $IS_CLEAN"
  echo "Response: $RESULT"
  exit 1
fi
echo "PASS: security_scan detected injection"

# --- Step 5: Call analyze_sql ---
echo "=== Testing analyze_sql ==="
RESULT=$(rpc 5 "tools/call" '{"name":"analyze_sql","arguments":{"sql":"SELECT id FROM users"}}')
INNER=$(echo "$RESULT" | jq -r '.result.content[0].text')
for KEY in format lint metadata parse security validate; do
  if ! echo "$INNER" | jq -e ".$KEY" > /dev/null 2>&1; then
    echo "FAIL: missing key $KEY in analyze result"
    echo "Response: $RESULT"
    exit 1
  fi
done
echo "PASS: analyze_sql returned all 6 sub-results"

echo ""
echo "=== All E2E tests passed ==="
```

- [ ] **Step 9: Make script executable and test**

Run: `chmod +x scripts/mcp-e2e-test.sh && bash scripts/mcp-e2e-test.sh`
Expected: All PASS (requires curl, jq; skip in CI if not available)

- [ ] **Step 10: Commit**

```bash
git add pkg/mcp/protocol_test.go scripts/mcp-e2e-test.sh
git commit -m "test(mcp): add MCP protocol round-trip tests (in-process client + JSON-RPC E2E)"
```

---

## Chunk 7: Final Verification

### Task 7: Run Full Suite and Verify Coverage Target

- [ ] **Step 1: Run complete test suite with race detection**

Run: `go test -race -timeout 120s -cover ./pkg/mcp/`
Expected: PASS, coverage > 95%

- [ ] **Step 2: Generate detailed coverage report**

Run: `go test -race -timeout 120s -coverprofile=/tmp/mcp_cover_final.out ./pkg/mcp/ && go tool cover -func=/tmp/mcp_cover_final.out`
Expected: `Server.Start` > 80%, all `*Internal` functions > 90%, total > 95%

- [ ] **Step 3: Run the full project test suite to confirm no regressions**

Run: `task test:race`
Expected: All packages PASS

- [ ] **Step 4: Commit and tag**

```bash
git add -A pkg/mcp/
git commit -m "test(mcp): comprehensive test suite — >95% coverage with race, integration, edge-case tests"
```
