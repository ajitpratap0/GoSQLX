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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeReq builds a minimal CallToolRequest with the given string params.
func makeReq(params map[string]any) mcpmcp.CallToolRequest {
	req := mcpmcp.CallToolRequest{}
	req.Params.Arguments = params
	return req
}

// unmarshalResult parses the text content of a CallToolResult as JSON.
func unmarshalResult(t *testing.T, res *mcpmcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("expected non-nil CallToolResult")
	}
	if len(res.Content) == 0 {
		t.Fatal("expected at least one content item in CallToolResult")
	}
	// Content[0] is a TextContent whose Text field holds the JSON payload.
	textContent, ok := res.Content[0].(mcpmcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("failed to unmarshal result JSON: %v\nraw: %s", err, textContent.Text)
	}
	return out
}

// ---------------------------------------------------------------------------
// handleValidateSQL
// ---------------------------------------------------------------------------

func TestHandleValidateSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns valid=true", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT id FROM users"})
		res, err := handleValidateSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		valid, ok := data["valid"].(bool)
		if !ok || !valid {
			t.Errorf("expected valid=true, got %v", data["valid"])
		}
	})

	t.Run("invalid SQL returns valid=false without protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT FROM"})
		res, err := handleValidateSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected protocol error for invalid SQL: %v", err)
		}
		data := unmarshalResult(t, res)
		valid, ok := data["valid"].(bool)
		if !ok || valid {
			t.Errorf("expected valid=false for invalid SQL, got %v", data["valid"])
		}
		if _, hasErr := data["error"]; !hasErr {
			t.Error("expected 'error' key in result for invalid SQL")
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleValidateSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleValidateSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})

	t.Run("valid SQL with dialect", func(t *testing.T) {
		req := makeReq(map[string]any{
			"sql":     "SELECT id FROM users",
			"dialect": "postgresql",
		})
		res, err := handleValidateSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		valid, ok := data["valid"].(bool)
		if !ok || !valid {
			t.Errorf("expected valid=true, got %v", data["valid"])
		}
		if data["dialect"] != "postgresql" {
			t.Errorf("expected dialect=postgresql, got %v", data["dialect"])
		}
	})
}

// ---------------------------------------------------------------------------
// handleFormatSQL
// ---------------------------------------------------------------------------

func TestHandleFormatSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns formatted_sql", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "select id from users"})
		res, err := handleFormatSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		if _, ok := data["formatted_sql"]; !ok {
			t.Error("expected 'formatted_sql' key in result")
		}
	})

	t.Run("custom options reflected in result", func(t *testing.T) {
		req := makeReq(map[string]any{
			"sql":                "select id from users",
			"indent_size":        4,
			"uppercase_keywords": true,
			"add_semicolon":      true,
		})
		res, err := handleFormatSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		if _, ok := data["formatted_sql"]; !ok {
			t.Error("expected 'formatted_sql' key in result")
		}
		opts, ok := data["options"].(map[string]any)
		if !ok {
			t.Fatal("expected 'options' map in result")
		}
		if opts["indent_size"] != float64(4) {
			t.Errorf("expected indent_size=4, got %v", opts["indent_size"])
		}
		if opts["uppercase_keywords"] != true {
			t.Errorf("expected uppercase_keywords=true, got %v", opts["uppercase_keywords"])
		}
		if opts["add_semicolon"] != true {
			t.Errorf("expected add_semicolon=true, got %v", opts["add_semicolon"])
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleFormatSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleFormatSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// handleParseSQL
// ---------------------------------------------------------------------------

func TestHandleParseSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns statement info", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT id FROM users; SELECT name FROM orders"})
		res, err := handleParseSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		if _, ok := data["statement_count"]; !ok {
			t.Error("expected 'statement_count' key in result")
		}
		if _, ok := data["statement_types"]; !ok {
			t.Error("expected 'statement_types' key in result")
		}
		count, ok := data["statement_count"].(float64)
		if !ok || count < 1 {
			t.Errorf("expected at least 1 statement, got %v", count)
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleParseSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleParseSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// handleExtractMetadata
// ---------------------------------------------------------------------------

func TestHandleExtractMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns metadata keys", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT u.id, o.name FROM users u JOIN orders o ON u.id = o.user_id"})
		res, err := handleExtractMetadata(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		for _, key := range []string{"tables", "columns", "functions"} {
			if _, ok := data[key]; !ok {
				t.Errorf("expected key %q in result", key)
			}
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleExtractMetadata(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleExtractMetadata(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// handleSecurityScan
// ---------------------------------------------------------------------------

func TestHandleSecurityScan(t *testing.T) {
	ctx := context.Background()

	t.Run("clean SQL returns is_clean=true", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT id FROM users WHERE id = 42"})
		res, err := handleSecurityScan(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		for _, key := range []string{"is_clean", "has_critical", "has_high", "total_count",
			"critical_count", "high_count", "medium_count", "low_count", "findings"} {
			if _, ok := data[key]; !ok {
				t.Errorf("expected key %q in result", key)
			}
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleSecurityScan(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleSecurityScan(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// handleLintSQL
// ---------------------------------------------------------------------------

func TestHandleLintSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns lint result", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT id FROM users"})
		res, err := handleLintSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		if _, ok := data["violation_count"]; !ok {
			t.Error("expected 'violation_count' key in result")
		}
		if _, ok := data["violations"]; !ok {
			t.Error("expected 'violations' key in result")
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleLintSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleLintSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// handleAnalyzeSQL
// ---------------------------------------------------------------------------

func TestHandleAnalyzeSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("valid SQL returns all six analysis keys", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT id, name FROM users WHERE id = 1"})
		res, err := handleAnalyzeSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)

		expectedKeys := []string{"validate", "parse", "metadata", "security", "lint", "format"}
		for _, key := range expectedKeys {
			if _, ok := data[key]; !ok {
				t.Errorf("expected key %q in analyze result", key)
			}
		}
	})

	t.Run("validate sub-result contains valid field", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "SELECT 1"})
		res, err := handleAnalyzeSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		validateData, ok := data["validate"].(map[string]any)
		if !ok {
			t.Fatal("expected 'validate' sub-result to be a map")
		}
		if _, ok := validateData["valid"]; !ok {
			t.Error("expected 'valid' field in validate sub-result")
		}
	})

	t.Run("format sub-result contains formatted_sql", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": "select id from users"})
		res, err := handleAnalyzeSQL(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data := unmarshalResult(t, res)
		formatData, ok := data["format"].(map[string]any)
		if !ok {
			t.Fatal("expected 'format' sub-result to be a map")
		}
		if _, ok := formatData["formatted_sql"]; !ok {
			t.Error("expected 'formatted_sql' field in format sub-result")
		}
	})

	t.Run("empty sql returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{"sql": ""})
		_, err := handleAnalyzeSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for empty sql, got nil")
		}
	})

	t.Run("missing sql param returns protocol error", func(t *testing.T) {
		req := makeReq(map[string]any{})
		_, err := handleAnalyzeSQL(ctx, req)
		if err == nil {
			t.Fatal("expected error for missing sql param, got nil")
		}
	})
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

func TestHandleValidateSQL_AllDialects(t *testing.T) {
	ctx := context.Background()
	dialects := []string{"generic", "mysql", "postgresql", "sqlite", "sqlserver", "oracle", "snowflake"}

	for _, dialect := range dialects {
		t.Run(dialect, func(t *testing.T) {
			req := makeReq(map[string]any{
				"sql":     "SELECT 1",
				"dialect": dialect,
			})
			res, err := handleValidateSQL(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error for dialect %s: %v", dialect, err)
			}
			data := unmarshalResult(t, res)
			valid, ok := data["valid"].(bool)
			if !ok || !valid {
				t.Errorf("expected valid=true for dialect %s, got %v", dialect, data["valid"])
			}
			if data["dialect"] != dialect {
				t.Errorf("expected dialect=%s, got %v", dialect, data["dialect"])
			}
		})
	}
}

func TestHandleParseSQL_CTE(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{"sql": "WITH cte AS (SELECT 1) SELECT * FROM cte"})
	res, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	count, ok := data["statement_count"].(float64)
	if !ok || count != 1 {
		t.Errorf("expected statement_count=1, got %v", data["statement_count"])
	}
	types, ok := data["statement_types"].([]any)
	if !ok || len(types) == 0 {
		t.Fatalf("expected non-empty statement_types, got %v", data["statement_types"])
	}
	if types[0] != "*ast.SelectStatement" {
		t.Errorf("expected *ast.SelectStatement, got %v", types[0])
	}
}

func TestHandleParseSQL_WindowFunction(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT ROW_NUMBER() OVER(PARTITION BY dept ORDER BY salary DESC) FROM employees",
	})
	res, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	count, ok := data["statement_count"].(float64)
	if !ok || count != 1 {
		t.Errorf("expected statement_count=1, got %v", data["statement_count"])
	}
	types, ok := data["statement_types"].([]any)
	if !ok || len(types) == 0 {
		t.Fatalf("expected non-empty statement_types, got %v", data["statement_types"])
	}
	if types[0] != "*ast.SelectStatement" {
		t.Errorf("expected *ast.SelectStatement, got %v", types[0])
	}
}

func TestHandleParseSQL_Subquery(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT * FROM (SELECT id FROM users) AS sub",
	})
	res, err := handleParseSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	count, ok := data["statement_count"].(float64)
	if !ok || count != 1 {
		t.Errorf("expected statement_count=1, got %v", data["statement_count"])
	}
}

func TestHandleExtractMetadata_ComplexJoin(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT a.id, b.name, c.value FROM alpha a JOIN beta b ON a.id = b.alpha_id JOIN gamma c ON b.id = c.beta_id",
	})
	res, err := handleExtractMetadata(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	tables, ok := data["tables"].([]any)
	if !ok {
		t.Fatalf("expected tables to be []any, got %T", data["tables"])
	}
	if len(tables) < 3 {
		t.Errorf("expected at least 3 tables, got %d: %v", len(tables), tables)
	}
	// Check that all three table names are present.
	tableSet := make(map[string]bool)
	for _, tbl := range tables {
		s, ok := tbl.(string)
		if !ok {
			t.Fatalf("expected table name to be string, got %T", tbl)
		}
		tableSet[s] = true
	}
	for _, expected := range []string{"alpha", "beta", "gamma"} {
		if !tableSet[expected] {
			t.Errorf("expected table %q in tables, got %v", expected, tables)
		}
	}
}

func TestHandleExtractMetadata_AggregateFunctions(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT COUNT(*), SUM(amount), AVG(price), MIN(id), MAX(id) FROM orders",
	})
	res, err := handleExtractMetadata(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	functions, ok := data["functions"].([]any)
	if !ok {
		t.Fatalf("expected functions to be []any, got %T", data["functions"])
	}
	fnSet := make(map[string]bool)
	for _, fn := range functions {
		s, ok := fn.(string)
		if !ok {
			t.Fatalf("expected function name to be string, got %T", fn)
		}
		fnSet[s] = true
	}
	for _, expected := range []string{"COUNT", "SUM", "AVG", "MIN", "MAX"} {
		if !fnSet[expected] {
			t.Errorf("expected function %q in functions, got %v", expected, functions)
		}
	}
}

func TestHandleSecurityScan_TautologyAttack(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT * FROM users WHERE 1=1",
	})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	isClean, ok := data["is_clean"].(bool)
	if !ok || isClean {
		t.Errorf("expected is_clean=false for tautology, got %v", data["is_clean"])
	}
	totalCount, ok := data["total_count"].(float64)
	if !ok || totalCount < 1 {
		t.Errorf("expected total_count >= 1, got %v", data["total_count"])
	}
	findings, ok := data["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatal("expected at least one finding for tautology attack")
	}
	f, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected finding to be map[string]any, got %T", findings[0])
	}
	if f["pattern"] != "TAUTOLOGY" {
		t.Errorf("expected pattern=TAUTOLOGY, got %v", f["pattern"])
	}
}

func TestHandleSecurityScan_UnionInjection(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT id FROM users UNION SELECT password FROM admins",
	})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	isClean, ok := data["is_clean"].(bool)
	if !ok || isClean {
		t.Errorf("expected is_clean=false for union injection, got %v", data["is_clean"])
	}
	totalCount, ok := data["total_count"].(float64)
	if !ok || totalCount < 1 {
		t.Errorf("expected total_count >= 1, got %v", data["total_count"])
	}
	findings, ok := data["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatal("expected at least one finding for union injection")
	}
	f, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected finding to be map[string]any, got %T", findings[0])
	}
	if f["pattern"] != "UNION_GENERIC" {
		t.Errorf("expected pattern=UNION_GENERIC, got %v", f["pattern"])
	}
}

func TestHandleSecurityScan_CleanComplexSQL(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY o.total DESC LIMIT 10",
	})
	res, err := handleSecurityScan(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	isClean, ok := data["is_clean"].(bool)
	if !ok || !isClean {
		t.Errorf("expected is_clean=true for legitimate query, got %v", data["is_clean"])
	}
	totalCount, ok := data["total_count"].(float64)
	if !ok || totalCount != 0 {
		t.Errorf("expected total_count=0, got %v", data["total_count"])
	}
}

func TestHandleFormatSQL_UppercaseKeywords(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql":                "select id from users where active = true",
		"uppercase_keywords": true,
	})
	res, err := handleFormatSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data := unmarshalResult(t, res)
	formatted, ok := data["formatted_sql"].(string)
	if !ok || formatted == "" {
		t.Fatal("expected non-empty formatted_sql")
	}
	opts, ok := data["options"].(map[string]any)
	if !ok {
		t.Fatal("expected 'options' map in result")
	}
	if opts["uppercase_keywords"] != true {
		t.Errorf("expected uppercase_keywords=true in options, got %v", opts["uppercase_keywords"])
	}
}

func TestHandleFormatSQL_InvalidSQL(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{
		"sql": ")))((( @@@ !!!",
	})
	_, err := handleFormatSQL(ctx, req)
	if err == nil {
		t.Fatal("expected error for unparseable SQL, got nil")
	}
}

func TestHandleAnalyzeSQL_InvalidSQLPartialResults(t *testing.T) {
	ctx := context.Background()
	req := makeReq(map[string]any{"sql": "SELECT FROM"})
	res, err := handleAnalyzeSQL(ctx, req)
	if err != nil {
		t.Fatalf("unexpected protocol error: %v", err)
	}
	data := unmarshalResult(t, res)

	// Validate should report valid=false (it returns a result, not an error).
	validateData, ok := data["validate"].(map[string]any)
	if !ok {
		t.Fatal("expected 'validate' sub-result to be a map")
	}
	valid, ok := validateData["valid"].(bool)
	if !ok || valid {
		t.Errorf("expected validate.valid=false for invalid SQL, got %v", validateData["valid"])
	}

	// Security should still succeed.
	securityData, ok := data["security"].(map[string]any)
	if !ok {
		t.Fatal("expected 'security' sub-result to be a map")
	}
	if _, ok := securityData["is_clean"]; !ok {
		t.Error("expected 'is_clean' key in security sub-result")
	}

	// Lint should still succeed.
	lintData, ok := data["lint"].(map[string]any)
	if !ok {
		t.Fatal("expected 'lint' sub-result to be a map")
	}
	if _, ok := lintData["violation_count"]; !ok {
		t.Error("expected 'violation_count' key in lint sub-result")
	}

	// Parse, metadata, and format should have errors since "SELECT FROM" fails to parse.
	errs, ok := data["errors"].(map[string]any)
	if !ok {
		t.Fatal("expected 'errors' map for failed sub-results")
	}
	for _, key := range []string{"parse", "metadata", "format"} {
		if _, ok := errs[key]; !ok {
			t.Errorf("expected error entry for %q in errors map", key)
		}
	}
}
