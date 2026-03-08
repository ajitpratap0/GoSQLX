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
		count := data["statement_count"].(float64)
		if count < 1 {
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
