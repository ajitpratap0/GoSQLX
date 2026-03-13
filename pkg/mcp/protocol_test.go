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

	"github.com/mark3labs/mcp-go/client"
	mcpmcp "github.com/mark3labs/mcp-go/mcp"
)

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

// --- Tool Discovery ---

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

// --- Tool Calls ---

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

// --- Error Handling ---

func TestProtocol_CallTool_MissingSQLReturnsError(t *testing.T) {
	c := newInProcessClient(t)
	ctx := context.Background()

	req := mcpmcp.CallToolRequest{}
	req.Params.Name = "validate_sql"
	req.Params.Arguments = map[string]any{}

	_, err := c.CallTool(ctx, req)
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
