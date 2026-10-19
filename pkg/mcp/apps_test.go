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
	"reflect"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	mcpmcp "github.com/mark3labs/mcp-go/mcp"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// newAppsClient starts an in-process client against a server built from cfg
// and returns it together with the initialize result.
func newAppsClient(t *testing.T, cfg *Config) (*client.Client, *mcpmcp.InitializeResult) {
	t.Helper()
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
	initReq.Params.ClientInfo = mcpmcp.Implementation{Name: "apps-test", Version: "0.0.1"}
	res, err := c.Initialize(ctx, initReq)
	if err != nil {
		t.Fatalf("client.Initialize: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, res
}

// metaMap round-trips a value through JSON so nested _meta can be inspected
// as plain maps regardless of the concrete Go types used to build it.
func metaMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	return out
}

func mustMap(t *testing.T, v any, what string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected object, got %T (%v)", what, v, v)
	}
	return m
}

func mustEmptyList(t *testing.T, v any, what string) {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected array, got %T (%v)", what, v, v)
	}
	if len(l) != 0 {
		t.Errorf("%s: expected empty array, got %v", what, l)
	}
}

// checkWidgetResourceMeta asserts the dual MCP Apps / OpenAI resource metadata.
func checkWidgetResourceMeta(t *testing.T, meta map[string]any) {
	t.Helper()
	ui := mustMap(t, meta["ui"], "_meta.ui")
	csp := mustMap(t, ui["csp"], "_meta.ui.csp")
	mustEmptyList(t, csp["connectDomains"], "ui.csp.connectDomains")
	mustEmptyList(t, csp["resourceDomains"], "ui.csp.resourceDomains")
	if ui["prefersBorder"] != true {
		t.Errorf("ui.prefersBorder = %v, want true", ui["prefersBorder"])
	}
	perms := mustMap(t, ui["permissions"], "ui.permissions")
	if _, ok := perms["clipboardWrite"]; !ok {
		t.Error("ui.permissions.clipboardWrite missing")
	}
	oaCSP := mustMap(t, meta["openai/widgetCSP"], "openai/widgetCSP")
	mustEmptyList(t, oaCSP["connect_domains"], "openai/widgetCSP.connect_domains")
	mustEmptyList(t, oaCSP["resource_domains"], "openai/widgetCSP.resource_domains")
	if desc, ok := meta["openai/widgetDescription"].(string); !ok || desc == "" {
		t.Errorf("openai/widgetDescription missing or empty: %v", meta["openai/widgetDescription"])
	}
}

func TestApps_Initialize_InstructionsVersionCapabilities(t *testing.T) {
	_, res := newAppsClient(t, DefaultConfig())

	if res.ServerInfo.Version != gosqlx.Version {
		t.Errorf("server version = %q, want gosqlx.Version %q", res.ServerInfo.Version, gosqlx.Version)
	}
	if res.Capabilities.Resources == nil {
		t.Error("resources capability not advertised")
	}
	if res.Capabilities.Tools == nil {
		t.Error("tools capability not advertised")
	}
	for _, tool := range []string{"analyze_sql", "validate_sql", "format_sql", "parse_sql", "extract_metadata", "security_scan", "lint_sql"} {
		if !strings.Contains(res.Instructions, tool) {
			t.Errorf("instructions do not mention %s", tool)
		}
	}
}

func TestApps_ResourcesList_ExposesWidget(t *testing.T) {
	c, _ := newAppsClient(t, DefaultConfig())

	res, err := c.ListResources(context.Background(), mcpmcp.ListResourcesRequest{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(res.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res.Resources))
	}
	r := res.Resources[0]
	if r.URI != AnalysisWidgetURI {
		t.Errorf("URI = %q, want %q", r.URI, AnalysisWidgetURI)
	}
	if !strings.HasPrefix(r.URI, "ui://") {
		t.Errorf("widget URI must use the ui:// scheme, got %q", r.URI)
	}
	if r.MIMEType != AppMIMEType {
		t.Errorf("mimeType = %q, want %q", r.MIMEType, AppMIMEType)
	}
	if r.Meta == nil {
		t.Fatal("resource _meta missing from resources/list")
	}
	checkWidgetResourceMeta(t, metaMap(t, r.Meta))
}

func TestApps_ResourcesRead_ReturnsSelfContainedWidget(t *testing.T) {
	c, _ := newAppsClient(t, DefaultConfig())

	req := mcpmcp.ReadResourceRequest{}
	req.Params.URI = AnalysisWidgetURI
	res, err := c.ReadResource(context.Background(), req)
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("UI resource must return exactly one content item, got %d", len(res.Contents))
	}
	tc, ok := res.Contents[0].(mcpmcp.TextResourceContents)
	if !ok {
		t.Fatalf("expected TextResourceContents, got %T", res.Contents[0])
	}
	if tc.URI != AnalysisWidgetURI {
		t.Errorf("URI = %q, want %q", tc.URI, AnalysisWidgetURI)
	}
	if tc.MIMEType != AppMIMEType {
		t.Errorf("mimeType = %q, want %q", tc.MIMEType, AppMIMEType)
	}
	if tc.Text != AnalysisWidgetHTML() {
		t.Error("resource text differs from embedded widget HTML")
	}
	checkWidgetResourceMeta(t, metaMap(t, tc.Meta))

	lower := strings.ToLower(tc.Text)
	if !strings.HasPrefix(lower, "<!doctype html>") {
		t.Error("widget must be an HTML5 document")
	}
	// Self-contained: the declared CSP has no domains, so nothing remote may load.
	for _, forbidden := range []string{
		`src="http`, `src='http`, `href="http`, `href='http`, "@import", "fetch(", "xmlhttprequest", "innerhtml",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("widget HTML contains %q; it must be self-contained and render via textContent", forbidden)
		}
	}
	// The widget must speak the MCP Apps bridge.
	for _, want := range []string{"ui/initialize", "ui/notifications/initialized", "ui/notifications/tool-result", "structuredContent"} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("widget HTML does not reference %q", want)
		}
	}
}

func TestApps_ToolsList_MetaAndAnnotations(t *testing.T) {
	tests := []struct {
		name       string
		authToken  string
		wantNoAuth bool
	}{
		{name: "no auth advertises noauth security scheme", authToken: "", wantNoAuth: true},
		{name: "bearer auth omits noauth security scheme", authToken: "secret", wantNoAuth: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AuthToken = tt.authToken
			c, _ := newAppsClient(t, cfg)

			res, err := c.ListTools(context.Background(), mcpmcp.ListToolsRequest{})
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			if len(res.Tools) != 7 {
				t.Fatalf("expected 7 tools, got %d", len(res.Tools))
			}
			for _, tool := range res.Tools {
				a := tool.Annotations
				if a.ReadOnlyHint == nil || !*a.ReadOnlyHint {
					t.Errorf("%s: readOnlyHint must be true", tool.Name)
				}
				if a.DestructiveHint == nil || *a.DestructiveHint {
					t.Errorf("%s: destructiveHint must be false", tool.Name)
				}
				if a.OpenWorldHint == nil || *a.OpenWorldHint {
					t.Errorf("%s: openWorldHint must be false", tool.Name)
				}
				if a.Title == "" {
					t.Errorf("%s: title annotation missing", tool.Name)
				}
				if tool.Meta == nil {
					t.Fatalf("%s: _meta missing", tool.Name)
				}
				meta := metaMap(t, tool.Meta)

				for _, k := range []string{"openai/toolInvocation/invoking", "openai/toolInvocation/invoked"} {
					s, ok := meta[k].(string)
					if !ok || s == "" || len([]rune(s)) > 64 {
						t.Errorf("%s: %s = %v, want non-empty string <= 64 chars", tool.Name, k, meta[k])
					}
				}

				schemes, hasSchemes := meta["securitySchemes"]
				if tt.wantNoAuth {
					list, ok := schemes.([]any)
					if !ok || len(list) != 1 {
						t.Fatalf("%s: securitySchemes = %v, want one noauth entry", tool.Name, schemes)
					}
					if mustMap(t, list[0], "securitySchemes[0]")["type"] != "noauth" {
						t.Errorf("%s: securitySchemes[0].type != noauth", tool.Name)
					}
				} else if hasSchemes {
					t.Errorf("%s: securitySchemes must be omitted when bearer auth is enabled", tool.Name)
				}

				_, hasTemplate := meta["openai/outputTemplate"]
				_, hasUI := meta["ui"]
				if tool.Name != "analyze_sql" {
					if hasTemplate || hasUI {
						t.Errorf("%s: only analyze_sql should be bound to the widget", tool.Name)
					}
					continue
				}
				ui := mustMap(t, meta["ui"], "analyze_sql _meta.ui")
				if ui["resourceUri"] != AnalysisWidgetURI {
					t.Errorf("analyze_sql ui.resourceUri = %v, want %q", ui["resourceUri"], AnalysisWidgetURI)
				}
				if meta["openai/outputTemplate"] != AnalysisWidgetURI {
					t.Errorf("analyze_sql openai/outputTemplate = %v, want %q", meta["openai/outputTemplate"], AnalysisWidgetURI)
				}
				if meta["openai/widgetAccessible"] != true {
					t.Errorf("analyze_sql openai/widgetAccessible = %v, want true", meta["openai/widgetAccessible"])
				}
				if _, deprecated := meta["ui/resourceUri"]; deprecated {
					t.Error("analyze_sql uses deprecated flat ui/resourceUri key")
				}
			}
		})
	}
}

func TestApps_ToolsList_ValidateDialectEnum(t *testing.T) {
	c, _ := newAppsClient(t, DefaultConfig())
	res, err := c.ListTools(context.Background(), mcpmcp.ListToolsRequest{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name != "validate_sql" {
			continue
		}
		dialect := mustMap(t, tool.InputSchema.Properties["dialect"], "dialect schema")
		enum, ok := dialect["enum"].([]any)
		if !ok {
			b, _ := json.Marshal(dialect["enum"])
			if err := json.Unmarshal(b, &enum); err != nil {
				t.Fatalf("dialect enum has unexpected type %T", dialect["enum"])
			}
		}
		got := map[string]bool{}
		for _, v := range enum {
			s, ok := v.(string)
			if !ok {
				t.Fatalf("enum value %v is %T, want string", v, v)
			}
			got[s] = true
		}
		for _, want := range []string{"generic", "postgresql", "mysql", "mariadb", "sqlserver", "oracle", "sqlite", "snowflake", "clickhouse"} {
			if !got[want] {
				t.Errorf("dialect enum missing %q", want)
			}
		}
		return
	}
	t.Fatal("validate_sql not found")
}

func TestValidateSQLInternal_AllAdvertisedDialects(t *testing.T) {
	for _, d := range supportedDialects {
		t.Run(d, func(t *testing.T) {
			res, err := validateSQLInternal("SELECT id FROM users WHERE id = 1", d)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res["valid"] != true {
				t.Errorf("dialect %q: valid = %v, error = %v", d, res["valid"], res["error"])
			}
		})
	}
}

func TestApps_CallTool_StructuredContentMatchesText(t *testing.T) {
	c, _ := newAppsClient(t, DefaultConfig())
	const q = "SELECT u.id, COUNT(o.id) FROM users u JOIN orders o ON o.user_id = u.id WHERE u.name = 'x' OR 1=1 GROUP BY u.id"

	tests := []struct {
		tool string
		args map[string]any
	}{
		{"validate_sql", map[string]any{"sql": q}},
		{"validate_sql", map[string]any{"sql": "SELEC broken", "dialect": "postgresql"}},
		{"format_sql", map[string]any{"sql": q, "uppercase_keywords": true}},
		{"parse_sql", map[string]any{"sql": q}},
		{"extract_metadata", map[string]any{"sql": q}},
		{"security_scan", map[string]any{"sql": q}},
		{"lint_sql", map[string]any{"sql": q}},
		{"analyze_sql", map[string]any{"sql": q}},
		{"analyze_sql", map[string]any{"sql": "SELEC broken"}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			req := mcpmcp.CallToolRequest{}
			req.Params.Name = tt.tool
			req.Params.Arguments = tt.args
			res, err := c.CallTool(context.Background(), req)
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected tool error: %+v", res.Content)
			}
			if res.StructuredContent == nil {
				t.Fatal("structuredContent missing")
			}
			if len(res.Content) != 1 {
				t.Fatalf("expected exactly 1 content item, got %d", len(res.Content))
			}
			tc, ok := res.Content[0].(mcpmcp.TextContent)
			if !ok {
				t.Fatalf("expected TextContent, got %T", res.Content[0])
			}
			var fromText any
			if err := json.Unmarshal([]byte(tc.Text), &fromText); err != nil {
				t.Fatalf("text content is not JSON: %v", err)
			}
			fromStructured := metaMap(t, res.StructuredContent)
			if !reflect.DeepEqual(fromText, any(fromStructured)) {
				t.Errorf("structuredContent != text JSON\ntext:       %s\nstructured: %v", tc.Text, fromStructured)
			}
		})
	}
}

// TestToolResult_TextIsByteIdentical guards backward compatibility: the text
// content must stay exactly what json.Marshal produced before structured
// content was added.
func TestToolResult_TextIsByteIdentical(t *testing.T) {
	data := map[string]any{"valid": true, "dialect": "postgresql", "n": 3, "list": []string{"a", "b"}}
	want, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, err := toolResult(data)
	if err != nil {
		t.Fatalf("toolResult: %v", err)
	}
	tc, ok := res.Content[0].(mcpmcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	if tc.Text != string(want) {
		t.Errorf("text = %s, want %s", tc.Text, want)
	}
	if tc.Type != "text" {
		t.Errorf("content type = %q, want text", tc.Type)
	}
	sc, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structuredContent is %T, want map[string]any", res.StructuredContent)
	}
	if !reflect.DeepEqual(sc, data) {
		t.Errorf("structuredContent = %v, want %v", sc, data)
	}
}

func TestServer_ToolCount(t *testing.T) {
	if got := New(DefaultConfig()).ToolCount(); got != 7 {
		t.Errorf("ToolCount() = %d, want 7", got)
	}
}
