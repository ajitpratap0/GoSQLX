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
	_ "embed"

	"github.com/mark3labs/mcp-go/mcp"
)

// This file wires the interactive UI ("MCP Apps" / OpenAI Apps SDK) layer.
//
// The same metadata serves two host families:
//
//   - MCP Apps hosts (extension io.modelcontextprotocol/ui, spec 2026-01-26),
//     e.g. Claude: they read _meta.ui.resourceUri on the tool and the
//     _meta.ui.* keys on the resource contents.
//   - ChatGPT (OpenAI Apps SDK): it understands the MCP Apps keys and also
//     the legacy openai/* aliases, which are set to the same values.
//
// Hosts that know neither simply ignore the _meta keys, so plain MCP clients
// (Cursor, Claude Code, MCP Inspector, ...) see no behavioural change.

// AnalysisWidgetURI is the ui:// resource URI of the analyze_sql report widget.
//
// The version suffix is part of the URI on purpose: ChatGPT caches templates
// by URI, so a breaking widget change should bump it (v2, v3, ...).
const AnalysisWidgetURI = "ui://gosqlx/analysis-v1.html"

// AppMIMEType is the MCP Apps HTML profile MIME type (ext-apps RESOURCE_MIME_TYPE).
// ChatGPT accepts it as the successor of the legacy "text/html+skybridge".
const AppMIMEType = "text/html;profile=mcp-app"

// analysisWidgetDescription is shown to the model by ChatGPT alongside the
// rendered widget so it does not need to re-describe what the user can see.
const analysisWidgetDescription = "Interactive GoSQLX analysis report: validity, statement types, " +
	"referenced tables/columns/functions, security findings by severity, lint violations, " +
	"and the formatted SQL with a copy button."

//go:embed widget/analysis.html
var analysisWidgetHTML string

// AnalysisWidgetHTML returns the embedded, self-contained HTML of the
// analyze_sql report widget (inline CSS/JS, no external requests).
func AnalysisWidgetHTML() string {
	return analysisWidgetHTML
}

// widgetResourceMeta is the _meta attached to the widget resource. An empty
// CSP is declared explicitly: the widget fetches nothing and loads no remote
// assets, and app submission requires a declared CSP.
func widgetResourceMeta() map[string]any {
	return map[string]any{
		"ui": map[string]any{
			"csp": map[string]any{
				"connectDomains":  []string{},
				"resourceDomains": []string{},
			},
			"prefersBorder": true,
			// The "Copy" button uses the async clipboard API when the host
			// grants it, and falls back to execCommand otherwise.
			"permissions": map[string]any{
				"clipboardWrite": map[string]any{},
			},
		},
		"openai/widgetCSP": map[string]any{
			"connect_domains":  []string{},
			"resource_domains": []string{},
		},
		"openai/widgetPrefersBorder": true,
		"openai/widgetDescription":   analysisWidgetDescription,
	}
}

// widgetToolMeta returns the tool-descriptor _meta that binds a tool to the
// analysis widget, in both the MCP Apps form and the OpenAI alias form.
func widgetToolMeta() map[string]any {
	return map[string]any{
		"ui": map[string]any{
			"resourceUri": AnalysisWidgetURI,
			"visibility":  []string{"model", "app"},
		},
		"openai/outputTemplate":   AnalysisWidgetURI,
		"openai/widgetAccessible": true,
	}
}

// toolMeta builds the _meta for a tool descriptor.
//
// invoking/invoked are ChatGPT status strings (kept well under 64 chars).
// When withWidget is true the analysis widget is attached. When the server
// runs without bearer auth the tool is advertised as needing no auth, which
// is what ChatGPT's connector dialog and app review expect.
func toolMeta(cfg *Config, invoking, invoked string, withWidget bool) *mcp.Meta {
	m := map[string]any{
		"openai/toolInvocation/invoking": invoking,
		"openai/toolInvocation/invoked":  invoked,
	}
	if cfg == nil || !cfg.AuthEnabled() {
		m["securitySchemes"] = []map[string]any{{"type": "noauth"}}
	}
	if withWidget {
		for k, v := range widgetToolMeta() {
			m[k] = v
		}
	}
	return mcp.NewMetaFromMap(m)
}

// withToolMeta is a ToolOption that sets the tool's _meta.
func withToolMeta(meta *mcp.Meta) mcp.ToolOption {
	return func(t *mcp.Tool) {
		t.Meta = meta
	}
}

// registerResources registers the UI widget resource.
func (s *Server) registerResources() {
	res := mcp.NewResource(
		AnalysisWidgetURI,
		"gosqlx_analysis_report",
		mcp.WithResourceDescription(analysisWidgetDescription),
		mcp.WithMIMEType(AppMIMEType),
	)
	res.Meta = mcp.NewMetaFromMap(widgetResourceMeta())

	s.mcpSrv.AddResource(res, handleReadAnalysisWidget)
}

// handleReadAnalysisWidget serves the widget HTML. resources/read must return
// exactly one content item for a UI resource.
func handleReadAnalysisWidget(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      AnalysisWidgetURI,
			MIMEType: AppMIMEType,
			Text:     analysisWidgetHTML,
			Meta:     widgetResourceMeta(),
		},
	}, nil
}
