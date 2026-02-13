package lsp

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Diagnostics (via didOpen → publishDiagnostics)
// ---------------------------------------------------------------------------

func TestFunctional_Diagnostics_ValidSQL_NoDiagnostics(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"simple select", "SELECT 1"},
		{"select from table", "SELECT * FROM users"},
		{"insert", "INSERT INTO users (name) VALUES ('a')"},
		{"update", "UPDATE users SET name = 'b' WHERE id = 1"},
		{"delete", "DELETE FROM users WHERE id = 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			openDoc(t, server, tt.sql)

			diags := extractPublishedDiagnostics(t, mock.output.String())
			if len(diags) != 0 {
				t.Errorf("expected 0 diagnostics, got %d: %v", len(diags), diags)
			}
		})
	}
}

func TestFunctional_Diagnostics_InvalidSQL_ReturnErrors(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		minDiags      int
		wantSubstring string // at least one diagnostic message should contain this
	}{
		{"missing table", "SELECT * FROM", 1, ""},
		{"garbage", "XYZZY BOGUS", 1, ""},
		{"unterminated", "SELECT * FROM users WHERE", 1, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReadWriter()
			logger := log.New(io.Discard, "", 0)
			server := NewServer(mock.input, mock.output, logger)

			openDoc(t, server, tt.sql)

			diags := extractPublishedDiagnostics(t, mock.output.String())
			if len(diags) < tt.minDiags {
				t.Errorf("expected >= %d diagnostics, got %d", tt.minDiags, len(diags))
			}
			if tt.wantSubstring != "" {
				found := false
				for _, d := range diags {
					if strings.Contains(d.Message, tt.wantSubstring) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no diagnostic contains %q", tt.wantSubstring)
				}
			}
		})
	}
}

func TestFunctional_Diagnostics_MultiError_Recovery(t *testing.T) {
	// Two bad statements separated by semicolons should produce ≥2 diagnostics
	// thanks to ParseWithRecovery.
	sql := "SELECT * FROM; DELETE FROM"
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	openDoc(t, server, sql)

	diags := extractPublishedDiagnostics(t, mock.output.String())
	if len(diags) < 2 {
		t.Errorf("expected ≥2 diagnostics from multi-error recovery, got %d", len(diags))
	}
}

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------

func TestFunctional_Completion_Keywords(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	server.Documents().Open("file:///test.sql", "sql", 1, "SEL")

	params := CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			Position:     Position{Line: 0, Character: 3},
		},
	}
	raw, _ := json.Marshal(params)
	result, err := server.handler.HandleRequest("textDocument/completion", raw)
	if err != nil {
		t.Fatal(err)
	}

	list := result.(*CompletionList)
	if len(list.Items) == 0 {
		t.Fatal("expected completion items for 'SEL'")
	}

	foundSelect := false
	for _, item := range list.Items {
		if item.Label == "SELECT" {
			foundSelect = true
			break
		}
	}
	if !foundSelect {
		t.Error("expected SELECT in completion results")
	}
}

func TestFunctional_Completion_EmptyPrefix(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	server.Documents().Open("file:///test.sql", "sql", 1, "")

	params := CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			Position:     Position{Line: 0, Character: 0},
		},
	}
	raw, _ := json.Marshal(params)
	result, err := server.handler.HandleRequest("textDocument/completion", raw)
	if err != nil {
		t.Fatal(err)
	}

	list := result.(*CompletionList)
	// Should return many items (keywords + snippets) capped at 100
	if len(list.Items) < 50 {
		t.Errorf("expected ≥50 completion items with empty prefix, got %d", len(list.Items))
	}
}

// ---------------------------------------------------------------------------
// Hover
// ---------------------------------------------------------------------------

func TestFunctional_Hover_KnownKeyword(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Position:     Position{Line: 0, Character: 2}, // inside "SELECT"
	}
	raw, _ := json.Marshal(params)
	result, err := server.handler.HandleRequest("textDocument/hover", raw)
	if err != nil {
		t.Fatal(err)
	}

	hover := result.(*Hover)
	if hover.Contents.Value == "" {
		t.Error("expected hover documentation for SELECT")
	}
	if !strings.Contains(hover.Contents.Value, "SELECT") {
		t.Error("hover docs should mention SELECT")
	}
}

func TestFunctional_Hover_UnknownWord(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT xyzzy FROM users")

	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Position:     Position{Line: 0, Character: 8}, // inside "xyzzy"
	}
	raw, _ := json.Marshal(params)
	result, err := server.handler.HandleRequest("textDocument/hover", raw)
	if err != nil {
		t.Fatal(err)
	}

	hover := result.(*Hover)
	if hover.Contents.Value != "" {
		t.Error("expected empty hover for unknown word")
	}
}

// ---------------------------------------------------------------------------
// Initialize
// ---------------------------------------------------------------------------

func TestFunctional_Initialize(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	params := InitializeParams{RootURI: "file:///workspace"}
	raw, _ := json.Marshal(params)
	result, err := server.handler.HandleRequest("initialize", raw)
	if err != nil {
		t.Fatal(err)
	}

	initResult := result.(*InitializeResult)
	if initResult.ServerInfo == nil || initResult.ServerInfo.Name != "gosqlx-lsp" {
		t.Error("expected server info with name gosqlx-lsp")
	}
	if !initResult.Capabilities.HoverProvider {
		t.Error("expected hover provider capability")
	}
	if initResult.Capabilities.CompletionProvider == nil {
		t.Error("expected completion provider capability")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func openDoc(t *testing.T, server *Server, sql string) {
	t.Helper()
	params := DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        "file:///test.sql",
			LanguageID: "sql",
			Version:    1,
			Text:       sql,
		},
	}
	raw, _ := json.Marshal(params)
	server.handler.HandleNotification("textDocument/didOpen", raw)
}

func extractPublishedDiagnostics(t *testing.T, output string) []Diagnostic {
	t.Helper()
	// Output may contain multiple LSP messages; find the publishDiagnostics one.
	// Each message is prefixed with Content-Length header.
	parts := strings.Split(output, "Content-Length:")
	for _, part := range parts {
		if !strings.Contains(part, "publishDiagnostics") {
			continue
		}
		// Find the JSON body
		idx := strings.Index(part, "{")
		if idx < 0 {
			continue
		}
		body := part[idx:]
		// May have trailing data; find balanced braces
		var msg struct {
			Params struct {
				Diagnostics []Diagnostic `json:"diagnostics"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(body), &msg); err != nil {
			// Try to find end of JSON
			depth := 0
			end := 0
			for i, c := range body {
				if c == '{' {
					depth++
				} else if c == '}' {
					depth--
					if depth == 0 {
						end = i + 1
						break
					}
				}
			}
			if end > 0 {
				_ = json.Unmarshal([]byte(body[:end]), &msg)
			}
		}
		return msg.Params.Diagnostics
	}
	return nil
}
