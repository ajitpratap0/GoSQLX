package lsp

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
	"time"
)

// mockReadWriter provides a mock for testing the LSP server
type mockReadWriter struct {
	input  *bytes.Buffer
	output *bytes.Buffer
}

func newMockReadWriter() *mockReadWriter {
	return &mockReadWriter{
		input:  &bytes.Buffer{},
		output: &bytes.Buffer{},
	}
}

func (m *mockReadWriter) Read(p []byte) (int, error) {
	return m.input.Read(p)
}

func (m *mockReadWriter) Write(p []byte) (int, error) {
	return m.output.Write(p)
}

func TestNewServer(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	if server == nil {
		t.Fatal("expected server to be created")
	}
	if server.documents == nil {
		t.Fatal("expected documents to be initialized")
	}
	if server.handler == nil {
		t.Fatal("expected handler to be initialized")
	}
}

func TestDocumentManager(t *testing.T) {
	dm := NewDocumentManager()

	// Test Open
	dm.Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	doc, ok := dm.Get("file:///test.sql")
	if !ok {
		t.Fatal("expected document to be found")
	}
	if doc.Content != "SELECT * FROM users" {
		t.Errorf("expected content 'SELECT * FROM users', got %q", doc.Content)
	}
	if doc.Version != 1 {
		t.Errorf("expected version 1, got %d", doc.Version)
	}

	// Test Update with full sync
	dm.Update("file:///test.sql", 2, []TextDocumentContentChangeEvent{
		{Text: "SELECT id FROM users"},
	})

	content, ok := dm.GetContent("file:///test.sql")
	if !ok {
		t.Fatal("expected content to be found")
	}
	if content != "SELECT id FROM users" {
		t.Errorf("expected updated content, got %q", content)
	}

	// Test Close
	dm.Close("file:///test.sql")
	_, ok = dm.Get("file:///test.sql")
	if ok {
		t.Fatal("expected document to be closed")
	}
}

func TestDocumentGetWordAtPosition(t *testing.T) {
	doc := &Document{
		Content: "SELECT id FROM users WHERE active = true",
		Lines:   []string{"SELECT id FROM users WHERE active = true"},
	}

	tests := []struct {
		pos      Position
		expected string
	}{
		{Position{Line: 0, Character: 0}, "SELECT"},
		{Position{Line: 0, Character: 3}, "SELECT"},
		{Position{Line: 0, Character: 7}, "id"},
		{Position{Line: 0, Character: 14}, "FROM"},
		{Position{Line: 0, Character: 19}, "users"},
		{Position{Line: 0, Character: 25}, "WHERE"},
		{Position{Line: 0, Character: 31}, "active"},
		{Position{Line: 0, Character: 37}, "true"}, // "true" starts at 37: "SELECT id FROM users WHERE active = true"
	}

	for _, tt := range tests {
		word := doc.GetWordAtPosition(tt.pos)
		if word != tt.expected {
			t.Errorf("GetWordAtPosition(%v) = %q, want %q", tt.pos, word, tt.expected)
		}
	}
}

func TestHandler_Initialize(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	initParams := InitializeParams{
		ProcessID:    1234,
		RootURI:      "file:///workspace",
		Capabilities: ClientCapabilities{},
	}

	paramsJSON, _ := json.Marshal(initParams)
	result, err := server.handler.HandleRequest("initialize", paramsJSON)
	if err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	initResult, ok := result.(*InitializeResult)
	if !ok {
		t.Fatalf("expected InitializeResult, got %T", result)
	}

	if initResult.ServerInfo.Name != "gosqlx-lsp" {
		t.Errorf("expected server name 'gosqlx-lsp', got %q", initResult.ServerInfo.Name)
	}

	if !initResult.Capabilities.HoverProvider {
		t.Error("expected hover provider to be enabled")
	}

	if !initResult.Capabilities.DocumentFormattingProvider {
		t.Error("expected formatting provider to be enabled")
	}
}

func TestHandler_Shutdown(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	result, err := server.handler.HandleRequest("shutdown", nil)
	if err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected shutdown result")
	}
}

func TestHandler_DidOpen(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	didOpenParams := DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        "file:///test.sql",
			LanguageID: "sql",
			Version:    1,
			Text:       "SELECT * FROM users",
		},
	}

	paramsJSON, _ := json.Marshal(didOpenParams)
	server.handler.HandleNotification("textDocument/didOpen", paramsJSON)

	// Give time for async processing
	time.Sleep(10 * time.Millisecond)

	// Verify document was opened
	content, ok := server.Documents().GetContent("file:///test.sql")
	if !ok {
		t.Fatal("expected document to be opened")
	}
	if content != "SELECT * FROM users" {
		t.Errorf("expected content 'SELECT * FROM users', got %q", content)
	}
}

func TestHandler_DidChange(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// First open a document
	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	// Then change it
	didChangeParams := DidChangeTextDocumentParams{
		TextDocument: VersionedTextDocumentIdentifier{
			TextDocumentIdentifier: TextDocumentIdentifier{URI: "file:///test.sql"},
			Version:                2,
		},
		ContentChanges: []TextDocumentContentChangeEvent{
			{Text: "SELECT id, name FROM users WHERE active = true"},
		},
	}

	paramsJSON, _ := json.Marshal(didChangeParams)
	server.handler.HandleNotification("textDocument/didChange", paramsJSON)

	// Verify document was updated
	content, ok := server.Documents().GetContent("file:///test.sql")
	if !ok {
		t.Fatal("expected document to be found")
	}
	if content != "SELECT id, name FROM users WHERE active = true" {
		t.Errorf("expected updated content, got %q", content)
	}
}

func TestHandler_Completion(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Open a document
	server.Documents().Open("file:///test.sql", "sql", 1, "SEL")

	completionParams := CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			Position:     Position{Line: 0, Character: 3},
		},
	}

	paramsJSON, _ := json.Marshal(completionParams)
	result, err := server.handler.HandleRequest("textDocument/completion", paramsJSON)
	if err != nil {
		t.Fatalf("completion failed: %v", err)
	}

	completionList, ok := result.(*CompletionList)
	if !ok {
		t.Fatalf("expected CompletionList, got %T", result)
	}

	// Check that SELECT is in the completions
	found := false
	for _, item := range completionList.Items {
		if item.Label == "SELECT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SELECT in completion items")
	}
}

func TestHandler_Hover(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Open a document
	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	hoverParams := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Position:     Position{Line: 0, Character: 3}, // On SELECT
	}

	paramsJSON, _ := json.Marshal(hoverParams)
	result, err := server.handler.HandleRequest("textDocument/hover", paramsJSON)
	if err != nil {
		t.Fatalf("hover failed: %v", err)
	}

	hover, ok := result.(*Hover)
	if !ok {
		t.Fatalf("expected Hover, got %T", result)
	}

	if !strings.Contains(hover.Contents.Value, "SELECT") {
		t.Errorf("expected hover content to contain SELECT info, got %q", hover.Contents.Value)
	}
}

func TestHandler_Formatting(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Open a document with messy SQL
	server.Documents().Open("file:///test.sql", "sql", 1, "   SELECT    *   FROM   users  ")

	formatParams := DocumentFormattingParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Options: FormattingOptions{
			TabSize:      2,
			InsertSpaces: true,
		},
	}

	paramsJSON, _ := json.Marshal(formatParams)
	result, err := server.handler.HandleRequest("textDocument/formatting", paramsJSON)
	if err != nil {
		t.Fatalf("formatting failed: %v", err)
	}

	edits, ok := result.([]TextEdit)
	if !ok {
		t.Fatalf("expected []TextEdit, got %T", result)
	}

	if len(edits) == 0 {
		t.Log("No formatting changes needed")
	} else {
		t.Logf("Formatting produced %d edits", len(edits))
	}
}

func TestHandler_MethodNotFound(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	_, err := server.handler.HandleRequest("unknown/method", nil)
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
	if !strings.Contains(err.Error(), "method not found") {
		t.Errorf("expected 'method not found' error, got %v", err)
	}
}

func TestPositionToOffset(t *testing.T) {
	lines := []string{
		"SELECT *",
		"FROM users",
		"WHERE id = 1",
	}

	tests := []struct {
		pos      Position
		expected int
	}{
		{Position{Line: 0, Character: 0}, 0},
		{Position{Line: 0, Character: 6}, 6},
		{Position{Line: 1, Character: 0}, 9}, // After "SELECT *\n"
		{Position{Line: 1, Character: 4}, 13},
		{Position{Line: 2, Character: 0}, 20}, // After "FROM users\n"
	}

	for _, tt := range tests {
		offset := positionToOffset(lines, tt.pos)
		if offset != tt.expected {
			t.Errorf("positionToOffset(%v) = %d, want %d", tt.pos, offset, tt.expected)
		}
	}
}

func TestKeywordDocumentation(t *testing.T) {
	// Test that we have documentation for common keywords
	keywords := []string{
		"SELECT", "FROM", "WHERE", "JOIN", "INSERT", "UPDATE", "DELETE",
		"CREATE", "DROP", "ALTER", "GROUP", "ORDER", "HAVING", "LIMIT",
	}

	for _, kw := range keywords {
		doc := getKeywordDocumentation(kw)
		if doc == "" {
			t.Errorf("missing documentation for keyword %s", kw)
		}
	}
}

func TestExtractPositionFromError(t *testing.T) {
	content := "SELECT *\nFROM users\nWHERE id = 1"

	tests := []struct {
		name         string
		errMsg       string
		expectedLine int
		expectedChar int
	}{
		{
			name:         "line and column pattern",
			errMsg:       "syntax error at line 2, column 5",
			expectedLine: 1, // 0-based
			expectedChar: 4, // 0-based
		},
		{
			name:         "line only pattern",
			errMsg:       "unexpected token at line 3",
			expectedLine: 2, // 0-based
			expectedChar: 0,
		},
		{
			name:         "bracket pattern",
			errMsg:       "parse error [2:10]",
			expectedLine: 1,
			expectedChar: 9,
		},
		{
			name:         "position pattern",
			errMsg:       "error at position 15",
			expectedLine: 1, // "SELECT *\n" = 9 chars, so position 15 is line 1, col 6
			expectedChar: 6,
		},
		{
			name:         "no position info",
			errMsg:       "some error without position",
			expectedLine: 0,
			expectedChar: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, char := extractPositionFromError(tt.errMsg, content, 0)
			if line != tt.expectedLine {
				t.Errorf("line = %d, want %d", line, tt.expectedLine)
			}
			if char != tt.expectedChar {
				t.Errorf("char = %d, want %d", char, tt.expectedChar)
			}
		})
	}
}

func TestOffsetToLineColumn(t *testing.T) {
	content := "SELECT *\nFROM users\nWHERE id = 1"

	tests := []struct {
		offset       int
		expectedLine int
		expectedCol  int
	}{
		{0, 0, 0},    // Start of file
		{6, 0, 6},    // "SELECT" -> 'T'
		{9, 1, 0},    // After "SELECT *\n" -> start of line 1
		{14, 1, 5},   // "FROM " -> space after FROM
		{20, 2, 0},   // Start of line 2 (WHERE)
		{100, 2, 11}, // Beyond end -> clamped to last char (content length is 32, so index 31 = col 11)
	}

	for _, tt := range tests {
		line, col := offsetToLineColumn(content, tt.offset)
		if line != tt.expectedLine || col != tt.expectedCol {
			t.Errorf("offsetToLineColumn(%d) = (%d, %d), want (%d, %d)",
				tt.offset, line, col, tt.expectedLine, tt.expectedCol)
		}
	}
}

func TestSnippetCompletions(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Open a document with cursor in the middle of "sel"
	server.Documents().Open("file:///test.sql", "sql", 1, "sel")

	completionParams := CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			Position:     Position{Line: 0, Character: 2}, // Position within "sel"
		},
	}

	paramsJSON, _ := json.Marshal(completionParams)
	result, err := server.handler.HandleRequest("textDocument/completion", paramsJSON)
	if err != nil {
		t.Fatalf("completion failed: %v", err)
	}

	completionList, ok := result.(*CompletionList)
	if !ok {
		t.Fatalf("expected CompletionList, got %T", result)
	}

	// Check that snippet completions are included (like "sel", "selall", etc.)
	snippetFound := false
	for _, item := range completionList.Items {
		if item.Kind == SnippetCompletion && item.Label == "sel" {
			snippetFound = true
			if item.InsertTextFormat != SnippetFormat {
				t.Error("expected snippet to have SnippetFormat")
			}
			break
		}
	}
	if !snippetFound {
		t.Error("expected 'sel' snippet in completion items")
	}
}

func TestIncrementalSync(t *testing.T) {
	mock := newMockReadWriter()
	logger := log.New(io.Discard, "", 0)
	server := NewServer(mock.input, mock.output, logger)

	// Initialize and verify incremental sync is advertised
	initParams := InitializeParams{
		ProcessID:    1234,
		RootURI:      "file:///workspace",
		Capabilities: ClientCapabilities{},
	}

	paramsJSON, _ := json.Marshal(initParams)
	result, err := server.handler.HandleRequest("initialize", paramsJSON)
	if err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	initResult, ok := result.(*InitializeResult)
	if !ok {
		t.Fatalf("expected InitializeResult, got %T", result)
	}

	if initResult.Capabilities.TextDocumentSync.Change != SyncIncremental {
		t.Errorf("expected SyncIncremental, got %v", initResult.Capabilities.TextDocumentSync.Change)
	}
}
