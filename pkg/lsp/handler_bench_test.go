package lsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
)

// BenchmarkHandler_Hover benchmarks hover operation
func BenchmarkHandler_Hover(b *testing.B) {
	server := setupTestServer()
	sql := "SELECT id, name FROM users WHERE active = true"
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Position:     Position{Line: 0, Character: 0}, // On SELECT
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/hover", paramsJSON)
	}
}

// BenchmarkHandler_HoverKeyword benchmarks hover on different keywords
func BenchmarkHandler_HoverKeyword(b *testing.B) {
	keywords := []struct {
		name     string
		sql      string
		position Position
	}{
		{"SELECT", "SELECT * FROM users", Position{Line: 0, Character: 0}},
		{"FROM", "SELECT * FROM users", Position{Line: 0, Character: 10}},
		{"WHERE", "SELECT * FROM users WHERE id = 1", Position{Line: 0, Character: 20}},
		{"JOIN", "SELECT * FROM users JOIN orders ON users.id = orders.user_id", Position{Line: 0, Character: 20}},
		{"INSERT", "INSERT INTO users (name) VALUES ('test')", Position{Line: 0, Character: 0}},
		{"UPDATE", "UPDATE users SET name = 'test' WHERE id = 1", Position{Line: 0, Character: 0}},
		{"DELETE", "DELETE FROM users WHERE id = 1", Position{Line: 0, Character: 0}},
	}

	for _, kw := range keywords {
		b.Run(kw.name, func(b *testing.B) {
			server := setupTestServer()
			server.Documents().Open("file:///test.sql", "sql", 1, kw.sql)

			params := TextDocumentPositionParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
				Position:     kw.position,
			}
			paramsJSON, _ := json.Marshal(params)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = server.handler.HandleRequest("textDocument/hover", paramsJSON)
			}
		})
	}
}

// BenchmarkHandler_Completion benchmarks completion operation
func BenchmarkHandler_Completion(b *testing.B) {
	server := setupTestServer()
	sql := "SEL"
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			Position:     Position{Line: 0, Character: 3},
		},
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/completion", paramsJSON)
	}
}

// BenchmarkHandler_CompletionDifferentPrefixes benchmarks completion with various prefixes
func BenchmarkHandler_CompletionDifferentPrefixes(b *testing.B) {
	prefixes := []struct {
		name   string
		prefix string
		pos    int
	}{
		{"Empty", "", 0},
		{"S", "S", 1},
		{"SE", "SE", 2},
		{"SEL", "SEL", 3},
		{"SELE", "SELE", 4},
		{"SELEC", "SELEC", 5},
		{"IN", "IN", 2},
		{"INS", "INS", 3},
		{"UPD", "UPD", 3},
		{"DEL", "DEL", 3},
	}

	for _, prefix := range prefixes {
		b.Run(prefix.name, func(b *testing.B) {
			server := setupTestServer()
			server.Documents().Open("file:///test.sql", "sql", 1, prefix.prefix)

			params := CompletionParams{
				TextDocumentPositionParams: TextDocumentPositionParams{
					TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
					Position:     Position{Line: 0, Character: prefix.pos},
				},
			}
			paramsJSON, _ := json.Marshal(params)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = server.handler.HandleRequest("textDocument/completion", paramsJSON)
			}
		})
	}
}

// BenchmarkHandler_Formatting benchmarks formatting operation
func BenchmarkHandler_Formatting(b *testing.B) {
	server := setupTestServer()
	sql := "select id,name,email from users where active=true order by name"
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := DocumentFormattingParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Options:      FormattingOptions{TabSize: 2, InsertSpaces: true},
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/formatting", paramsJSON)
	}
}

// BenchmarkHandler_FormattingComplexQueries benchmarks formatting of complex queries
func BenchmarkHandler_FormattingComplexQueries(b *testing.B) {
	queries := []struct {
		name string
		sql  string
	}{
		{
			name: "Simple",
			sql:  "select * from users",
		},
		{
			name: "WithJoin",
			sql:  "select u.id,u.name,o.order_date from users u join orders o on u.id=o.user_id",
		},
		{
			name: "WithSubquery",
			sql:  "select * from users where id in (select user_id from orders where total>100)",
		},
		{
			name: "WithCTE",
			sql:  "with active_users as (select * from users where active=true) select * from active_users",
		},
		{
			name: "Complex",
			sql: `select u.id,u.name,count(o.id) as order_count,sum(o.total) as total_amount
from users u left join orders o on u.id=o.user_id
where u.active=true and o.created_at>='2023-01-01'
group by u.id,u.name having count(o.id)>5 order by total_amount desc limit 10`,
		},
	}

	for _, query := range queries {
		b.Run(query.name, func(b *testing.B) {
			server := setupTestServer()
			server.Documents().Open("file:///test.sql", "sql", 1, query.sql)

			params := DocumentFormattingParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
				Options:      FormattingOptions{TabSize: 2, InsertSpaces: true},
			}
			paramsJSON, _ := json.Marshal(params)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = server.handler.HandleRequest("textDocument/formatting", paramsJSON)
			}
		})
	}
}

// BenchmarkHandler_DocumentSymbol benchmarks document symbol extraction
func BenchmarkHandler_DocumentSymbol(b *testing.B) {
	server := setupTestServer()
	sql := `SELECT * FROM users;
INSERT INTO logs (msg) VALUES ('test');
UPDATE users SET name = 'John' WHERE id = 1;
DELETE FROM temp_data WHERE created_at < NOW();`
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := DocumentSymbolParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/documentSymbol", paramsJSON)
	}
}

// BenchmarkHandler_DocumentSymbolMultiStatement benchmarks symbol extraction with varying statement counts
func BenchmarkHandler_DocumentSymbolMultiStatement(b *testing.B) {
	statementCounts := []int{1, 5, 10, 25, 50, 100}

	for _, count := range statementCounts {
		b.Run(fmt.Sprintf("%dStatements", count), func(b *testing.B) {
			server := setupTestServer()
			sql := generateMultipleStatements(count)
			server.Documents().Open("file:///test.sql", "sql", 1, sql)

			params := DocumentSymbolParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			}
			paramsJSON, _ := json.Marshal(params)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = server.handler.HandleRequest("textDocument/documentSymbol", paramsJSON)
			}
		})
	}
}

// BenchmarkHandler_SignatureHelp benchmarks signature help operation
func BenchmarkHandler_SignatureHelp(b *testing.B) {
	server := setupTestServer()
	sql := "SELECT COUNT("
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Position:     Position{Line: 0, Character: 13},
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/signatureHelp", paramsJSON)
	}
}

// BenchmarkHandler_CodeAction benchmarks code action generation
func BenchmarkHandler_CodeAction(b *testing.B) {
	server := setupTestServer()
	sql := "select * from users"
	server.Documents().Open("file:///test.sql", "sql", 1, sql)

	params := CodeActionParams{
		TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
		Range:        Range{Start: Position{Line: 0, Character: 0}, End: Position{Line: 0, Character: 19}},
		Context:      CodeActionContext{Diagnostics: []Diagnostic{}},
	}
	paramsJSON, _ := json.Marshal(params)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.handler.HandleRequest("textDocument/codeAction", paramsJSON)
	}
}

// BenchmarkHandler_DidOpen benchmarks document open notification
func BenchmarkHandler_DidOpen(b *testing.B) {
	sql := "SELECT * FROM users WHERE id = 1"

	didOpenParams := DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{
			URI:        "file:///test.sql",
			LanguageID: "sql",
			Version:    1,
			Text:       sql,
		},
	}
	paramsJSON, _ := json.Marshal(didOpenParams)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server := setupTestServer()
		server.handler.HandleNotification("textDocument/didOpen", paramsJSON)
	}
}

// BenchmarkHandler_DidChange benchmarks document change notification
func BenchmarkHandler_DidChange(b *testing.B) {
	server := setupTestServer()
	server.Documents().Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

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

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.handler.HandleNotification("textDocument/didChange", paramsJSON)
	}
}

// BenchmarkHandler_Initialize benchmarks initialization
func BenchmarkHandler_Initialize(b *testing.B) {
	initParams := InitializeParams{
		ProcessID:    1234,
		RootURI:      "file:///workspace",
		Capabilities: ClientCapabilities{},
	}
	paramsJSON, _ := json.Marshal(initParams)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server := setupTestServer()
		_, _ = server.handler.HandleRequest("initialize", paramsJSON)
	}
}

// BenchmarkHandler_LargeDocument benchmarks operations on large documents
func BenchmarkHandler_LargeDocument(b *testing.B) {
	sizes := []int{100, 500, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%dStatements", size), func(b *testing.B) {
			server := setupTestServer()

			// Generate large SQL document
			sql := generateLargeSQLDocument(size)
			server.Documents().Open("file:///test.sql", "sql", 1, sql)

			params := DocumentSymbolParams{
				TextDocument: TextDocumentIdentifier{URI: "file:///test.sql"},
			}
			paramsJSON, _ := json.Marshal(params)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = server.handler.HandleRequest("textDocument/documentSymbol", paramsJSON)
			}
		})
	}
}

// BenchmarkDocumentManager_Open benchmarks document opening
func BenchmarkDocumentManager_Open(b *testing.B) {
	dm := NewDocumentManager()
	sql := "SELECT * FROM users WHERE active = true"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uri := fmt.Sprintf("file:///test%d.sql", i)
		dm.Open(uri, "sql", 1, sql)
	}
}

// BenchmarkDocumentManager_Get benchmarks document retrieval
func BenchmarkDocumentManager_Get(b *testing.B) {
	dm := NewDocumentManager()
	dm.Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dm.Get("file:///test.sql")
	}
}

// BenchmarkDocumentManager_Update benchmarks document updates
func BenchmarkDocumentManager_Update(b *testing.B) {
	dm := NewDocumentManager()
	dm.Open("file:///test.sql", "sql", 1, "SELECT * FROM users")

	changes := []TextDocumentContentChangeEvent{
		{Text: "SELECT id, name FROM users WHERE active = true"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dm.Update("file:///test.sql", i+2, changes)
	}
}

// BenchmarkDocumentManager_Concurrent benchmarks concurrent document operations
func BenchmarkDocumentManager_Concurrent(b *testing.B) {
	dm := NewDocumentManager()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			uri := fmt.Sprintf("file:///test%d.sql", i%100)
			dm.Open(uri, "sql", i, "SELECT * FROM users")
			_, _ = dm.Get(uri)
			dm.Close(uri)
			i++
		}
	})
}

// BenchmarkDocument_GetWordAtPosition benchmarks word extraction at position
func BenchmarkDocument_GetWordAtPosition(b *testing.B) {
	doc := &Document{
		Content: "SELECT id, name, email FROM users WHERE active = true ORDER BY name",
		Lines:   []string{"SELECT id, name, email FROM users WHERE active = true ORDER BY name"},
	}

	positions := []Position{
		{Line: 0, Character: 0},  // SELECT
		{Line: 0, Character: 7},  // id
		{Line: 0, Character: 28}, // FROM
		{Line: 0, Character: 33}, // users
		{Line: 0, Character: 39}, // WHERE
		{Line: 0, Character: 45}, // active
		{Line: 0, Character: 61}, // BY
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pos := positions[i%len(positions)]
		_ = doc.GetWordAtPosition(pos)
	}
}

// BenchmarkPositionToOffset benchmarks position to offset conversion
func BenchmarkPositionToOffset(b *testing.B) {
	lines := []string{
		"SELECT id, name, email",
		"FROM users",
		"WHERE active = true",
		"ORDER BY name",
		"LIMIT 10",
	}

	positions := []Position{
		{Line: 0, Character: 0},
		{Line: 1, Character: 5},
		{Line: 2, Character: 10},
		{Line: 3, Character: 8},
		{Line: 4, Character: 6},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pos := positions[i%len(positions)]
		_ = positionToOffset(lines, pos)
	}
}

// BenchmarkOffsetToLineColumn benchmarks offset to line/column conversion
func BenchmarkOffsetToLineColumn(b *testing.B) {
	content := `SELECT id, name, email
FROM users
WHERE active = true
ORDER BY name
LIMIT 10`

	offsets := []int{0, 10, 25, 50, 75, 100}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		offset := offsets[i%len(offsets)]
		_, _ = offsetToLineColumn(content, offset)
	}
}

// setupTestServer creates a test server with mock I/O
func setupTestServer() *Server {
	mock := &mockReadWriter{
		input:  bytes.NewBuffer(nil),
		output: bytes.NewBuffer(nil),
	}
	return NewServer(mock.input, mock.output, log.New(io.Discard, "", 0))
}

// generateLargeSQLDocument generates a SQL document with the specified number of statements
func generateLargeSQLDocument(statements int) string {
	var builder strings.Builder
	for i := 0; i < statements; i++ {
		builder.WriteString(fmt.Sprintf("SELECT col%d FROM table%d WHERE id = %d;\n", i, i%10, i))
	}
	return builder.String()
}

// generateMultipleStatements generates multiple different types of SQL statements
func generateMultipleStatements(count int) string {
	var builder strings.Builder
	statementTypes := []string{
		"SELECT * FROM users WHERE id = %d;",
		"INSERT INTO logs (message) VALUES ('entry %d');",
		"UPDATE users SET last_seen = NOW() WHERE id = %d;",
		"DELETE FROM temp_data WHERE id = %d;",
		"SELECT COUNT(*) FROM orders WHERE user_id = %d;",
	}

	for i := 0; i < count; i++ {
		stmt := statementTypes[i%len(statementTypes)]
		builder.WriteString(fmt.Sprintf(stmt, i))
		builder.WriteString("\n")
	}
	return builder.String()
}
