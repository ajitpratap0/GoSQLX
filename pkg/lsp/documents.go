package lsp

import (
	"strings"
	"sync"
)

// DocumentManager manages open SQL documents in a thread-safe manner.
//
// DocumentManager provides centralized document state management for the LSP server.
// It handles document lifecycle events (open, change, close) and maintains the
// current content and version for each document.
//
// # Thread Safety
//
// All operations are protected by a read/write mutex:
//   - Read operations (Get, GetContent): Use read lock for concurrent access
//   - Write operations (Open, Update, Close): Use write lock for exclusive access
//
// This ensures safe concurrent access from multiple LSP request handlers.
//
// # Document Lifecycle
//
// Documents follow the LSP document lifecycle:
//  1. Open: Document opened in editor (textDocument/didOpen)
//  2. Update: Content changes as user edits (textDocument/didChange)
//  3. Close: Document closed in editor (textDocument/didClose)
//
// # Synchronization Modes
//
// The manager supports both synchronization modes:
//   - Full sync: Entire document content sent on each change
//   - Incremental sync: Only changed portions sent (more efficient)
//
// # Document Versioning
//
// Each document has a version number that increments with changes.
// This enables the server to:
//   - Detect stale diagnostics
//   - Handle out-of-order updates
//   - Verify diagnostic freshness
//
// # Content Caching
//
// Documents cache their line-split content to optimize:
//   - Position-to-offset conversions
//   - Word extraction for hover and completion
//   - Incremental change application
type DocumentManager struct {
	mu        sync.RWMutex
	documents map[string]*Document
}

// Document represents an open SQL document with its current state.
//
// Document stores all information needed to process LSP requests for a
// single SQL file. It maintains the current content, version, and metadata.
//
// Fields:
//   - URI: Document identifier (file:// URI)
//   - LanguageID: Language identifier (typically "sql")
//   - Version: Monotonically increasing version number
//   - Content: Current full text content
//   - Lines: Cached line-split content for efficient position operations
//
// The Lines field is automatically synchronized with Content to avoid
// repeated string splitting operations.
type Document struct {
	URI        string
	LanguageID string
	Version    int
	Content    string
	Lines      []string // Cached line splits
}

// NewDocumentManager creates a new document manager.
//
// This constructor initializes a DocumentManager with an empty document map.
// The returned manager is ready to handle document lifecycle events from LSP clients.
//
// Returns:
//   - *DocumentManager: A new document manager instance
//
// Thread Safety: The returned DocumentManager is fully thread-safe and ready
// for concurrent use by multiple LSP request handlers.
//
// Usage:
//
//	dm := NewDocumentManager()
//	dm.Open("file:///query.sql", "sql", 1, "SELECT * FROM users")
//
// Typically, this is called once when creating the LSP server, not for each
// document operation.
func NewDocumentManager() *DocumentManager {
	return &DocumentManager{
		documents: make(map[string]*Document),
	}
}

// Open adds a document to the manager.
//
// This method is called when the client sends a textDocument/didOpen notification.
// It stores the initial document state including URI, language, version, and content.
//
// Parameters:
//   - uri: Document URI (e.g., "file:///path/to/query.sql")
//   - languageID: Language identifier (typically "sql")
//   - version: Initial version number (starts at 1, increments with changes)
//   - content: Full document text content
//
// Thread Safety: This method uses a write lock to safely add documents
// concurrently from multiple goroutines.
//
// The document's content is cached in both raw form (Content) and split into
// lines (Lines) for efficient position-to-offset conversions.
//
// Example:
//
//	dm.Open("file:///query.sql", "sql", 1, "SELECT * FROM users WHERE active = true")
//
// If a document with the same URI already exists, it will be replaced with
// the new content and version.
func (dm *DocumentManager) Open(uri, languageID string, version int, content string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.documents[uri] = &Document{
		URI:        uri,
		LanguageID: languageID,
		Version:    version,
		Content:    content,
		Lines:      splitLines(content),
	}
}

// Update updates a document's content.
//
// This method is called when the client sends a textDocument/didChange notification.
// It applies content changes to an existing document and updates its version number.
//
// Parameters:
//   - uri: Document URI to update
//   - version: New version number (should be greater than current version)
//   - changes: Array of content changes to apply
//
// Thread Safety: This method uses a write lock to safely update documents
// concurrently from multiple goroutines.
//
// The method supports two synchronization modes:
//
// Full Sync (change.Range == nil):
//   - The entire document is replaced with change.Text
//   - Simple and robust, but sends more data over the network
//
// Incremental Sync (change.Range != nil):
//   - Only the specified range is replaced with change.Text
//   - More efficient for large documents with small edits
//   - Requires proper position-to-offset conversion
//
// Example - Full sync:
//
//	dm.Update("file:///query.sql", 2, []TextDocumentContentChangeEvent{
//	    {Text: "SELECT id, name FROM users WHERE active = true"},
//	})
//
// Example - Incremental sync:
//
//	dm.Update("file:///query.sql", 3, []TextDocumentContentChangeEvent{
//	    {
//	        Range: &Range{Start: Position{Line: 0, Character: 7}, End: Position{Line: 0, Character: 8}},
//	        Text:  "*",
//	    },
//	})
//
// If the document doesn't exist, this method does nothing. The document must
// first be opened with Open() before it can be updated.
//
// After applying changes, the Lines cache is automatically rebuilt for
// efficient subsequent operations.
func (dm *DocumentManager) Update(uri string, version int, changes []TextDocumentContentChangeEvent) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	doc, ok := dm.documents[uri]
	if !ok {
		return
	}

	doc.Version = version

	for _, change := range changes {
		if change.Range == nil {
			// Full document sync
			doc.Content = change.Text
			doc.Lines = splitLines(change.Text)
		} else {
			// Incremental sync
			doc.Content = applyChange(doc.Content, doc.Lines, change)
			doc.Lines = splitLines(doc.Content)
		}
	}
}

// Close removes a document from the manager.
//
// This method is called when the client sends a textDocument/didClose notification.
// It removes the document from the internal map and releases associated resources.
//
// Parameters:
//   - uri: Document URI to close and remove
//
// Thread Safety: This method uses a write lock to safely remove documents
// concurrently from multiple goroutines.
//
// After closing a document, the server typically sends an empty diagnostics
// notification to clear any error markers in the editor:
//
//	dm.Close("file:///query.sql")
//	server.SendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
//	    URI:         "file:///query.sql",
//	    Diagnostics: []Diagnostic{},
//	})
//
// If the document doesn't exist, this method does nothing (safe to call redundantly).
//
// Once closed, the document must be re-opened with Open() before it can be
// accessed again. Attempting to Update() or Get() a closed document will fail.
func (dm *DocumentManager) Close(uri string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.documents, uri)
}

// Get retrieves a copy of a document to avoid race conditions
// The returned document is a snapshot and modifications won't affect the original
func (dm *DocumentManager) Get(uri string) (*Document, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	doc, ok := dm.documents[uri]
	if !ok {
		return nil, false
	}
	// Return a copy to prevent race conditions when accessing fields after lock release
	docCopy := &Document{
		URI:        doc.URI,
		LanguageID: doc.LanguageID,
		Version:    doc.Version,
		Content:    doc.Content,
		Lines:      make([]string, len(doc.Lines)),
	}
	copy(docCopy.Lines, doc.Lines)
	return docCopy, true
}

// GetContent retrieves a document's content
func (dm *DocumentManager) GetContent(uri string) (string, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	doc, ok := dm.documents[uri]
	if !ok {
		return "", false
	}
	return doc.Content, true
}

// splitLines splits content into lines, preserving line endings
func splitLines(content string) []string {
	if content == "" {
		return []string{""}
	}
	lines := strings.Split(content, "\n")
	return lines
}

// applyChange applies an incremental change to the document
func applyChange(content string, lines []string, change TextDocumentContentChangeEvent) string {
	if change.Range == nil {
		return change.Text
	}

	startOffset := positionToOffset(lines, change.Range.Start)
	endOffset := positionToOffset(lines, change.Range.End)

	// Build new content
	var result strings.Builder
	result.WriteString(content[:startOffset])
	result.WriteString(change.Text)
	if endOffset < len(content) {
		result.WriteString(content[endOffset:])
	}

	return result.String()
}

// positionToOffset converts a Position to a byte offset
func positionToOffset(lines []string, pos Position) int {
	offset := 0
	for i := 0; i < pos.Line && i < len(lines); i++ {
		offset += len(lines[i]) + 1 // +1 for newline
	}
	if pos.Line < len(lines) {
		lineLen := len(lines[pos.Line])
		if pos.Character < lineLen {
			offset += pos.Character
		} else {
			offset += lineLen
		}
	}
	return offset
}

// GetWordAtPosition returns the word at the given position.
//
// This method extracts the identifier or keyword at a specific cursor position,
// which is used for hover documentation and completion filtering.
//
// The method uses rune-based indexing to properly handle UTF-8 encoded SQL
// identifiers that may contain international characters.
//
// Word boundaries are defined as:
//   - Start: Beginning of line or non-word character
//   - End: End of line or non-word character
//   - Word characters: A-Z, a-z, 0-9, underscore
//
// Parameters:
//   - pos: The cursor position (0-based line and character indices)
//
// Returns:
//   - The word at the position, or empty string if:
//   - Position is out of bounds
//   - No word character at position
//   - Position is in whitespace
//
// Example:
//
//	doc.Content = "SELECT name FROM users"
//	word := doc.GetWordAtPosition(Position{Line: 0, Character: 9})
//	// Returns: "name"
//
// This method is safe for concurrent use as it operates on document fields
// without modifying state.
func (doc *Document) GetWordAtPosition(pos Position) string {
	if pos.Line >= len(doc.Lines) {
		return ""
	}

	line := doc.Lines[pos.Line]
	runes := []rune(line)

	if pos.Character >= len(runes) {
		return ""
	}

	// Find word boundaries using rune indexing for UTF-8 safety
	start := pos.Character
	end := pos.Character

	// Move start backwards to find word start
	for start > 0 && isWordChar(runes[start-1]) {
		start--
	}

	// Move end forwards to find word end
	for end < len(runes) && isWordChar(runes[end]) {
		end++
	}

	if start == end {
		return ""
	}

	return string(runes[start:end])
}

// isWordChar returns true if c is a valid word character
func isWordChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}
