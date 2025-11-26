package lsp

import (
	"strings"
	"sync"
)

// DocumentManager manages open documents
type DocumentManager struct {
	mu        sync.RWMutex
	documents map[string]*Document
}

// Document represents an open SQL document
type Document struct {
	URI        string
	LanguageID string
	Version    int
	Content    string
	Lines      []string // Cached line splits
}

// NewDocumentManager creates a new document manager
func NewDocumentManager() *DocumentManager {
	return &DocumentManager{
		documents: make(map[string]*Document),
	}
}

// Open adds a document to the manager
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

// Update updates a document's content
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

// Close removes a document from the manager
func (dm *DocumentManager) Close(uri string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	delete(dm.documents, uri)
}

// Get retrieves a document
func (dm *DocumentManager) Get(uri string) (*Document, bool) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	doc, ok := dm.documents[uri]
	return doc, ok
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

// offsetToPosition converts a byte offset to a Position
func offsetToPosition(content string, offset int) Position {
	if offset < 0 {
		return Position{Line: 0, Character: 0}
	}
	if offset > len(content) {
		offset = len(content)
	}

	line := 0
	lineStart := 0
	for i := 0; i < offset; i++ {
		if i < len(content) && content[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}
	return Position{Line: line, Character: offset - lineStart}
}

// GetWordAtPosition returns the word at the given position
func (doc *Document) GetWordAtPosition(pos Position) string {
	if pos.Line >= len(doc.Lines) {
		return ""
	}

	line := doc.Lines[pos.Line]
	if pos.Character >= len(line) {
		return ""
	}

	// Find word boundaries
	start := pos.Character
	end := pos.Character

	// Move start backwards to find word start
	for start > 0 && isWordChar(rune(line[start-1])) {
		start--
	}

	// Move end forwards to find word end
	for end < len(line) && isWordChar(rune(line[end])) {
		end++
	}

	if start == end {
		return ""
	}

	return line[start:end]
}

// isWordChar returns true if c is a valid word character
func isWordChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}
