package lsp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Handler processes LSP requests and notifications
type Handler struct {
	server   *Server
	keywords *keywords.Keywords
}

// NewHandler creates a new LSP request handler
func NewHandler(server *Server) *Handler {
	return &Handler{
		server:   server,
		keywords: keywords.New(keywords.DialectGeneric, true),
	}
}

// HandleRequest processes an LSP request and returns a result
func (h *Handler) HandleRequest(method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "initialize":
		return h.handleInitialize(params)
	case "shutdown":
		return h.handleShutdown()
	case "textDocument/hover":
		return h.handleHover(params)
	case "textDocument/completion":
		return h.handleCompletion(params)
	case "textDocument/formatting":
		return h.handleFormatting(params)
	case "textDocument/documentSymbol":
		return h.handleDocumentSymbol(params)
	case "textDocument/signatureHelp":
		return h.handleSignatureHelp(params)
	case "textDocument/codeAction":
		return h.handleCodeAction(params)
	default:
		return nil, fmt.Errorf("method not found: %s", method)
	}
}

// HandleNotification processes an LSP notification
func (h *Handler) HandleNotification(method string, params json.RawMessage) {
	switch method {
	case "initialized":
		h.handleInitialized()
	case "exit":
		h.handleExit()
	case "textDocument/didOpen":
		h.handleDidOpen(params)
	case "textDocument/didChange":
		h.handleDidChange(params)
	case "textDocument/didClose":
		h.handleDidClose(params)
	case "textDocument/didSave":
		h.handleDidSave(params)
	}
}

// handleInitialize handles the initialize request
func (h *Handler) handleInitialize(params json.RawMessage) (*InitializeResult, error) {
	var initParams InitializeParams
	if err := json.Unmarshal(params, &initParams); err != nil {
		return nil, err
	}

	h.server.Logger().Printf("Initialize request from client, rootURI: %s", initParams.RootURI)

	return &InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: &TextDocumentSyncOptions{
				OpenClose: true,
				Change:    SyncIncremental, // Support incremental updates for better performance
				Save: &SaveOptions{
					IncludeText: true,
				},
			},
			CompletionProvider: &CompletionOptions{
				TriggerCharacters: []string{" ", ".", "("},
				ResolveProvider:   false,
			},
			HoverProvider:              true,
			DocumentFormattingProvider: true,
			DocumentSymbolProvider:     true,
			SignatureHelpProvider: &SignatureHelpOptions{
				TriggerCharacters:   []string{"(", ","},
				RetriggerCharacters: []string{","},
			},
			CodeActionProvider: &CodeActionOptions{
				CodeActionKinds: []CodeActionKind{CodeActionQuickFix},
			},
		},
		ServerInfo: &ServerInfo{
			Name:    "gosqlx-lsp",
			Version: "1.0.0",
		},
	}, nil
}

// handleInitialized is called when the client confirms initialization
func (h *Handler) handleInitialized() {
	h.server.Logger().Println("Client initialized")
}

// handleShutdown handles the shutdown request
func (h *Handler) handleShutdown() (*ShutdownResult, error) {
	h.server.Logger().Println("Shutdown requested")
	return &ShutdownResult{}, nil
}

// handleExit handles the exit notification
func (h *Handler) handleExit() {
	h.server.Logger().Println("Exit notification received")
	h.server.SetShutdown()
}

// handleDidOpen handles document open notifications
func (h *Handler) handleDidOpen(params json.RawMessage) {
	var p DidOpenTextDocumentParams
	if err := json.Unmarshal(params, &p); err != nil {
		h.server.Logger().Printf("textDocument/didOpen: failed to parse params: %v (raw: %s)", err, truncateForLog(params))
		h.sendParseError("didOpen", err)
		return
	}

	h.server.Logger().Printf("Document opened: %s", p.TextDocument.URI)

	h.server.Documents().Open(
		p.TextDocument.URI,
		p.TextDocument.LanguageID,
		p.TextDocument.Version,
		p.TextDocument.Text,
	)

	// Validate and publish diagnostics
	h.validateDocument(p.TextDocument.URI, p.TextDocument.Text, p.TextDocument.Version)
}

// handleDidChange handles document change notifications
func (h *Handler) handleDidChange(params json.RawMessage) {
	var p DidChangeTextDocumentParams
	if err := json.Unmarshal(params, &p); err != nil {
		h.server.Logger().Printf("textDocument/didChange: failed to parse params: %v (raw: %s)", err, truncateForLog(params))
		h.sendParseError("didChange", err)
		return
	}

	h.server.Logger().Printf("Document changed: %s (version %d)", p.TextDocument.URI, p.TextDocument.Version)

	h.server.Documents().Update(
		p.TextDocument.URI,
		p.TextDocument.Version,
		p.ContentChanges,
	)

	// Get updated content and validate
	if content, ok := h.server.Documents().GetContent(p.TextDocument.URI); ok {
		h.validateDocument(p.TextDocument.URI, content, p.TextDocument.Version)
	}
}

// handleDidClose handles document close notifications
func (h *Handler) handleDidClose(params json.RawMessage) {
	var p DidCloseTextDocumentParams
	if err := json.Unmarshal(params, &p); err != nil {
		h.server.Logger().Printf("textDocument/didClose: failed to parse params: %v (raw: %s)", err, truncateForLog(params))
		h.sendParseError("didClose", err)
		return
	}

	h.server.Logger().Printf("Document closed: %s", p.TextDocument.URI)
	h.server.Documents().Close(p.TextDocument.URI)

	// Clear diagnostics for closed document
	h.server.SendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         p.TextDocument.URI,
		Diagnostics: []Diagnostic{},
	})
}

// handleDidSave handles document save notifications
func (h *Handler) handleDidSave(params json.RawMessage) {
	var p DidSaveTextDocumentParams
	if err := json.Unmarshal(params, &p); err != nil {
		h.server.Logger().Printf("textDocument/didSave: failed to parse params: %v (raw: %s)", err, truncateForLog(params))
		h.sendParseError("didSave", err)
		return
	}

	h.server.Logger().Printf("Document saved: %s", p.TextDocument.URI)

	// If text is included, use it; otherwise get from document manager
	content := p.Text
	if content == "" {
		if c, ok := h.server.Documents().GetContent(p.TextDocument.URI); ok {
			content = c
		}
	}

	if content != "" {
		h.validateDocument(p.TextDocument.URI, content, 0)
	}
}

// validateDocument parses the SQL and publishes diagnostics
func (h *Handler) validateDocument(uri, content string, version int) {
	var diagnostics []Diagnostic

	// Use high-level gosqlx.Parse which handles tokenization and parsing
	_, err := gosqlx.Parse(content)
	if err != nil {
		// Parse error - create diagnostic
		diag := h.createDiagnosticFromError(content, err.Error(), 0)
		diagnostics = append(diagnostics, diag)
	}

	// Publish diagnostics
	h.server.SendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         uri,
		Version:     version,
		Diagnostics: diagnostics,
	})

	h.server.Logger().Printf("Published %d diagnostics for %s", len(diagnostics), uri)
}

// sendParseError sends an error message to the client when notification parsing fails
func (h *Handler) sendParseError(method string, err error) {
	h.server.SendNotification("window/showMessage", ShowMessageParams{
		Type:    MessageWarning,
		Message: fmt.Sprintf("GoSQLX LSP: Failed to process %s notification: %v", method, err),
	})
}

// Position extraction patterns for GoSQLX error messages
var (
	// Matches patterns like "at line 5, column 10" or "line 5 column 10"
	lineColPattern = regexp.MustCompile(`(?i)(?:at\s+)?line\s+(\d+)(?:,?\s*column\s+(\d+))?`)
	// Matches patterns like "position 42" or "at position 42"
	positionPattern = regexp.MustCompile(`(?i)(?:at\s+)?position\s+(\d+)`)
	// Matches patterns like "[1:5]" (line:column)
	bracketPattern = regexp.MustCompile(`\[(\d+):(\d+)\]`)
)

// createDiagnosticFromError creates a diagnostic from an error message
func (h *Handler) createDiagnosticFromError(content, errMsg string, defaultLine int) Diagnostic {
	line, char := extractPositionFromError(errMsg, content, defaultLine)

	// Calculate end position (end of line or reasonable span)
	lines := strings.Split(content, "\n")
	endChar := char + 1
	if line < len(lines) {
		// Extend to end of word or reasonable span
		lineContent := lines[line]
		if char < len(lineContent) {
			// Find end of current word/token
			end := char
			for end < len(lineContent) && !isWhitespace(lineContent[end]) {
				end++
			}
			if end > char {
				endChar = end
			} else {
				endChar = len(lineContent)
			}
		} else {
			endChar = len(lineContent)
		}
	}

	return Diagnostic{
		Range: Range{
			Start: Position{Line: line, Character: char},
			End:   Position{Line: line, Character: endChar},
		},
		Severity: SeverityError,
		Source:   "gosqlx",
		Message:  errMsg,
	}
}

// extractPositionFromError attempts to extract line and column from error message
func extractPositionFromError(errMsg, content string, defaultLine int) (line, char int) {
	line = defaultLine
	char = 0

	// Try line:column pattern first (e.g., "at line 5, column 10")
	if matches := lineColPattern.FindStringSubmatch(errMsg); len(matches) >= 2 {
		if l, err := strconv.Atoi(matches[1]); err == nil {
			line = l - 1 // Convert to 0-based
			if line < 0 {
				line = 0
			}
		}
		if len(matches) >= 3 && matches[2] != "" {
			if c, err := strconv.Atoi(matches[2]); err == nil {
				char = c - 1 // Convert to 0-based
				if char < 0 {
					char = 0
				}
			}
		}
		return
	}

	// Try bracket pattern (e.g., "[1:5]")
	if matches := bracketPattern.FindStringSubmatch(errMsg); len(matches) >= 3 {
		if l, err := strconv.Atoi(matches[1]); err == nil {
			line = l - 1
			if line < 0 {
				line = 0
			}
		}
		if c, err := strconv.Atoi(matches[2]); err == nil {
			char = c - 1
			if char < 0 {
				char = 0
			}
		}
		return
	}

	// Try absolute position pattern (e.g., "position 42")
	if matches := positionPattern.FindStringSubmatch(errMsg); len(matches) >= 2 {
		if pos, err := strconv.Atoi(matches[1]); err == nil {
			line, char = offsetToLineColumn(content, pos)
		}
		return
	}

	return
}

// offsetToLineColumn converts an absolute offset to line and column
func offsetToLineColumn(content string, offset int) (line, col int) {
	if offset < 0 {
		return 0, 0
	}
	if offset >= len(content) {
		offset = len(content) - 1
		if offset < 0 {
			return 0, 0
		}
	}

	line = 0
	col = 0
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 0
		} else {
			col++
		}
	}
	return
}

// isWhitespace returns true if c is a whitespace character
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// handleHover provides hover information for SQL keywords
func (h *Handler) handleHover(params json.RawMessage) (*Hover, error) {
	var p TextDocumentPositionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	doc, ok := h.server.Documents().Get(p.TextDocument.URI)
	if !ok {
		// Return empty hover response instead of nil for proper LSP compliance
		return &Hover{}, nil
	}

	// Get word at position
	word := doc.GetWordAtPosition(p.Position)
	if word == "" {
		return &Hover{}, nil
	}

	// Look up keyword documentation
	doc_text := getKeywordDocumentation(strings.ToUpper(word))
	if doc_text == "" {
		return &Hover{}, nil
	}

	return &Hover{
		Contents: MarkupContent{
			Kind:  Markdown,
			Value: doc_text,
		},
	}, nil
}

// handleCompletion provides completion suggestions
func (h *Handler) handleCompletion(params json.RawMessage) (*CompletionList, error) {
	var p CompletionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	doc, ok := h.server.Documents().Get(p.TextDocument.URI)
	if !ok {
		return &CompletionList{Items: []CompletionItem{}}, nil
	}

	// Get partial word at position for filtering
	word := doc.GetWordAtPosition(p.Position)
	prefix := strings.ToUpper(word)
	lowerPrefix := strings.ToLower(word)

	// Build completion items - keywords first
	items := []CompletionItem{}
	for _, kw := range sqlKeywords {
		if prefix == "" || strings.HasPrefix(strings.ToUpper(kw.Label), prefix) {
			items = append(items, kw)
		}
	}

	// Add snippets (match on lowercase prefix for snippet shortcuts)
	for _, snippet := range sqlSnippets {
		if lowerPrefix == "" || strings.HasPrefix(strings.ToLower(snippet.Label), lowerPrefix) {
			items = append(items, snippet)
		}
	}

	// Limit results
	if len(items) > 100 {
		items = items[:100]
	}

	return &CompletionList{
		IsIncomplete: len(items) >= 100,
		Items:        items,
	}, nil
}

// handleFormatting formats the SQL document
func (h *Handler) handleFormatting(params json.RawMessage) ([]TextEdit, error) {
	var p DocumentFormattingParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	content, ok := h.server.Documents().GetContent(p.TextDocument.URI)
	if !ok {
		return nil, nil
	}

	// Format the SQL using a simple formatter
	formatted := formatSQL(content, p.Options)
	if formatted == content {
		return []TextEdit{}, nil
	}

	// Calculate the full document range
	lines := strings.Split(content, "\n")
	endLine := len(lines) - 1
	endChar := 0
	if endLine >= 0 && endLine < len(lines) {
		endChar = len(lines[endLine])
	}

	return []TextEdit{
		{
			Range: Range{
				Start: Position{Line: 0, Character: 0},
				End:   Position{Line: endLine, Character: endChar},
			},
			NewText: formatted,
		},
	}, nil
}

// formatSQL provides basic SQL formatting
func formatSQL(sql string, opts FormattingOptions) string {
	// Basic SQL formatter - normalize whitespace and keyword casing
	lines := strings.Split(sql, "\n")
	var result []string

	indent := ""
	if opts.InsertSpaces {
		indent = strings.Repeat(" ", opts.TabSize)
	} else {
		indent = "\t"
	}

	currentIndent := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		upper := strings.ToUpper(trimmed)

		// Adjust indent based on keywords
		if strings.HasPrefix(upper, "SELECT") ||
			strings.HasPrefix(upper, "INSERT") ||
			strings.HasPrefix(upper, "UPDATE") ||
			strings.HasPrefix(upper, "DELETE") ||
			strings.HasPrefix(upper, "CREATE") ||
			strings.HasPrefix(upper, "DROP") ||
			strings.HasPrefix(upper, "ALTER") ||
			strings.HasPrefix(upper, "WITH") {
			currentIndent = ""
		} else if strings.HasPrefix(upper, "FROM") ||
			strings.HasPrefix(upper, "WHERE") ||
			strings.HasPrefix(upper, "SET") ||
			strings.HasPrefix(upper, "VALUES") {
			currentIndent = ""
		} else if strings.HasPrefix(upper, "AND") ||
			strings.HasPrefix(upper, "OR") {
			currentIndent = indent
		} else if strings.HasPrefix(upper, "JOIN") ||
			strings.HasPrefix(upper, "LEFT") ||
			strings.HasPrefix(upper, "RIGHT") ||
			strings.HasPrefix(upper, "INNER") ||
			strings.HasPrefix(upper, "OUTER") ||
			strings.HasPrefix(upper, "CROSS") {
			currentIndent = ""
		} else if strings.HasPrefix(upper, "GROUP") ||
			strings.HasPrefix(upper, "ORDER") ||
			strings.HasPrefix(upper, "HAVING") ||
			strings.HasPrefix(upper, "LIMIT") {
			currentIndent = ""
		}

		result = append(result, currentIndent+trimmed)
	}

	formatted := strings.Join(result, "\n")

	if opts.InsertFinalNewline && !strings.HasSuffix(formatted, "\n") {
		formatted += "\n"
	}

	return formatted
}

// SQL keyword documentation
func getKeywordDocumentation(keyword string) string {
	docs := map[string]string{
		"SELECT":     "**SELECT** - Retrieves data from one or more tables.\n\n```sql\nSELECT column1, column2 FROM table_name;\n```",
		"FROM":       "**FROM** - Specifies the table(s) to retrieve data from.\n\n```sql\nSELECT * FROM users;\n```",
		"WHERE":      "**WHERE** - Filters rows based on a condition.\n\n```sql\nSELECT * FROM users WHERE active = true;\n```",
		"JOIN":       "**JOIN** - Combines rows from two or more tables based on a related column.\n\n```sql\nSELECT * FROM orders JOIN customers ON orders.customer_id = customers.id;\n```",
		"LEFT":       "**LEFT JOIN** - Returns all rows from the left table and matched rows from the right table.\n\n```sql\nSELECT * FROM orders LEFT JOIN customers ON orders.customer_id = customers.id;\n```",
		"RIGHT":      "**RIGHT JOIN** - Returns all rows from the right table and matched rows from the left table.\n\n```sql\nSELECT * FROM orders RIGHT JOIN customers ON orders.customer_id = customers.id;\n```",
		"INNER":      "**INNER JOIN** - Returns rows that have matching values in both tables.\n\n```sql\nSELECT * FROM orders INNER JOIN customers ON orders.customer_id = customers.id;\n```",
		"OUTER":      "**OUTER JOIN** - Returns all rows when there is a match in either table.\n\n```sql\nSELECT * FROM orders FULL OUTER JOIN customers ON orders.customer_id = customers.id;\n```",
		"GROUP":      "**GROUP BY** - Groups rows that have the same values in specified columns.\n\n```sql\nSELECT department, COUNT(*) FROM employees GROUP BY department;\n```",
		"ORDER":      "**ORDER BY** - Sorts the result set by specified columns.\n\n```sql\nSELECT * FROM users ORDER BY name ASC;\n```",
		"HAVING":     "**HAVING** - Filters groups based on a condition (used with GROUP BY).\n\n```sql\nSELECT department, COUNT(*) FROM employees GROUP BY department HAVING COUNT(*) > 5;\n```",
		"LIMIT":      "**LIMIT** - Restricts the number of rows returned.\n\n```sql\nSELECT * FROM users LIMIT 10;\n```",
		"OFFSET":     "**OFFSET** - Skips a specified number of rows before returning results.\n\n```sql\nSELECT * FROM users LIMIT 10 OFFSET 20;\n```",
		"INSERT":     "**INSERT** - Adds new rows to a table.\n\n```sql\nINSERT INTO users (name, email) VALUES ('John', 'john@example.com');\n```",
		"UPDATE":     "**UPDATE** - Modifies existing rows in a table.\n\n```sql\nUPDATE users SET name = 'Jane' WHERE id = 1;\n```",
		"DELETE":     "**DELETE** - Removes rows from a table.\n\n```sql\nDELETE FROM users WHERE id = 1;\n```",
		"CREATE":     "**CREATE** - Creates database objects (tables, indexes, views, etc.).\n\n```sql\nCREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));\n```",
		"DROP":       "**DROP** - Removes database objects.\n\n```sql\nDROP TABLE users;\n```",
		"ALTER":      "**ALTER** - Modifies database objects.\n\n```sql\nALTER TABLE users ADD COLUMN age INT;\n```",
		"TRUNCATE":   "**TRUNCATE** - Removes all rows from a table quickly.\n\n```sql\nTRUNCATE TABLE logs;\n```",
		"WITH":       "**WITH** - Defines a Common Table Expression (CTE).\n\n```sql\nWITH active_users AS (SELECT * FROM users WHERE active = true)\nSELECT * FROM active_users;\n```",
		"UNION":      "**UNION** - Combines result sets of two queries (removes duplicates).\n\n```sql\nSELECT name FROM employees UNION SELECT name FROM contractors;\n```",
		"EXCEPT":     "**EXCEPT** - Returns rows from the first query that are not in the second.\n\n```sql\nSELECT name FROM employees EXCEPT SELECT name FROM managers;\n```",
		"INTERSECT":  "**INTERSECT** - Returns rows that appear in both queries.\n\n```sql\nSELECT name FROM employees INTERSECT SELECT name FROM managers;\n```",
		"CASE":       "**CASE** - Provides conditional logic in SQL.\n\n```sql\nSELECT name, CASE WHEN age >= 18 THEN 'Adult' ELSE 'Minor' END FROM users;\n```",
		"WHEN":       "**WHEN** - Specifies a condition in a CASE expression.\n\n```sql\nCASE WHEN status = 'active' THEN 'Yes' ELSE 'No' END\n```",
		"THEN":       "**THEN** - Specifies the result when a CASE condition is true.\n\n```sql\nCASE WHEN status = 'active' THEN 'Yes' END\n```",
		"ELSE":       "**ELSE** - Specifies the default result in a CASE expression.\n\n```sql\nCASE WHEN x > 0 THEN 'Positive' ELSE 'Non-positive' END\n```",
		"END":        "**END** - Ends a CASE expression or block.\n\n```sql\nCASE WHEN x > 0 THEN 'Positive' ELSE 'Non-positive' END\n```",
		"AND":        "**AND** - Combines conditions (all must be true).\n\n```sql\nSELECT * FROM users WHERE active = true AND age >= 18;\n```",
		"OR":         "**OR** - Combines conditions (at least one must be true).\n\n```sql\nSELECT * FROM users WHERE status = 'active' OR status = 'pending';\n```",
		"NOT":        "**NOT** - Negates a condition.\n\n```sql\nSELECT * FROM users WHERE NOT deleted;\n```",
		"IN":         "**IN** - Checks if a value matches any value in a list.\n\n```sql\nSELECT * FROM users WHERE status IN ('active', 'pending');\n```",
		"BETWEEN":    "**BETWEEN** - Checks if a value is within a range.\n\n```sql\nSELECT * FROM orders WHERE amount BETWEEN 100 AND 500;\n```",
		"LIKE":       "**LIKE** - Pattern matching with wildcards (% and _).\n\n```sql\nSELECT * FROM users WHERE name LIKE 'John%';\n```",
		"IS":         "**IS** - Tests for NULL values.\n\n```sql\nSELECT * FROM users WHERE deleted_at IS NULL;\n```",
		"NULL":       "**NULL** - Represents a missing or unknown value.\n\n```sql\nSELECT * FROM users WHERE email IS NOT NULL;\n```",
		"AS":         "**AS** - Creates an alias for a column or table.\n\n```sql\nSELECT name AS user_name FROM users u;\n```",
		"DISTINCT":   "**DISTINCT** - Returns only unique values.\n\n```sql\nSELECT DISTINCT status FROM orders;\n```",
		"COUNT":      "**COUNT** - Counts the number of rows.\n\n```sql\nSELECT COUNT(*) FROM users;\n```",
		"SUM":        "**SUM** - Calculates the sum of values.\n\n```sql\nSELECT SUM(amount) FROM orders;\n```",
		"AVG":        "**AVG** - Calculates the average of values.\n\n```sql\nSELECT AVG(salary) FROM employees;\n```",
		"MIN":        "**MIN** - Returns the minimum value.\n\n```sql\nSELECT MIN(price) FROM products;\n```",
		"MAX":        "**MAX** - Returns the maximum value.\n\n```sql\nSELECT MAX(price) FROM products;\n```",
		"OVER":       "**OVER** - Defines a window for window functions.\n\n```sql\nSELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) FROM employees;\n```",
		"PARTITION":  "**PARTITION BY** - Divides rows into partitions for window functions.\n\n```sql\nSELECT dept, name, RANK() OVER (PARTITION BY dept ORDER BY salary) FROM employees;\n```",
		"ROW_NUMBER": "**ROW_NUMBER()** - Assigns unique sequential numbers to rows.\n\n```sql\nSELECT name, ROW_NUMBER() OVER (ORDER BY name) FROM users;\n```",
		"RANK":       "**RANK()** - Assigns ranks with gaps for ties.\n\n```sql\nSELECT name, RANK() OVER (ORDER BY score DESC) FROM players;\n```",
		"DENSE_RANK": "**DENSE_RANK()** - Assigns ranks without gaps for ties.\n\n```sql\nSELECT name, DENSE_RANK() OVER (ORDER BY score DESC) FROM players;\n```",
		"LAG":        "**LAG()** - Accesses data from a previous row.\n\n```sql\nSELECT date, value, LAG(value) OVER (ORDER BY date) AS prev_value FROM metrics;\n```",
		"LEAD":       "**LEAD()** - Accesses data from a following row.\n\n```sql\nSELECT date, value, LEAD(value) OVER (ORDER BY date) AS next_value FROM metrics;\n```",
		"MERGE":      "**MERGE** - Performs INSERT, UPDATE, or DELETE based on conditions.\n\n```sql\nMERGE INTO target USING source ON target.id = source.id\nWHEN MATCHED THEN UPDATE SET target.value = source.value\nWHEN NOT MATCHED THEN INSERT (id, value) VALUES (source.id, source.value);\n```",
		"ROLLUP":     "**ROLLUP** - Creates subtotals and grand totals in GROUP BY.\n\n```sql\nSELECT region, product, SUM(sales) FROM orders GROUP BY ROLLUP(region, product);\n```",
		"CUBE":       "**CUBE** - Creates all possible subtotal combinations in GROUP BY.\n\n```sql\nSELECT region, product, SUM(sales) FROM orders GROUP BY CUBE(region, product);\n```",
		"GROUPING":   "**GROUPING SETS** - Specifies multiple grouping sets in one query.\n\n```sql\nSELECT region, product, SUM(sales) FROM orders GROUP BY GROUPING SETS((region), (product), ());\n```",
		"FETCH":      "**FETCH** - Limits rows returned (SQL standard alternative to LIMIT).\n\n```sql\nSELECT * FROM users ORDER BY id FETCH FIRST 10 ROWS ONLY;\n```",
		"ROWS":       "**ROWS** - Defines window frame in terms of physical rows.\n\n```sql\nSUM(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)\n```",
		"RANGE":      "**RANGE** - Defines window frame in terms of value range.\n\n```sql\nSUM(amount) OVER (ORDER BY date RANGE UNBOUNDED PRECEDING)\n```",
	}

	return docs[keyword]
}

// sqlKeywords provides completion items for SQL keywords
var sqlKeywords = []CompletionItem{
	{Label: "SELECT", Kind: KeywordCompletion, Detail: "Query data from tables"},
	{Label: "FROM", Kind: KeywordCompletion, Detail: "Specify source table(s)"},
	{Label: "WHERE", Kind: KeywordCompletion, Detail: "Filter rows"},
	{Label: "JOIN", Kind: KeywordCompletion, Detail: "Combine tables"},
	{Label: "LEFT JOIN", Kind: KeywordCompletion, Detail: "Left outer join", InsertText: "LEFT JOIN "},
	{Label: "RIGHT JOIN", Kind: KeywordCompletion, Detail: "Right outer join", InsertText: "RIGHT JOIN "},
	{Label: "INNER JOIN", Kind: KeywordCompletion, Detail: "Inner join", InsertText: "INNER JOIN "},
	{Label: "FULL OUTER JOIN", Kind: KeywordCompletion, Detail: "Full outer join", InsertText: "FULL OUTER JOIN "},
	{Label: "CROSS JOIN", Kind: KeywordCompletion, Detail: "Cross join", InsertText: "CROSS JOIN "},
	{Label: "ON", Kind: KeywordCompletion, Detail: "Join condition"},
	{Label: "AND", Kind: KeywordCompletion, Detail: "Logical AND"},
	{Label: "OR", Kind: KeywordCompletion, Detail: "Logical OR"},
	{Label: "NOT", Kind: KeywordCompletion, Detail: "Logical NOT"},
	{Label: "IN", Kind: KeywordCompletion, Detail: "Value in list"},
	{Label: "BETWEEN", Kind: KeywordCompletion, Detail: "Value in range"},
	{Label: "LIKE", Kind: KeywordCompletion, Detail: "Pattern matching"},
	{Label: "IS NULL", Kind: KeywordCompletion, Detail: "Check for NULL", InsertText: "IS NULL"},
	{Label: "IS NOT NULL", Kind: KeywordCompletion, Detail: "Check for non-NULL", InsertText: "IS NOT NULL"},
	{Label: "GROUP BY", Kind: KeywordCompletion, Detail: "Group rows", InsertText: "GROUP BY "},
	{Label: "ORDER BY", Kind: KeywordCompletion, Detail: "Sort results", InsertText: "ORDER BY "},
	{Label: "HAVING", Kind: KeywordCompletion, Detail: "Filter groups"},
	{Label: "LIMIT", Kind: KeywordCompletion, Detail: "Limit rows returned"},
	{Label: "OFFSET", Kind: KeywordCompletion, Detail: "Skip rows"},
	{Label: "FETCH FIRST", Kind: KeywordCompletion, Detail: "Limit rows (SQL standard)", InsertText: "FETCH FIRST "},
	{Label: "ASC", Kind: KeywordCompletion, Detail: "Ascending order"},
	{Label: "DESC", Kind: KeywordCompletion, Detail: "Descending order"},
	{Label: "NULLS FIRST", Kind: KeywordCompletion, Detail: "NULLs appear first", InsertText: "NULLS FIRST"},
	{Label: "NULLS LAST", Kind: KeywordCompletion, Detail: "NULLs appear last", InsertText: "NULLS LAST"},
	{Label: "DISTINCT", Kind: KeywordCompletion, Detail: "Unique values"},
	{Label: "AS", Kind: KeywordCompletion, Detail: "Create alias"},
	{Label: "CASE", Kind: KeywordCompletion, Detail: "Conditional expression"},
	{Label: "WHEN", Kind: KeywordCompletion, Detail: "CASE condition"},
	{Label: "THEN", Kind: KeywordCompletion, Detail: "CASE result"},
	{Label: "ELSE", Kind: KeywordCompletion, Detail: "CASE default"},
	{Label: "END", Kind: KeywordCompletion, Detail: "End CASE"},
	{Label: "INSERT INTO", Kind: KeywordCompletion, Detail: "Insert rows", InsertText: "INSERT INTO "},
	{Label: "VALUES", Kind: KeywordCompletion, Detail: "Specify values"},
	{Label: "UPDATE", Kind: KeywordCompletion, Detail: "Update rows"},
	{Label: "SET", Kind: KeywordCompletion, Detail: "Set column values"},
	{Label: "DELETE FROM", Kind: KeywordCompletion, Detail: "Delete rows", InsertText: "DELETE FROM "},
	{Label: "CREATE TABLE", Kind: KeywordCompletion, Detail: "Create new table", InsertText: "CREATE TABLE "},
	{Label: "CREATE INDEX", Kind: KeywordCompletion, Detail: "Create index", InsertText: "CREATE INDEX "},
	{Label: "CREATE VIEW", Kind: KeywordCompletion, Detail: "Create view", InsertText: "CREATE VIEW "},
	{Label: "DROP TABLE", Kind: KeywordCompletion, Detail: "Drop table", InsertText: "DROP TABLE "},
	{Label: "DROP INDEX", Kind: KeywordCompletion, Detail: "Drop index", InsertText: "DROP INDEX "},
	{Label: "ALTER TABLE", Kind: KeywordCompletion, Detail: "Alter table", InsertText: "ALTER TABLE "},
	{Label: "TRUNCATE TABLE", Kind: KeywordCompletion, Detail: "Remove all rows", InsertText: "TRUNCATE TABLE "},
	{Label: "WITH", Kind: KeywordCompletion, Detail: "Common Table Expression"},
	{Label: "RECURSIVE", Kind: KeywordCompletion, Detail: "Recursive CTE"},
	{Label: "UNION", Kind: KeywordCompletion, Detail: "Combine results (unique)"},
	{Label: "UNION ALL", Kind: KeywordCompletion, Detail: "Combine results (all)", InsertText: "UNION ALL"},
	{Label: "EXCEPT", Kind: KeywordCompletion, Detail: "Difference of results"},
	{Label: "INTERSECT", Kind: KeywordCompletion, Detail: "Intersection of results"},
	{Label: "COUNT", Kind: FunctionCompletion, Detail: "Count rows", InsertText: "COUNT("},
	{Label: "SUM", Kind: FunctionCompletion, Detail: "Sum values", InsertText: "SUM("},
	{Label: "AVG", Kind: FunctionCompletion, Detail: "Average value", InsertText: "AVG("},
	{Label: "MIN", Kind: FunctionCompletion, Detail: "Minimum value", InsertText: "MIN("},
	{Label: "MAX", Kind: FunctionCompletion, Detail: "Maximum value", InsertText: "MAX("},
	{Label: "ROW_NUMBER", Kind: FunctionCompletion, Detail: "Row number", InsertText: "ROW_NUMBER() OVER ("},
	{Label: "RANK", Kind: FunctionCompletion, Detail: "Rank with gaps", InsertText: "RANK() OVER ("},
	{Label: "DENSE_RANK", Kind: FunctionCompletion, Detail: "Rank without gaps", InsertText: "DENSE_RANK() OVER ("},
	{Label: "NTILE", Kind: FunctionCompletion, Detail: "Divide into buckets", InsertText: "NTILE("},
	{Label: "LAG", Kind: FunctionCompletion, Detail: "Previous row value", InsertText: "LAG("},
	{Label: "LEAD", Kind: FunctionCompletion, Detail: "Next row value", InsertText: "LEAD("},
	{Label: "FIRST_VALUE", Kind: FunctionCompletion, Detail: "First value in window", InsertText: "FIRST_VALUE("},
	{Label: "LAST_VALUE", Kind: FunctionCompletion, Detail: "Last value in window", InsertText: "LAST_VALUE("},
	{Label: "OVER", Kind: KeywordCompletion, Detail: "Window specification"},
	{Label: "PARTITION BY", Kind: KeywordCompletion, Detail: "Partition window", InsertText: "PARTITION BY "},
	{Label: "ROWS BETWEEN", Kind: KeywordCompletion, Detail: "Window frame (rows)", InsertText: "ROWS BETWEEN "},
	{Label: "RANGE BETWEEN", Kind: KeywordCompletion, Detail: "Window frame (range)", InsertText: "RANGE BETWEEN "},
	{Label: "UNBOUNDED PRECEDING", Kind: KeywordCompletion, Detail: "Frame start", InsertText: "UNBOUNDED PRECEDING"},
	{Label: "CURRENT ROW", Kind: KeywordCompletion, Detail: "Current row", InsertText: "CURRENT ROW"},
	{Label: "UNBOUNDED FOLLOWING", Kind: KeywordCompletion, Detail: "Frame end", InsertText: "UNBOUNDED FOLLOWING"},
	{Label: "MERGE INTO", Kind: KeywordCompletion, Detail: "Merge statement", InsertText: "MERGE INTO "},
	{Label: "USING", Kind: KeywordCompletion, Detail: "Merge source"},
	{Label: "WHEN MATCHED", Kind: KeywordCompletion, Detail: "Merge match condition", InsertText: "WHEN MATCHED THEN"},
	{Label: "WHEN NOT MATCHED", Kind: KeywordCompletion, Detail: "Merge no-match condition", InsertText: "WHEN NOT MATCHED THEN"},
	{Label: "ROLLUP", Kind: KeywordCompletion, Detail: "Hierarchical grouping"},
	{Label: "CUBE", Kind: KeywordCompletion, Detail: "All grouping combinations"},
	{Label: "GROUPING SETS", Kind: KeywordCompletion, Detail: "Multiple groupings", InsertText: "GROUPING SETS ("},
	{Label: "TRUE", Kind: KeywordCompletion, Detail: "Boolean true"},
	{Label: "FALSE", Kind: KeywordCompletion, Detail: "Boolean false"},
	{Label: "NULL", Kind: KeywordCompletion, Detail: "NULL value"},
	{Label: "DEFAULT", Kind: KeywordCompletion, Detail: "Default value"},
	{Label: "PRIMARY KEY", Kind: KeywordCompletion, Detail: "Primary key constraint", InsertText: "PRIMARY KEY"},
	{Label: "FOREIGN KEY", Kind: KeywordCompletion, Detail: "Foreign key constraint", InsertText: "FOREIGN KEY"},
	{Label: "REFERENCES", Kind: KeywordCompletion, Detail: "Foreign key reference"},
	{Label: "UNIQUE", Kind: KeywordCompletion, Detail: "Unique constraint"},
	{Label: "NOT NULL", Kind: KeywordCompletion, Detail: "Not null constraint", InsertText: "NOT NULL"},
	{Label: "CHECK", Kind: KeywordCompletion, Detail: "Check constraint"},
	{Label: "CONSTRAINT", Kind: KeywordCompletion, Detail: "Named constraint"},
	{Label: "INDEX", Kind: KeywordCompletion, Detail: "Index"},
	{Label: "CASCADE", Kind: KeywordCompletion, Detail: "Cascade action"},
	{Label: "RESTRICT", Kind: KeywordCompletion, Detail: "Restrict action"},
	{Label: "COALESCE", Kind: FunctionCompletion, Detail: "First non-null value", InsertText: "COALESCE("},
	{Label: "NULLIF", Kind: FunctionCompletion, Detail: "Return null if equal", InsertText: "NULLIF("},
	{Label: "CAST", Kind: FunctionCompletion, Detail: "Type conversion", InsertText: "CAST("},
	{Label: "CONVERT", Kind: FunctionCompletion, Detail: "Type conversion", InsertText: "CONVERT("},
	{Label: "SUBSTRING", Kind: FunctionCompletion, Detail: "Extract substring", InsertText: "SUBSTRING("},
	{Label: "TRIM", Kind: FunctionCompletion, Detail: "Remove whitespace", InsertText: "TRIM("},
	{Label: "UPPER", Kind: FunctionCompletion, Detail: "Convert to uppercase", InsertText: "UPPER("},
	{Label: "LOWER", Kind: FunctionCompletion, Detail: "Convert to lowercase", InsertText: "LOWER("},
	{Label: "LENGTH", Kind: FunctionCompletion, Detail: "String length", InsertText: "LENGTH("},
	{Label: "CONCAT", Kind: FunctionCompletion, Detail: "Concatenate strings", InsertText: "CONCAT("},
	{Label: "NOW", Kind: FunctionCompletion, Detail: "Current timestamp", InsertText: "NOW()"},
	{Label: "CURRENT_DATE", Kind: FunctionCompletion, Detail: "Current date", InsertText: "CURRENT_DATE"},
	{Label: "CURRENT_TIME", Kind: FunctionCompletion, Detail: "Current time", InsertText: "CURRENT_TIME"},
	{Label: "CURRENT_TIMESTAMP", Kind: FunctionCompletion, Detail: "Current timestamp", InsertText: "CURRENT_TIMESTAMP"},
}

// sqlSnippets provides snippet completions for common SQL patterns
var sqlSnippets = []CompletionItem{
	{
		Label:            "sel",
		Kind:             SnippetCompletion,
		Detail:           "SELECT statement",
		InsertText:       "SELECT ${1:columns}\nFROM ${2:table}\nWHERE ${3:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "selall",
		Kind:             SnippetCompletion,
		Detail:           "SELECT * FROM table",
		InsertText:       "SELECT *\nFROM ${1:table}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "selcount",
		Kind:             SnippetCompletion,
		Detail:           "SELECT COUNT(*)",
		InsertText:       "SELECT COUNT(*)\nFROM ${1:table}\nWHERE ${2:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "seljoin",
		Kind:             SnippetCompletion,
		Detail:           "SELECT with JOIN",
		InsertText:       "SELECT ${1:columns}\nFROM ${2:table1} t1\nJOIN ${3:table2} t2 ON t1.${4:id} = t2.${5:foreign_id}\nWHERE ${6:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "selleft",
		Kind:             SnippetCompletion,
		Detail:           "SELECT with LEFT JOIN",
		InsertText:       "SELECT ${1:columns}\nFROM ${2:table1} t1\nLEFT JOIN ${3:table2} t2 ON t1.${4:id} = t2.${5:foreign_id}\nWHERE ${6:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "selgroup",
		Kind:             SnippetCompletion,
		Detail:           "SELECT with GROUP BY",
		InsertText:       "SELECT ${1:column}, COUNT(*) as count\nFROM ${2:table}\nGROUP BY ${1:column}\nHAVING COUNT(*) > ${3:1}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "ins",
		Kind:             SnippetCompletion,
		Detail:           "INSERT statement",
		InsertText:       "INSERT INTO ${1:table} (${2:columns})\nVALUES (${3:values})",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "inssel",
		Kind:             SnippetCompletion,
		Detail:           "INSERT SELECT statement",
		InsertText:       "INSERT INTO ${1:target_table} (${2:columns})\nSELECT ${2:columns}\nFROM ${3:source_table}\nWHERE ${4:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "upd",
		Kind:             SnippetCompletion,
		Detail:           "UPDATE statement",
		InsertText:       "UPDATE ${1:table}\nSET ${2:column} = ${3:value}\nWHERE ${4:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "del",
		Kind:             SnippetCompletion,
		Detail:           "DELETE statement",
		InsertText:       "DELETE FROM ${1:table}\nWHERE ${2:condition}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "cretbl",
		Kind:             SnippetCompletion,
		Detail:           "CREATE TABLE statement",
		InsertText:       "CREATE TABLE ${1:table_name} (\n\t${2:id} INT PRIMARY KEY,\n\t${3:column} ${4:VARCHAR(255)}\n)",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "creidx",
		Kind:             SnippetCompletion,
		Detail:           "CREATE INDEX statement",
		InsertText:       "CREATE INDEX ${1:idx_name} ON ${2:table} (${3:column})",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "cte",
		Kind:             SnippetCompletion,
		Detail:           "Common Table Expression (WITH)",
		InsertText:       "WITH ${1:cte_name} AS (\n\tSELECT ${2:columns}\n\tFROM ${3:table}\n\tWHERE ${4:condition}\n)\nSELECT *\nFROM ${1:cte_name}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "cterec",
		Kind:             SnippetCompletion,
		Detail:           "Recursive CTE",
		InsertText:       "WITH RECURSIVE ${1:cte_name} AS (\n\t-- Base case\n\tSELECT ${2:columns}\n\tFROM ${3:table}\n\tWHERE ${4:base_condition}\n\t\n\tUNION ALL\n\t\n\t-- Recursive case\n\tSELECT ${2:columns}\n\tFROM ${3:table} t\n\tJOIN ${1:cte_name} c ON t.${5:parent_id} = c.${6:id}\n)\nSELECT * FROM ${1:cte_name}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "case",
		Kind:             SnippetCompletion,
		Detail:           "CASE expression",
		InsertText:       "CASE\n\tWHEN ${1:condition} THEN ${2:result}\n\tELSE ${3:default}\nEND",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "casecol",
		Kind:             SnippetCompletion,
		Detail:           "CASE on column value",
		InsertText:       "CASE ${1:column}\n\tWHEN ${2:value1} THEN ${3:result1}\n\tWHEN ${4:value2} THEN ${5:result2}\n\tELSE ${6:default}\nEND",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "window",
		Kind:             SnippetCompletion,
		Detail:           "Window function",
		InsertText:       "${1:ROW_NUMBER}() OVER (\n\tPARTITION BY ${2:partition_column}\n\tORDER BY ${3:order_column}\n)",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "merge",
		Kind:             SnippetCompletion,
		Detail:           "MERGE statement",
		InsertText:       "MERGE INTO ${1:target_table} t\nUSING ${2:source_table} s ON t.${3:id} = s.${3:id}\nWHEN MATCHED THEN\n\tUPDATE SET t.${4:column} = s.${4:column}\nWHEN NOT MATCHED THEN\n\tINSERT (${5:columns}) VALUES (${6:values})",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "trunc",
		Kind:             SnippetCompletion,
		Detail:           "TRUNCATE TABLE",
		InsertText:       "TRUNCATE TABLE ${1:table_name}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "altertbl",
		Kind:             SnippetCompletion,
		Detail:           "ALTER TABLE ADD COLUMN",
		InsertText:       "ALTER TABLE ${1:table_name}\nADD COLUMN ${2:column_name} ${3:data_type}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "droptbl",
		Kind:             SnippetCompletion,
		Detail:           "DROP TABLE IF EXISTS",
		InsertText:       "DROP TABLE IF EXISTS ${1:table_name}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "union",
		Kind:             SnippetCompletion,
		Detail:           "UNION query",
		InsertText:       "SELECT ${1:columns} FROM ${2:table1}\nUNION\nSELECT ${1:columns} FROM ${3:table2}",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "exists",
		Kind:             SnippetCompletion,
		Detail:           "EXISTS subquery",
		InsertText:       "EXISTS (\n\tSELECT 1\n\tFROM ${1:table}\n\tWHERE ${2:condition}\n)",
		InsertTextFormat: SnippetFormat,
	},
	{
		Label:            "subq",
		Kind:             SnippetCompletion,
		Detail:           "Subquery",
		InsertText:       "(\n\tSELECT ${1:column}\n\tFROM ${2:table}\n\tWHERE ${3:condition}\n)",
		InsertTextFormat: SnippetFormat,
	},
}

// handleDocumentSymbol returns symbols in the document (SQL statements, tables, columns)
func (h *Handler) handleDocumentSymbol(params json.RawMessage) ([]DocumentSymbol, error) {
	var p DocumentSymbolParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	content, ok := h.server.Documents().GetContent(p.TextDocument.URI)
	if !ok {
		return []DocumentSymbol{}, nil
	}

	// Parse the SQL to extract symbols
	ast, err := gosqlx.Parse(content)
	if err != nil {
		// Return empty symbols on parse error
		return []DocumentSymbol{}, nil
	}

	symbols := []DocumentSymbol{}
	lines := strings.Split(content, "\n")

	// Extract symbols from each statement
	for i, stmt := range ast.Statements {
		symbol := h.extractStatementSymbol(stmt, i, lines, content)
		if symbol != nil {
			symbols = append(symbols, *symbol)
		}
	}

	return symbols, nil
}

// extractStatementSymbol extracts a document symbol from a SQL statement
func (h *Handler) extractStatementSymbol(stmt interface{}, index int, lines []string, content string) *DocumentSymbol {
	// Determine statement type and name
	var name string
	var detail string
	var kind SymbolKind

	// Use type switch to determine statement type
	typeName := fmt.Sprintf("%T", stmt)
	switch {
	case strings.Contains(typeName, "SelectStatement"):
		name = fmt.Sprintf("SELECT #%d", index+1)
		detail = "SELECT statement"
		kind = SymbolMethod
	case strings.Contains(typeName, "InsertStatement"):
		name = fmt.Sprintf("INSERT #%d", index+1)
		detail = "INSERT statement"
		kind = SymbolMethod
	case strings.Contains(typeName, "UpdateStatement"):
		name = fmt.Sprintf("UPDATE #%d", index+1)
		detail = "UPDATE statement"
		kind = SymbolMethod
	case strings.Contains(typeName, "DeleteStatement"):
		name = fmt.Sprintf("DELETE #%d", index+1)
		detail = "DELETE statement"
		kind = SymbolMethod
	case strings.Contains(typeName, "CreateTableStatement"):
		name = fmt.Sprintf("CREATE TABLE #%d", index+1)
		detail = "DDL statement"
		kind = SymbolStruct
	case strings.Contains(typeName, "CreateIndexStatement"):
		name = fmt.Sprintf("CREATE INDEX #%d", index+1)
		detail = "DDL statement"
		kind = SymbolStruct
	case strings.Contains(typeName, "DropStatement"):
		name = fmt.Sprintf("DROP #%d", index+1)
		detail = "DDL statement"
		kind = SymbolStruct
	case strings.Contains(typeName, "AlterStatement"):
		name = fmt.Sprintf("ALTER #%d", index+1)
		detail = "DDL statement"
		kind = SymbolStruct
	case strings.Contains(typeName, "TruncateStatement"):
		name = fmt.Sprintf("TRUNCATE #%d", index+1)
		detail = "DDL statement"
		kind = SymbolStruct
	case strings.Contains(typeName, "MergeStatement"):
		name = fmt.Sprintf("MERGE #%d", index+1)
		detail = "DML statement"
		kind = SymbolMethod
	default:
		name = fmt.Sprintf("Statement #%d", index+1)
		detail = typeName
		kind = SymbolVariable
	}

	// For now, use a simple range based on statement index
	// A more sophisticated implementation would track actual positions
	startLine := 0
	endLine := len(lines) - 1
	if endLine < 0 {
		endLine = 0
	}
	endChar := 0
	if endLine < len(lines) {
		endChar = len(lines[endLine])
	}

	return &DocumentSymbol{
		Name:   name,
		Detail: detail,
		Kind:   kind,
		Range: Range{
			Start: Position{Line: startLine, Character: 0},
			End:   Position{Line: endLine, Character: endChar},
		},
		SelectionRange: Range{
			Start: Position{Line: startLine, Character: 0},
			End:   Position{Line: startLine, Character: len(name)},
		},
	}
}

// handleSignatureHelp provides signature help for SQL functions
func (h *Handler) handleSignatureHelp(params json.RawMessage) (*SignatureHelp, error) {
	var p TextDocumentPositionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	doc, ok := h.server.Documents().Get(p.TextDocument.URI)
	if !ok {
		return &SignatureHelp{}, nil
	}

	// Get the function name at position
	content := doc.Content
	funcName, paramIndex := h.getFunctionAtPosition(content, p.Position)
	if funcName == "" {
		return &SignatureHelp{}, nil
	}

	// Look up function signature
	sig := getSQLFunctionSignature(strings.ToUpper(funcName))
	if sig == nil {
		return &SignatureHelp{}, nil
	}

	return &SignatureHelp{
		Signatures:      []SignatureInformation{*sig},
		ActiveSignature: 0,
		ActiveParameter: paramIndex,
	}, nil
}

// getFunctionAtPosition finds the function name and parameter index at a position
func (h *Handler) getFunctionAtPosition(content string, pos Position) (string, int) {
	lines := strings.Split(content, "\n")
	if pos.Line >= len(lines) {
		return "", 0
	}

	line := lines[pos.Line]
	if pos.Character > len(line) {
		return "", 0
	}

	// Look backwards for opening parenthesis to find function name
	parenCount := 0
	paramIndex := 0
	funcEnd := -1

	for i := pos.Character - 1; i >= 0; i-- {
		ch := line[i]
		if ch == ')' {
			parenCount++
		} else if ch == '(' {
			if parenCount == 0 {
				funcEnd = i
				break
			}
			parenCount--
		} else if ch == ',' && parenCount == 0 {
			paramIndex++
		}
	}

	if funcEnd < 0 {
		return "", 0
	}

	// Extract function name (word before the parenthesis)
	funcStart := funcEnd - 1
	for funcStart >= 0 && (isAlphanumeric(line[funcStart]) || line[funcStart] == '_') {
		funcStart--
	}
	funcStart++

	if funcStart >= funcEnd {
		return "", 0
	}

	return line[funcStart:funcEnd], paramIndex
}

// isAlphanumeric checks if a byte is alphanumeric
func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// getSQLFunctionSignature returns the signature for a SQL function
func getSQLFunctionSignature(funcName string) *SignatureInformation {
	signatures := map[string]*SignatureInformation{
		"COUNT": {
			Label:         "COUNT(expression)",
			Documentation: "Returns the number of rows that match a specified condition.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to count. Use * for all rows."},
			},
		},
		"SUM": {
			Label:         "SUM(expression)",
			Documentation: "Returns the sum of all values in the expression.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Numeric column or expression to sum."},
			},
		},
		"AVG": {
			Label:         "AVG(expression)",
			Documentation: "Returns the average value of the expression.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Numeric column or expression to average."},
			},
		},
		"MIN": {
			Label:         "MIN(expression)",
			Documentation: "Returns the minimum value in the expression.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to find minimum value."},
			},
		},
		"MAX": {
			Label:         "MAX(expression)",
			Documentation: "Returns the maximum value in the expression.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to find maximum value."},
			},
		},
		"COALESCE": {
			Label:         "COALESCE(value1, value2, ...)",
			Documentation: "Returns the first non-null value in the list.",
			Parameters: []ParameterInformation{
				{Label: "value1", Documentation: "First value to check."},
				{Label: "value2, ...", Documentation: "Additional values to check."},
			},
		},
		"NULLIF": {
			Label:         "NULLIF(expression1, expression2)",
			Documentation: "Returns NULL if expression1 equals expression2, otherwise returns expression1.",
			Parameters: []ParameterInformation{
				{Label: "expression1", Documentation: "Value to return if not equal."},
				{Label: "expression2", Documentation: "Value to compare against."},
			},
		},
		"CAST": {
			Label:         "CAST(expression AS type)",
			Documentation: "Converts an expression to a specified data type.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Value to convert."},
				{Label: "type", Documentation: "Target data type."},
			},
		},
		"SUBSTRING": {
			Label:         "SUBSTRING(string, start, length)",
			Documentation: "Extracts a substring from a string.",
			Parameters: []ParameterInformation{
				{Label: "string", Documentation: "Source string."},
				{Label: "start", Documentation: "Starting position (1-based)."},
				{Label: "length", Documentation: "Number of characters to extract."},
			},
		},
		"TRIM": {
			Label:         "TRIM([LEADING|TRAILING|BOTH] [characters] FROM string)",
			Documentation: "Removes leading/trailing characters from a string.",
			Parameters: []ParameterInformation{
				{Label: "string", Documentation: "String to trim."},
			},
		},
		"UPPER": {
			Label:         "UPPER(string)",
			Documentation: "Converts a string to uppercase.",
			Parameters: []ParameterInformation{
				{Label: "string", Documentation: "String to convert."},
			},
		},
		"LOWER": {
			Label:         "LOWER(string)",
			Documentation: "Converts a string to lowercase.",
			Parameters: []ParameterInformation{
				{Label: "string", Documentation: "String to convert."},
			},
		},
		"LENGTH": {
			Label:         "LENGTH(string)",
			Documentation: "Returns the length of a string.",
			Parameters: []ParameterInformation{
				{Label: "string", Documentation: "String to measure."},
			},
		},
		"CONCAT": {
			Label:         "CONCAT(string1, string2, ...)",
			Documentation: "Concatenates two or more strings.",
			Parameters: []ParameterInformation{
				{Label: "string1", Documentation: "First string."},
				{Label: "string2, ...", Documentation: "Additional strings to concatenate."},
			},
		},
		"ROW_NUMBER": {
			Label:         "ROW_NUMBER() OVER (ORDER BY column)",
			Documentation: "Assigns unique sequential integers to rows within a partition.",
			Parameters:    []ParameterInformation{},
		},
		"RANK": {
			Label:         "RANK() OVER (ORDER BY column)",
			Documentation: "Assigns a rank to each row with gaps for ties.",
			Parameters:    []ParameterInformation{},
		},
		"DENSE_RANK": {
			Label:         "DENSE_RANK() OVER (ORDER BY column)",
			Documentation: "Assigns a rank to each row without gaps for ties.",
			Parameters:    []ParameterInformation{},
		},
		"LAG": {
			Label:         "LAG(expression, offset, default) OVER (...)",
			Documentation: "Accesses data from a previous row in the same result set.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to return."},
				{Label: "offset", Documentation: "Number of rows back (default 1)."},
				{Label: "default", Documentation: "Value to return if offset goes beyond partition."},
			},
		},
		"LEAD": {
			Label:         "LEAD(expression, offset, default) OVER (...)",
			Documentation: "Accesses data from a following row in the same result set.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to return."},
				{Label: "offset", Documentation: "Number of rows forward (default 1)."},
				{Label: "default", Documentation: "Value to return if offset goes beyond partition."},
			},
		},
		"FIRST_VALUE": {
			Label:         "FIRST_VALUE(expression) OVER (...)",
			Documentation: "Returns the first value in an ordered set of values.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to return."},
			},
		},
		"LAST_VALUE": {
			Label:         "LAST_VALUE(expression) OVER (...)",
			Documentation: "Returns the last value in an ordered set of values.",
			Parameters: []ParameterInformation{
				{Label: "expression", Documentation: "Column or expression to return."},
			},
		},
		"NTILE": {
			Label:         "NTILE(num_buckets) OVER (...)",
			Documentation: "Divides rows into a specified number of groups.",
			Parameters: []ParameterInformation{
				{Label: "num_buckets", Documentation: "Number of groups to create."},
			},
		},
	}

	return signatures[funcName]
}

// handleCodeAction provides code actions (quick fixes) for diagnostics
func (h *Handler) handleCodeAction(params json.RawMessage) ([]CodeAction, error) {
	var p CodeActionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	actions := []CodeAction{}

	// Generate quick fixes based on diagnostics
	for _, diag := range p.Context.Diagnostics {
		codeActions := h.getCodeActionsForDiagnostic(p.TextDocument.URI, diag)
		actions = append(actions, codeActions...)
	}

	return actions, nil
}

// getCodeActionsForDiagnostic generates code actions for a specific diagnostic
func (h *Handler) getCodeActionsForDiagnostic(uri string, diag Diagnostic) []CodeAction {
	actions := []CodeAction{}
	msg := strings.ToLower(diag.Message)

	// Common SQL error fixes
	if strings.Contains(msg, "unexpected") || strings.Contains(msg, "expected") {
		// Suggest adding missing semicolon
		if strings.Contains(msg, "semicolon") || strings.Contains(msg, ";") {
			actions = append(actions, CodeAction{
				Title:       "Add missing semicolon",
				Kind:        CodeActionQuickFix,
				Diagnostics: []Diagnostic{diag},
				Edit: &WorkspaceEdit{
					Changes: map[string][]TextEdit{
						uri: {
							{
								Range:   Range{Start: diag.Range.End, End: diag.Range.End},
								NewText: ";",
							},
						},
					},
				},
			})
		}
	}

	// Suggest uppercase for keywords
	if strings.Contains(msg, "keyword") {
		content, ok := h.server.Documents().GetContent(uri)
		if ok {
			lines := strings.Split(content, "\n")
			if diag.Range.Start.Line < len(lines) {
				line := lines[diag.Range.Start.Line]
				start := diag.Range.Start.Character
				end := diag.Range.End.Character
				if start < len(line) && end <= len(line) && start < end {
					word := line[start:end]
					upper := strings.ToUpper(word)
					if word != upper {
						actions = append(actions, CodeAction{
							Title:       fmt.Sprintf("Convert '%s' to uppercase", word),
							Kind:        CodeActionQuickFix,
							Diagnostics: []Diagnostic{diag},
							Edit: &WorkspaceEdit{
								Changes: map[string][]TextEdit{
									uri: {
										{
											Range:   diag.Range,
											NewText: upper,
										},
									},
								},
							},
						})
					}
				}
			}
		}
	}

	return actions
}

// truncateForLog truncates raw JSON for logging purposes to avoid overly verbose logs
func truncateForLog(data json.RawMessage) string {
	const maxLen = 200
	s := string(data)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
