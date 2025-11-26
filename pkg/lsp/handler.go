package lsp

import (
	"encoding/json"
	"fmt"
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
				Change:    SyncFull,
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
		h.server.Logger().Printf("Failed to parse didOpen params: %v", err)
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
		h.server.Logger().Printf("Failed to parse didChange params: %v", err)
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
		h.server.Logger().Printf("Failed to parse didClose params: %v", err)
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
		h.server.Logger().Printf("Failed to parse didSave params: %v", err)
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

// createDiagnosticFromError creates a diagnostic from an error message
func (h *Handler) createDiagnosticFromError(content, errMsg string, defaultLine int) Diagnostic {
	// Try to extract position from error message
	// GoSQLX errors often include position info like "at line X, column Y"
	line := defaultLine
	char := 0

	// Simple heuristic: show error at first line if no position info
	// A more sophisticated implementation would parse the error message

	// Calculate end position (end of line or reasonable span)
	lines := strings.Split(content, "\n")
	endChar := 0
	if line < len(lines) {
		endChar = len(lines[line])
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

// handleHover provides hover information for SQL keywords
func (h *Handler) handleHover(params json.RawMessage) (*Hover, error) {
	var p TextDocumentPositionParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}

	doc, ok := h.server.Documents().Get(p.TextDocument.URI)
	if !ok {
		return nil, nil
	}

	// Get word at position
	word := doc.GetWordAtPosition(p.Position)
	if word == "" {
		return nil, nil
	}

	// Look up keyword documentation
	doc_text := getKeywordDocumentation(strings.ToUpper(word))
	if doc_text == "" {
		return nil, nil
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

	// Build completion items
	items := []CompletionItem{}
	for _, kw := range sqlKeywords {
		if prefix == "" || strings.HasPrefix(strings.ToUpper(kw.Label), prefix) {
			items = append(items, kw)
		}
	}

	// Limit results
	if len(items) > 50 {
		items = items[:50]
	}

	return &CompletionList{
		IsIncomplete: len(items) >= 50,
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
