package linter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Context provides all information needed for linting at multiple levels.
//
// Context is passed to every rule's Check method and contains:
//   - Text level: Raw SQL and line-by-line access
//   - Token level: Tokenization results (if successful)
//   - AST level: Parsed structure (if successful)
//   - Metadata: Filename for reporting
//
// Rules should check if Tokens and AST are nil before using them, as
// tokenization and parsing are best-effort. Text-based rules can run
// even if tokenization fails; token-based rules can run if parsing fails.
//
// Example usage in a rule:
//
//	func (r *MyRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
//	    // Text level (always available)
//	    for lineNum, line := range ctx.Lines {
//	        // Check line content
//	    }
//
//	    // Token level (check availability)
//	    if ctx.Tokens != nil {
//	        for _, tok := range ctx.Tokens {
//	            // Analyze tokens
//	        }
//	    }
//
//	    // AST level (check availability and parse success)
//	    if ctx.AST != nil && ctx.ParseErr == nil {
//	        for _, stmt := range ctx.AST.Statements {
//	            // Analyze AST structure
//	        }
//	    }
//
//	    return violations, nil
//	}
type Context struct {
	// Source SQL content (complete, unmodified)
	SQL string

	// SQL split into lines for line-by-line analysis (preserves original content)
	Lines []string

	// Tokenization results (nil if tokenization failed)
	Tokens []models.TokenWithSpan

	// Parsing results (nil if parsing failed)
	AST *ast.AST

	// Parse error (non-nil if parsing failed, nil if successful or not attempted)
	ParseErr error

	// File metadata for violation reporting
	Filename string
}

// NewContext creates a new linting context from SQL content and filename.
//
// The SQL is split into lines for convenient line-by-line analysis.
// Tokens and AST are initially nil and should be added via WithTokens
// and WithAST if tokenization and parsing succeed.
//
// Parameters:
//   - sql: The SQL content to lint
//   - filename: File path for violation reporting (can be a logical name like "<stdin>")
//
// Returns a new Context ready for rule checking.
func NewContext(sql string, filename string) *Context {
	lines := strings.Split(sql, "\n")

	return &Context{
		SQL:      sql,
		Lines:    lines,
		Filename: filename,
	}
}

// WithTokens adds tokenization results to the context.
//
// This method is called by the linter after successful tokenization.
// Rules can check ctx.Tokens != nil to determine if tokenization succeeded.
//
// Returns the context for method chaining.
func (c *Context) WithTokens(tokens []models.TokenWithSpan) *Context {
	c.Tokens = tokens
	return c
}

// WithAST adds parsing results to the context.
//
// This method is called by the linter after attempting to parse tokens.
// Both successful and failed parses are recorded. Rules should check
// ctx.AST != nil && ctx.ParseErr == nil to ensure usable AST.
//
// Parameters:
//   - astObj: The parsed AST (may be nil or incomplete if parsing failed)
//   - err: Parse error (nil if successful)
//
// Returns the context for method chaining.
func (c *Context) WithAST(astObj *ast.AST, err error) *Context {
	c.AST = astObj
	c.ParseErr = err
	return c
}

// GetLine returns a specific line by number (1-indexed).
//
// This is a convenience method for rules that need to access individual lines
// by line number from violation locations.
//
// Returns the line content, or empty string if line number is out of bounds.
//
// Example:
//
//	line := ctx.GetLine(42)  // Get line 42
//	if strings.TrimSpace(line) == "" {
//	    // Line 42 is blank or whitespace-only
//	}
func (c *Context) GetLine(lineNum int) string {
	if lineNum < 1 || lineNum > len(c.Lines) {
		return ""
	}
	return c.Lines[lineNum-1]
}

// GetLineCount returns the total number of lines in the SQL content.
//
// This is useful for rules that need to check file-level properties
// (e.g., overall structure, ending newlines).
func (c *Context) GetLineCount() int {
	return len(c.Lines)
}
