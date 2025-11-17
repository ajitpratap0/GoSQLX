package linter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Context provides all information needed for linting
type Context struct {
	// Source SQL content
	SQL string

	// SQL split into lines for convenience
	Lines []string

	// Tokenization results (if available)
	Tokens []models.TokenWithSpan

	// Parsing results (if available)
	AST      *ast.AST
	ParseErr error

	// File metadata
	Filename string
}

// NewContext creates a new linting context
func NewContext(sql string, filename string) *Context {
	lines := strings.Split(sql, "\n")

	return &Context{
		SQL:      sql,
		Lines:    lines,
		Filename: filename,
	}
}

// WithTokens adds tokenization results to the context
func (c *Context) WithTokens(tokens []models.TokenWithSpan) *Context {
	c.Tokens = tokens
	return c
}

// WithAST adds parsing results to the context
func (c *Context) WithAST(astObj *ast.AST, err error) *Context {
	c.AST = astObj
	c.ParseErr = err
	return c
}

// GetLine returns a specific line (1-indexed)
// Returns empty string if line number is out of bounds
func (c *Context) GetLine(lineNum int) string {
	if lineNum < 1 || lineNum > len(c.Lines) {
		return ""
	}
	return c.Lines[lineNum-1]
}

// GetLineCount returns the total number of lines
func (c *Context) GetLineCount() int {
	return len(c.Lines)
}
