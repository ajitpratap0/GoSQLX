package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Formatter handles SQL formatting with custom rules
type Formatter struct {
	config FormatterConfig
	buffer *bytes.Buffer
	indent int
}

// NewFormatter creates a new formatter with the given configuration
func NewFormatter(config FormatterConfig) *Formatter {
	return &Formatter{
		config: config,
		buffer: &bytes.Buffer{},
		indent: 0,
	}
}

// Format formats SQL according to the configuration
func (f *Formatter) Format(sql string) (string, error) {
	// Reset buffer
	f.buffer.Reset()
	f.indent = 0

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization error: %w", err)
	}

	// Convert tokens for parser
	parserTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		return "", fmt.Errorf("token conversion error: %w", err)
	}

	// Create parser
	p := parser.NewParser()
	defer p.Release()

	// Parse
	result, err := p.Parse(parserTokens)
	if err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}

	// Format the AST - handle multiple statements
	if result != nil && len(result.Statements) > 0 {
		for _, stmt := range result.Statements {
			f.formatNode(stmt)
		}
	}

	return f.buffer.String(), nil
}

// formatNode formats an AST node
func (f *Formatter) formatNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.SelectStatement:
		f.formatSelectStatement(n)
	case *ast.InsertStatement:
		f.formatInsertStatement(n)
	case *ast.UpdateStatement:
		f.formatUpdateStatement(n)
	case *ast.DeleteStatement:
		f.formatDeleteStatement(n)
	default:
		// Fallback: just write the token literal
		f.writeString(node.TokenLiteral())
	}
}

// formatSelectStatement formats a SELECT statement
func (f *Formatter) formatSelectStatement(stmt *ast.SelectStatement) {
	// SELECT keyword
	f.writeKeyword("SELECT")
	f.newline()

	// Indent for columns
	f.increaseIndent()

	// Format columns
	if stmt.Columns != nil {
		for i, col := range stmt.Columns {
			if i > 0 {
				if f.config.CommaStyle == "trailing" {
					f.writeString(",")
					f.newline()
				} else {
					f.newline()
					f.writeString(", ")
				}
			}
			f.writeIndent()
			f.formatExpression(col)
		}
	}

	f.decreaseIndent()
	f.newline()

	// FROM clause
	if len(stmt.From) > 0 {
		f.writeKeyword("FROM")
		f.writeString(" ")
		for i, table := range stmt.From {
			if i > 0 {
				f.writeString(", ")
			}
			f.writeString(table.Name)
			if table.Alias != "" {
				f.writeString(" ")
				f.writeString(table.Alias)
			}
		}
		f.newline()
	}

	// WHERE clause
	if stmt.Where != nil {
		f.writeKeyword("WHERE")
		f.newline()
		f.increaseIndent()
		f.writeIndent()
		f.formatExpression(stmt.Where)
		f.decreaseIndent()
		f.newline()
	}

	// GROUP BY clause
	if len(stmt.GroupBy) > 0 {
		f.writeKeyword("GROUP BY")
		f.writeString(" ")
		for i, expr := range stmt.GroupBy {
			if i > 0 {
				f.writeString(", ")
			}
			f.formatExpression(expr)
		}
		f.newline()
	}

	// ORDER BY clause
	if len(stmt.OrderBy) > 0 {
		f.writeKeyword("ORDER BY")
		f.writeString(" ")
		for i, expr := range stmt.OrderBy {
			if i > 0 {
				f.writeString(", ")
			}
			f.formatExpression(expr)
		}
		f.newline()
	}

	// LIMIT clause
	if stmt.Limit != nil {
		f.writeKeyword("LIMIT")
		f.writeString(" ")
		f.writeString(fmt.Sprintf("%d", *stmt.Limit))
		f.newline()
	}
}

// formatInsertStatement formats an INSERT statement
func (f *Formatter) formatInsertStatement(stmt *ast.InsertStatement) {
	f.writeKeyword("INSERT INTO")
	f.writeString(" ")
	f.writeString(stmt.TableName)

	if len(stmt.Columns) > 0 {
		f.writeString(" (")
		for i, col := range stmt.Columns {
			if i > 0 {
				f.writeString(", ")
			}
			f.formatExpression(col)
		}
		f.writeString(")")
	}

	f.newline()
	f.writeKeyword("VALUES")
	f.writeString(" ")

	// Format values - simplified version
	f.writeString("(...)")
	f.newline()
}

// formatUpdateStatement formats an UPDATE statement
func (f *Formatter) formatUpdateStatement(stmt *ast.UpdateStatement) {
	f.writeKeyword("UPDATE")
	f.writeString(" ")
	f.writeString(stmt.TableName)

	f.newline()
	f.writeKeyword("SET")
	f.writeString(" ")
	f.writeString("...")
	f.newline()

	if stmt.Where != nil {
		f.writeKeyword("WHERE")
		f.writeString(" ")
		f.formatExpression(stmt.Where)
		f.newline()
	}
}

// formatDeleteStatement formats a DELETE statement
func (f *Formatter) formatDeleteStatement(stmt *ast.DeleteStatement) {
	f.writeKeyword("DELETE FROM")
	f.writeString(" ")
	f.writeString(stmt.TableName)
	f.newline()

	if stmt.Where != nil {
		f.writeKeyword("WHERE")
		f.writeString(" ")
		f.formatExpression(stmt.Where)
		f.newline()
	}
}

// formatExpression formats an expression - simplified version
func (f *Formatter) formatExpression(expr ast.Expression) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		f.writeString(e.Name)
	case *ast.BinaryExpression:
		f.formatExpression(e.Left)
		if f.config.SpaceAroundOperators {
			f.writeString(" ")
		}
		f.writeString(e.Operator)
		if f.config.SpaceAroundOperators {
			f.writeString(" ")
		}
		f.formatExpression(e.Right)
	case *ast.FunctionCall:
		funcName := e.Name
		if f.config.UppercaseFunctions {
			funcName = strings.ToUpper(funcName)
		}
		f.writeString(funcName)
		f.writeString("(")
		for i, arg := range e.Arguments {
			if i > 0 {
				f.writeString(", ")
			}
			f.formatExpression(arg)
		}
		f.writeString(")")
	default:
		// Fallback: write token literal
		f.writeString(expr.TokenLiteral())
	}
}

// writeKeyword writes a keyword with proper casing
func (f *Formatter) writeKeyword(keyword string) {
	switch f.config.KeywordCase {
	case "upper":
		f.writeString(strings.ToUpper(keyword))
	case "lower":
		f.writeString(strings.ToLower(keyword))
	case "title":
		f.writeString(strings.Title(strings.ToLower(keyword)))
	default:
		f.writeString(keyword)
	}
}

// writeString writes a string to the buffer
func (f *Formatter) writeString(s string) {
	f.buffer.WriteString(s)
}

// newline writes a newline
func (f *Formatter) newline() {
	f.buffer.WriteString("\n")
}

// writeIndent writes the current indentation
func (f *Formatter) writeIndent() {
	if f.config.IndentSpaces == 0 {
		for i := 0; i < f.indent; i++ {
			f.buffer.WriteString("\t")
		}
	} else {
		spaces := f.indent * f.config.IndentSpaces
		for i := 0; i < spaces; i++ {
			f.buffer.WriteString(" ")
		}
	}
}

// increaseIndent increases indentation level
func (f *Formatter) increaseIndent() {
	f.indent++
}

// decreaseIndent decreases indentation level
func (f *Formatter) decreaseIndent() {
	if f.indent > 0 {
		f.indent--
	}
}
