package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// ParseError represents a parse error with position information.
type ParseError struct {
	Msg       string
	TokenIdx  int
	Line      int
	Column    int
	TokenType string
	Literal   string
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("parse error at line %d, column %d (token %d): %s", e.Line, e.Column, e.TokenIdx, e.Msg)
	}
	return fmt.Sprintf("parse error at token %d: %s", e.TokenIdx, e.Msg)
}

// isStatementStartingKeyword checks if the current token is a statement-starting keyword.
func (p *Parser) isStatementStartingKeyword() bool {
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeSelect, models.TokenTypeInsert, models.TokenTypeUpdate,
			models.TokenTypeDelete, models.TokenTypeCreate, models.TokenTypeAlter,
			models.TokenTypeDrop, models.TokenTypeWith, models.TokenTypeMerge,
			models.TokenTypeRefresh, models.TokenTypeTruncate:
			return true
		}
	}
	// Fallback: string comparison for tokens without ModelType (e.g., tests)
	switch string(p.currentToken.Type) {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP",
		"WITH", "MERGE", "REFRESH", "TRUNCATE":
		return true
	}
	return false
}

// synchronize advances the parser past the current error to a synchronization point:
// either past a semicolon or to a statement-starting keyword.
func (p *Parser) synchronize() {
	for p.currentPos < len(p.tokens) && !p.isType(models.TokenTypeEOF) {
		// If we hit a semicolon, consume it and stop
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
			return
		}
		// If we hit a statement-starting keyword, stop (don't consume it)
		if p.isStatementStartingKeyword() {
			return
		}
		p.advance()
	}
}

// ParseWithRecovery parses a token stream, recovering from errors to collect multiple
// errors and return a partial AST with successfully parsed statements.
//
// Unlike Parse(), which stops at the first error, this method uses synchronization
// tokens (semicolons and statement-starting keywords) to skip past errors and
// continue parsing subsequent statements.
//
// Parameters:
//   - tokens: Slice of parser tokens to parse
//
// Returns:
//   - []ast.Statement: Successfully parsed statements (may be empty)
//   - []error: All parse errors encountered (each includes position information)
func (p *Parser) ParseWithRecovery(tokens []token.Token) ([]ast.Statement, []error) {
	p.tokens = tokens
	p.currentPos = 0
	if len(tokens) > 0 {
		p.currentToken = tokens[0]
	}

	var statements []ast.Statement
	var errors []error

	for p.currentPos < len(tokens) && !p.isType(models.TokenTypeEOF) {
		// Skip semicolons between statements
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
			continue
		}

		savedPos := p.currentPos
		stmt, err := p.parseStatement()
		if err != nil {
			// Create a ParseError with position info
			loc := p.currentLocation()
			pe := &ParseError{
				Msg:       err.Error(),
				TokenIdx:  savedPos,
				Line:      loc.Line,
				Column:    loc.Column,
			}
			if savedPos < len(tokens) {
				pe.TokenType = string(tokens[savedPos].Type)
				pe.Literal = tokens[savedPos].Literal
			}
			errors = append(errors, pe)
			p.synchronize()
		} else {
			statements = append(statements, stmt)
			// Optionally consume semicolon after statement
			if p.isType(models.TokenTypeSemicolon) {
				p.advance()
			}
		}
	}

	return statements, errors
}
