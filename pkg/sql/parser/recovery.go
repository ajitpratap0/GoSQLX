package parser

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

// ParseError represents a parse error with position information.
// It preserves the original error via Cause for use with errors.Is/As.
type ParseError struct {
	Msg       string
	TokenIdx  int
	Line      int
	Column    int
	TokenType string
	Literal   string
	Cause     error // original error, accessible via Unwrap()
}

func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("parse error at line %d, column %d (token %d): %s", e.Line, e.Column, e.TokenIdx, e.Msg)
	}
	return fmt.Sprintf("parse error at token %d: %s", e.TokenIdx, e.Msg)
}

// Unwrap returns the underlying cause, enabling errors.Is and errors.As.
func (e *ParseError) Unwrap() error {
	return e.Cause
}

// RecoveryResult holds the output of ParseWithRecovery, including parsed statements
// and any errors encountered during parsing.
//
// Callers MUST call Release() when done to return the parser to the pool.
//
// Example usage:
//
//	result := parser.ParseMultiWithRecovery(tokens)
//	defer result.Release()
//	for _, stmt := range result.Statements {
//	    // process statement
//	}
//	for _, err := range result.Errors {
//	    // handle error
//	}
type RecoveryResult struct {
	Statements []ast.Statement
	Errors     []error
	parser     *Parser // held for pool return
}

// Release returns the underlying parser to the pool.
// Must be called when the caller is done with the result.
// Safe to call multiple times.
func (r *RecoveryResult) Release() {
	if r.parser != nil {
		PutParser(r.parser)
		r.parser = nil
	}
}

// isStatementStartingKeyword checks if the current token is a statement-starting keyword.
func (p *Parser) isStatementStartingKeyword() bool {
	if p.currentToken.ModelType != modelTypeUnset {
		switch p.currentToken.ModelType {
		case models.TokenTypeSelect, models.TokenTypeInsert, models.TokenTypeUpdate,
			models.TokenTypeDelete, models.TokenTypeCreate, models.TokenTypeAlter,
			models.TokenTypeDrop, models.TokenTypeWith, models.TokenTypeMerge,
			models.TokenTypeRefresh, models.TokenTypeTruncate,
			models.TokenTypeGrant, models.TokenTypeRevoke,
			models.TokenTypeSet, models.TokenTypeBegin,
			models.TokenTypeCommit, models.TokenTypeRollback:
			return true
		}
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

// ParseMultiWithRecovery obtains a parser from the pool and parses a token stream,
// recovering from errors to collect multiple errors and return a partial AST.
//
// Unlike Parse(), which stops at the first error, this function uses synchronization
// tokens (semicolons and statement-starting keywords) to skip past errors and
// continue parsing subsequent statements.
//
// The caller MUST call Release() on the returned RecoveryResult to return the
// parser to the pool.
//
// Thread Safety: This function is safe for concurrent use — each call obtains its
// own parser instance from the pool.
//
// Example:
//
//	result := parser.ParseMultiWithRecovery(tokens)
//	defer result.Release()
//	fmt.Printf("parsed %d statements with %d errors\n", len(result.Statements), len(result.Errors))
func ParseMultiWithRecovery(tokens []token.Token) *RecoveryResult {
	p := GetParser()
	stmts, errs := p.parseWithRecovery(tokens)
	return &RecoveryResult{
		Statements: stmts,
		Errors:     errs,
		parser:     p,
	}
}

// ParseWithRecovery parses a token stream, recovering from errors to collect multiple
// errors and return a partial AST with successfully parsed statements.
//
// WARNING: This method mutates the parser's internal state (tokens, currentPos) and
// is NOT safe for concurrent use on the same Parser instance. For thread-safe usage,
// prefer ParseMultiWithRecovery() which obtains a parser from the pool.
//
// Callers are responsible for returning the parser to the pool via PutParser when done.
//
// Example:
//
//	p := parser.GetParser()
//	defer parser.PutParser(p)
//	stmts, errs := p.ParseWithRecovery(tokens)
func (p *Parser) ParseWithRecovery(tokens []token.Token) ([]ast.Statement, []error) {
	return p.parseWithRecovery(tokens)
}

// ParseWithRecoveryFromModelTokens parses tokenizer output with error recovery.
func (p *Parser) ParseWithRecoveryFromModelTokens(tokens []models.TokenWithSpan) ([]ast.Statement, []error) {
	converted, err := convertModelTokens(tokens)
	if err != nil {
		return nil, []error{fmt.Errorf("token conversion failed: %w", err)}
	}
	return p.parseWithRecovery(converted)
}

// parseWithRecovery is the internal implementation shared by both public APIs.
func (p *Parser) parseWithRecovery(tokens []token.Token) ([]ast.Statement, []error) {
	tokens = normalizeTokens(tokens)
	p.tokens = tokens
	p.currentPos = 0
	if len(tokens) > 0 {
		p.currentToken = tokens[0]
	}

	statements := make([]ast.Statement, 0, 8)
	errors := make([]error, 0, 4)

	for p.currentPos < len(tokens) && !p.isType(models.TokenTypeEOF) {
		// Skip semicolons between statements
		if p.isType(models.TokenTypeSemicolon) {
			p.advance()
			continue
		}

		stmtStartPos := p.currentPos
		stmt, err := p.parseStatement()
		if err != nil {
			// Create a ParseError with position info, preserving original error
			loc := p.currentLocation()
			pe := &ParseError{
				Msg:      err.Error(),
				TokenIdx: stmtStartPos,
				Line:     loc.Line,
				Column:   loc.Column,
				Cause:    err,
			}
			if stmtStartPos < len(tokens) {
				pe.TokenType = string(tokens[stmtStartPos].Type)
				pe.Literal = tokens[stmtStartPos].Literal
			}
			errors = append(errors, pe)
			// If parseStatement didn't advance (e.g., unrecognized keyword),
			// advance at least one token to avoid infinite loops.
			if p.currentPos == stmtStartPos {
				p.advance()
			}
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
