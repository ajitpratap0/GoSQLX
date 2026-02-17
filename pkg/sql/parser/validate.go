// Package parser — Validate() fast path for SQL validation without full AST construction.
// See issue #274.
package parser

import (
	"fmt"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Validate checks whether the given SQL string is syntactically valid without
// building a full AST. It tokenizes the input and runs the parser, but the
// returned AST is immediately released. This is significantly faster than
// Parse() when you only need to know if the SQL is valid.
func Validate(sql string) error {
	return ValidateBytes([]byte(sql))
}

// ValidateBytes is like Validate but accepts []byte to avoid a string copy.
func ValidateBytes(input []byte) error {
	// Fast path: empty/whitespace-only input is valid
	if len(trimBytes(input)) == 0 {
		return nil
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return fmt.Errorf("tokenization error: %w", err)
	}

	if len(tokens) == 0 {
		return nil
	}

	p := GetParser()
	defer PutParser(p)

	converted, convErr := convertModelTokens(tokens)
	if convErr != nil {
		return fmt.Errorf("token conversion failed: %w", convErr)
	}

	astResult, parseErr := p.Parse(converted)
	if parseErr != nil {
		return parseErr
	}
	ast.ReleaseAST(astResult)
	return nil
}

// trimBytes returns input with leading/trailing whitespace removed.
func trimBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}

// ParseBytes parses SQL from a []byte input without requiring a string conversion.
// This is especially useful when reading SQL from files via os.ReadFile.
// See issue #277.
func ParseBytes(input []byte) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return nil, fmt.Errorf("tokenization error: %w", err)
	}

	if len(tokens) == 0 {
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	p := GetParser()
	defer PutParser(p)

	return p.ParseFromModelTokens(tokens)
}

// ParseBytesWithTokens is like ParseBytes but also returns the token slice
// for callers that need both.
func ParseBytesWithTokens(input []byte) (*ast.AST, []token.Token, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return nil, nil, fmt.Errorf("tokenization error: %w", err)
	}

	if len(tokens) == 0 {
		return nil, nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	p := GetParser()
	defer PutParser(p)

	converted, convErr := convertModelTokens(tokens)
	if convErr != nil {
		return nil, nil, fmt.Errorf("token conversion failed: %w", convErr)
	}

	astResult, parseErr := p.Parse(converted)
	if parseErr != nil {
		return nil, nil, parseErr
	}

	return astResult, converted, nil
}

// ValidateWithDialect checks whether the given SQL string is syntactically valid
// using the specified SQL dialect for keyword recognition.
func ValidateWithDialect(sql string, dialect keywords.SQLDialect) error {
	return ValidateBytesWithDialect([]byte(sql), dialect)
}

// ValidateBytesWithDialect is like ValidateWithDialect but accepts []byte.
func ValidateBytesWithDialect(input []byte, dialect keywords.SQLDialect) error {
	if len(trimBytes(input)) == 0 {
		return nil
	}

	tkz, err := tokenizer.NewWithDialect(dialect)
	if err != nil {
		return fmt.Errorf("tokenizer initialization: %w", err)
	}

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return fmt.Errorf("tokenization error: %w", err)
	}

	if len(tokens) == 0 {
		return nil
	}

	p := NewParser(WithDialect(string(dialect)))
	defer p.Release()

	converted, convErr := convertModelTokens(tokens)
	if convErr != nil {
		return fmt.Errorf("token conversion failed: %w", convErr)
	}

	astResult, parseErr := p.Parse(converted)
	if parseErr != nil {
		return parseErr
	}
	ast.ReleaseAST(astResult)
	return nil
}

// ParseWithDialect parses SQL using the specified dialect for keyword recognition.
// This is a convenience function combining dialect-aware tokenization and parsing.
func ParseWithDialect(sql string, dialect keywords.SQLDialect) (*ast.AST, error) {
	return ParseBytesWithDialect([]byte(sql), dialect)
}

// ParseBytesWithDialect is like ParseWithDialect but accepts []byte.
func ParseBytesWithDialect(input []byte, dialect keywords.SQLDialect) (*ast.AST, error) {
	tkz, err := tokenizer.NewWithDialect(dialect)
	if err != nil {
		return nil, fmt.Errorf("tokenizer initialization: %w", err)
	}

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return nil, fmt.Errorf("tokenization error: %w", err)
	}

	if len(tokens) == 0 {
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	p := NewParser(WithDialect(string(dialect)))

	return p.ParseFromModelTokens(tokens)
}
