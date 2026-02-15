// Package token defines the Token struct and token pooling system for SQL lexical analysis.
//
// As of #215, the token system uses a unified integer-based type system (models.TokenType).
// The legacy string-based token.Type has been removed.
//
// # Token Structure
//
//	type Token struct {
//	    Type    models.TokenType // Int-based type (primary, for performance)
//	    Literal string           // The literal value of the token
//	}
//
// # Basic Usage
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//	    "github.com/ajitpratap0/GoSQLX/pkg/models"
//	)
//
//	tok := token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
//
//	if tok.IsType(models.TokenTypeSelect) {
//	    fmt.Println("This is a SELECT token")
//	}
//
//	if tok.IsAnyType(models.TokenTypeSelect, models.TokenTypeInsert) {
//	    fmt.Println("This is a DML statement")
//	}
//
// # Token Pool
//
// The package provides an object pool for zero-allocation token reuse:
//
//	tok := token.Get()
//	defer token.Put(tok)  // MANDATORY - return to pool when done
//
//	tok.Type = models.TokenTypeSelect
//	tok.Literal = "SELECT"
//
// # See Also
//
//   - pkg/models: Core token type definitions (models.TokenType)
//   - pkg/sql/tokenizer: SQL lexical analysis producing tokens
//   - pkg/sql/parser: Parser consuming tokens
package token
