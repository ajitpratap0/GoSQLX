package models

// TokenWithSpan represents a token with its location in the source code.
//
// TokenWithSpan combines a Token with precise position information (Start and End locations).
// This is the primary representation used by the tokenizer output and consumed by the parser.
//
// Fields:
//   - Token: The token itself (type, value, metadata)
//   - Start: Beginning location of the token in source (inclusive)
//   - End: Ending location of the token in source (exclusive)
//
// Example:
//
//	// Token for "SELECT" at line 1, columns 1-7
//	tokenWithSpan := models.TokenWithSpan{
//	    Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"},
//	    Start: models.Location{Line: 1, Column: 1},
//	    End:   models.Location{Line: 1, Column: 7},
//	}
//
// Usage with tokenizer:
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte(sql))
//	// tokens is []TokenWithSpan with location information
//	for _, t := range tokens {
//	    fmt.Printf("Token %s at line %d, column %d\n",
//	        t.Token.Value, t.Start.Line, t.Start.Column)
//	}
//
// Used for error reporting:
//
//	// Create error at token location
//	err := errors.NewError(
//	    errors.ErrCodeUnexpectedToken,
//	    "unexpected token",
//	    tokenWithSpan.Start,
//	)
//
// Performance: TokenWithSpan is a value type designed for zero-copy operations.
// The tokenizer returns slices of TokenWithSpan without heap allocations.
type TokenWithSpan struct {
	Token Token    // The token with type and value
	Start Location // Start position (inclusive)
	End   Location // End position (exclusive)
}

// WrapToken wraps a token with an empty location.
//
// Creates a TokenWithSpan from a Token when location information is not available
// or not needed. The Start and End locations are set to zero values.
//
// Example:
//
//	token := models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}
//	wrapped := models.WrapToken(token)
//	// wrapped.Start and wrapped.End are both Location{Line: 0, Column: 0}
//
// Use case: Testing or scenarios where location tracking is not required.
func WrapToken(token Token) TokenWithSpan {
	emptyLoc := Location{}
	return TokenWithSpan{Token: token, Start: emptyLoc, End: emptyLoc}
}
