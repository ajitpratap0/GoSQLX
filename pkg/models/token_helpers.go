package models

// NewToken creates a new Token with the given type and value.
//
// Factory function for creating tokens without location information.
// Useful for testing, manual token construction, or scenarios where
// position tracking is not needed.
//
// Parameters:
//   - tokenType: The TokenType classification
//   - value: The string representation of the token
//
// Returns a Token with the specified type and value.
//
// Example:
//
//	token := models.NewToken(models.TokenTypeSelect, "SELECT")
//	// token.Type = TokenTypeSelect, token.Value = "SELECT"
//
//	numToken := models.NewToken(models.TokenTypeNumber, "42")
//	// numToken.Type = TokenTypeNumber, numToken.Value = "42"
func NewToken(tokenType TokenType, value string) Token {
	return Token{
		Type:  tokenType,
		Value: value,
	}
}

// NewTokenWithSpan creates a new TokenWithSpan with the given type, value, and location.
//
// Factory function for creating tokens with precise position information.
// This is the primary way to create tokens during tokenization.
//
// Parameters:
//   - tokenType: The TokenType classification
//   - value: The string representation of the token
//   - start: Beginning location in source (inclusive)
//   - end: Ending location in source (exclusive)
//
// Returns a TokenWithSpan with all fields populated.
//
// Example:
//
//	token := models.NewTokenWithSpan(
//	    models.TokenTypeSelect,
//	    "SELECT",
//	    models.Location{Line: 1, Column: 1},
//	    models.Location{Line: 1, Column: 7},
//	)
//	// Represents "SELECT" spanning columns 1-6 on line 1
//
// Used by tokenizer:
//
//	tokens = append(tokens, models.NewTokenWithSpan(
//	    tokenType, value, startLoc, endLoc,
//	))
func NewTokenWithSpan(tokenType TokenType, value string, start, end Location) TokenWithSpan {
	return TokenWithSpan{
		Token: Token{
			Type:  tokenType,
			Value: value,
		},
		Start: start,
		End:   end,
	}
}

// NewEOFToken creates a new EOF token with span.
//
// Factory function for creating End-Of-File tokens. EOF tokens mark the
// end of the input stream and are essential for parser termination.
//
// Parameters:
//   - pos: The location where EOF was encountered
//
// Returns a TokenWithSpan with type TokenTypeEOF and empty value.
// Both Start and End are set to the same position.
//
// Example:
//
//	eofToken := models.NewEOFToken(models.Location{Line: 10, Column: 1})
//	// eofToken.Token.Type = TokenTypeEOF
//	// eofToken.Token.Value = ""
//	// eofToken.Start = eofToken.End = {Line: 10, Column: 1}
//
// Used by tokenizer at end of input:
//
//	tokens = append(tokens, models.NewEOFToken(currentLocation))
func NewEOFToken(pos Location) TokenWithSpan {
	return TokenWithSpan{
		Token: Token{
			Type:  TokenTypeEOF,
			Value: "",
		},
		Start: pos,
		End:   pos,
	}
}

// TokenAtLocation creates a new TokenWithSpan from a Token and location.
//
// Convenience function for adding location information to an existing Token.
// Useful when token is created first and location is determined later.
//
// Parameters:
//   - token: The Token to wrap with location
//   - start: Beginning location in source (inclusive)
//   - end: Ending location in source (exclusive)
//
// Returns a TokenWithSpan combining the token and location.
//
// Example:
//
//	token := models.NewToken(models.TokenTypeSelect, "SELECT")
//	start := models.Location{Line: 1, Column: 1}
//	end := models.Location{Line: 1, Column: 7}
//	tokenWithSpan := models.TokenAtLocation(token, start, end)
func TokenAtLocation(token Token, start, end Location) TokenWithSpan {
	return TokenWithSpan{
		Token: token,
		Start: start,
		End:   end,
	}
}
