package models

// NewToken creates a new Token with the given type and value
func NewToken(tokenType TokenType, value string) Token {
	return Token{
		Type:  tokenType,
		Value: value,
	}
}

// NewTokenWithSpan creates a new TokenWithSpan with the given type, value, and location
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

// NewEOFToken creates a new EOF token with span
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

// TokenAtLocation creates a new TokenWithSpan from a Token and location
func TokenAtLocation(token Token, start, end Location) TokenWithSpan {
	return TokenWithSpan{
		Token: token,
		Start: start,
		End:   end,
	}
}
