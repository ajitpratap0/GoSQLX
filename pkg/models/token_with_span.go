package models

// TokenWithSpan represents a token with its location in the source code
type TokenWithSpan struct {
	Token Token
	Start Location
	End   Location
}

// WrapToken wraps a token with an empty location
func WrapToken(token Token) TokenWithSpan {
	emptyLoc := Location{}
	return TokenWithSpan{Token: token, Start: emptyLoc, End: emptyLoc}
}
