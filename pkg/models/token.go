package models

// Token represents a SQL token
type Token struct {
	Type  TokenType
	Value string
}

// Keyword represents a lexical keyword with its properties
type Keyword struct {
	Word     string    // The actual keyword text
	Type     TokenType // The token type this keyword represents
	Reserved bool      // Whether this is a reserved keyword
}
