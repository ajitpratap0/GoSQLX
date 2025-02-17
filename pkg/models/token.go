package models

// Token represents a SQL token with its value and metadata
type Token struct {
	Type  TokenType
	Value string
	Word  *Word // For TokenTypeWord
	Long  bool  // For TokenTypeNumber to indicate if it's a long number
	Quote rune  // For quoted strings and identifiers
}

// Word represents a keyword or identifier with its properties
type Word struct {
	Value      string   // The actual text value
	QuoteStyle rune     // The quote character used (if quoted)
	Keyword    *Keyword // If this word is a keyword
}

// Keyword represents a lexical keyword with its properties
type Keyword struct {
	Word     string // The actual keyword text
	Reserved bool   // Whether this is a reserved keyword
}

// Whitespace represents different types of whitespace tokens
type Whitespace struct {
	Type    WhitespaceType
	Content string // For comments
	Prefix  string // For single line comments
}

// WhitespaceType represents the type of whitespace
type WhitespaceType int

const (
	WhitespaceTypeSpace WhitespaceType = iota
	WhitespaceTypeNewline
	WhitespaceTypeTab
	WhitespaceTypeSingleLineComment
	WhitespaceTypeMultiLineComment
)
