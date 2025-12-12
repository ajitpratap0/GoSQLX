// Package models provides core data structures for SQL tokenization and parsing,
// including tokens, spans, locations, and error types.
//
// This package is the foundation of GoSQLX v1.6.0, providing high-performance,
// zero-copy token types with comprehensive PostgreSQL and SQL standard support.
//
// See doc.go for complete package documentation and examples.
package models

// Token represents a SQL token with its value and metadata.
//
// Token is the fundamental unit of lexical analysis in GoSQLX. Each token
// represents a meaningful element in SQL source code: keywords, identifiers,
// operators, literals, or punctuation.
//
// Tokens are lightweight value types designed for use with object pooling
// and zero-copy operations. They are immutable and safe for concurrent use.
//
// Fields:
//   - Type: The token category (keyword, operator, literal, etc.)
//   - Value: The string representation of the token
//   - Word: Optional Word struct for keyword/identifier tokens
//   - Long: Flag for numeric tokens indicating long integer (int64)
//   - Quote: Quote character used for quoted strings/identifiers (' or ")
//
// Example usage:
//
//	token := models.Token{
//	    Type:  models.TokenTypeSelect,
//	    Value: "SELECT",
//	}
//
//	// Check token category
//	if token.Type.IsKeyword() {
//	    fmt.Println("Found SQL keyword:", token.Value)
//	}
//
// Performance: Tokens are stack-allocated value types with minimal memory overhead.
// Used extensively with sync.Pool for zero-allocation parsing in hot paths.
type Token struct {
	Type  TokenType
	Value string
	Word  *Word // For TokenTypeWord
	Long  bool  // For TokenTypeNumber to indicate if it's a long number
	Quote rune  // For quoted strings and identifiers
}

// Word represents a keyword or identifier with its properties.
//
// Word is used to distinguish between different types of word tokens:
// SQL keywords (SELECT, FROM, WHERE), identifiers (table/column names),
// and quoted identifiers ("column name" or [column name]).
//
// Fields:
//   - Value: The actual text of the word (case-preserved)
//   - QuoteStyle: The quote character if this is a quoted identifier (", `, [, etc.)
//   - Keyword: Pointer to Keyword struct if this word is a SQL keyword (nil for identifiers)
//
// Example:
//
//	// SQL keyword
//	word := &models.Word{
//	    Value:   "SELECT",
//	    Keyword: &models.Keyword{Word: "SELECT", Reserved: true},
//	}
//
//	// Quoted identifier
//	word := &models.Word{
//	    Value:      "column name",
//	    QuoteStyle: '"',
//	}
type Word struct {
	Value      string   // The actual text value
	QuoteStyle rune     // The quote character used (if quoted)
	Keyword    *Keyword // If this word is a keyword
}

// Keyword represents a lexical keyword with its properties.
//
// Keywords are SQL reserved words or dialect-specific keywords that have
// special meaning in SQL syntax. GoSQLX supports keywords from multiple
// SQL dialects: PostgreSQL, MySQL, SQL Server, Oracle, and SQLite.
//
// Fields:
//   - Word: The keyword text in uppercase (canonical form)
//   - Reserved: True if this is a reserved keyword that cannot be used as an identifier
//
// Example:
//
//	// Reserved keyword
//	kw := &models.Keyword{Word: "SELECT", Reserved: true}
//
//	// Non-reserved keyword
//	kw := &models.Keyword{Word: "RETURNING", Reserved: false}
//
// v1.6.0 adds support for PostgreSQL-specific keywords:
//   - LATERAL: Correlated subqueries in FROM clause
//   - RETURNING: Return modified rows from INSERT/UPDATE/DELETE
//   - FILTER: Conditional aggregation in window functions
type Keyword struct {
	Word     string // The actual keyword text
	Reserved bool   // Whether this is a reserved keyword
}

// Whitespace represents different types of whitespace tokens.
//
// Whitespace tokens are typically ignored during parsing but can be preserved
// for formatting tools, SQL formatters, or LSP servers that need to maintain
// original source formatting and comments.
//
// Fields:
//   - Type: The specific type of whitespace (space, newline, tab, comment)
//   - Content: The actual content (used for comments to preserve text)
//   - Prefix: Comment prefix for single-line comments (-- or # in MySQL)
//
// Example:
//
//	// Single-line comment
//	ws := models.Whitespace{
//	    Type:    models.WhitespaceTypeSingleLineComment,
//	    Content: "This is a comment",
//	    Prefix:  "--",
//	}
//
//	// Multi-line comment
//	ws := models.Whitespace{
//	    Type:    models.WhitespaceTypeMultiLineComment,
//	    Content: "/* Block comment */",
//	}
type Whitespace struct {
	Type    WhitespaceType
	Content string // For comments
	Prefix  string // For single line comments
}

// WhitespaceType represents the type of whitespace.
//
// Used to distinguish between different whitespace and comment types
// in SQL source code for accurate formatting and comment preservation.
type WhitespaceType int

const (
	WhitespaceTypeSpace             WhitespaceType = iota // Regular space character
	WhitespaceTypeNewline                                 // Line break (\n or \r\n)
	WhitespaceTypeTab                                     // Tab character (\t)
	WhitespaceTypeSingleLineComment                       // Single-line comment (-- or #)
	WhitespaceTypeMultiLineComment                        // Multi-line comment (/* ... */)
)
