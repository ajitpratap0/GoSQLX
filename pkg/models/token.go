// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	// Type is the TokenType classification of this token (e.g., TokenTypeSelect,
	// TokenTypeNumber, TokenTypeArrow). Use Type for all category checks.
	Type TokenType
	// Value is the raw string representation of the token as it appeared in the
	// SQL source (e.g., "SELECT", "42", "'hello'", "->").
	Value string
	// Word holds keyword or identifier metadata for TokenTypeWord tokens.
	// It is nil for all other token types.
	Word *Word
	// Long is true for TokenTypeNumber tokens whose value exceeds the range of
	// a 32-bit integer and must be interpreted as int64.
	Long bool
	// Quote is the quote character used to delimit the token, for quoted string
	// literals (') and quoted identifiers (", `, [). Zero for unquoted tokens.
	Quote rune
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
	// Value is the actual text of the word in its original case (e.g., "SELECT", "users").
	Value string
	// QuoteStyle is the quote character used to delimit a quoted identifier (", `, [).
	// Zero for unquoted words.
	QuoteStyle rune
	// Keyword holds SQL keyword metadata when this word is a recognized SQL keyword.
	// It is nil for plain identifiers (table names, column names, aliases).
	Keyword *Keyword
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
	// Word is the keyword text in its canonical uppercase form (e.g., "SELECT", "LATERAL").
	Word string
	// Reserved is true for keywords that cannot be used as unquoted identifiers
	// (e.g., SELECT, FROM, WHERE) and false for non-reserved keywords
	// (e.g., RETURNING, LATERAL, FILTER) that are valid as identifiers in some dialects.
	Reserved bool
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
	// Type identifies whether this is a space, newline, tab, or comment.
	Type WhitespaceType
	// Content holds the text of a comment, including its delimiters.
	// Empty for non-comment whitespace (spaces, newlines, tabs).
	Content string
	// Prefix holds the comment introducer for single-line comments ("--" or "#").
	// Empty for block comments and non-comment whitespace.
	Prefix string
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
