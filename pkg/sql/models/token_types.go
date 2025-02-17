package models

// TokenType represents different types of SQL tokens
type TokenType int

const (
	TokenTypeUnknown TokenType = iota

	// Basic token types
	TokenTypeIdentifier
	TokenTypeString
	TokenTypeOperator
	TokenTypeEquals
	TokenTypeLessThan
	TokenTypeGreaterThan
	TokenTypeLessEquals
	TokenTypeGreaterEquals
	TokenTypeNotEquals
	TokenTypeConcat
	TokenTypeCast
	TokenTypeDoubleArrow

	// Punctuation token types
	TokenTypeLeftParen
	TokenTypeRightParen
	TokenTypeLeftBracket
	TokenTypeRightBracket
	TokenTypeLeftBrace
	TokenTypeRightBrace
	TokenTypeDot

	// Join related token types
	TokenTypeFullJoin
	TokenTypeCrossJoin
	TokenTypeNaturalJoin
	TokenTypeUsing

	// DML related token types
	TokenTypeDistinct
	TokenTypeAll
	TokenTypeFetch
	TokenTypeNext
	TokenTypeRows
	TokenTypeOnly
	TokenTypeWith
	TokenTypeTies
	TokenTypeNulls
	TokenTypeFirst
	TokenTypeLast
)

// String returns the string representation of the token type
func (t TokenType) String() string {
	switch t {
	case TokenTypeFullJoin:
		return "FULL JOIN"
	case TokenTypeCrossJoin:
		return "CROSS JOIN"
	case TokenTypeNaturalJoin:
		return "NATURAL JOIN"
	case TokenTypeDistinct:
		return "DISTINCT"
	case TokenTypeAll:
		return "ALL"
	case TokenTypeFetch:
		return "FETCH"
	case TokenTypeNext:
		return "NEXT"
	case TokenTypeRows:
		return "ROWS"
	case TokenTypeOnly:
		return "ONLY"
	case TokenTypeWith:
		return "WITH"
	default:
		return "UNKNOWN"
	}
}
