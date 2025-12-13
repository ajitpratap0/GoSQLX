package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Keyword represents a SQL keyword with its properties and reservation status.
//
// Each keyword has multiple attributes that determine how it can be used:
//   - Word: The keyword string (e.g., "SELECT", "LATERAL")
//   - Type: The token type assigned to this keyword (models.TokenType)
//   - Reserved: Whether the keyword is reserved and cannot be used as an identifier
//   - ReservedForTableAlias: Whether the keyword cannot be used as a table alias
//
// Example:
//
//	selectKeyword := Keyword{
//	    Word:                  "SELECT",
//	    Type:                  models.TokenTypeSelect,
//	    Reserved:              true,
//	    ReservedForTableAlias: true,
//	}
//
//	rankFunction := Keyword{
//	    Word:                  "RANK",
//	    Type:                  models.TokenTypeKeyword,
//	    Reserved:              false,  // Window function names are non-reserved
//	    ReservedForTableAlias: false,
//	}
type Keyword struct {
	Word                  string           // The keyword string (uppercase normalized)
	Type                  models.TokenType // Token type for this keyword
	Reserved              bool             // True if keyword cannot be used as identifier
	ReservedForTableAlias bool             // True if keyword cannot be used as table alias
}
