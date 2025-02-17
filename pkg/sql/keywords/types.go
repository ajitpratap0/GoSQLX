package keywords

import "github.com/ajitpratapsingh/GoSQLX/pkg/models"

// Keyword represents a SQL keyword with its properties
type Keyword struct {
	Word                  string
	Type                  models.TokenType
	Reserved              bool
	ReservedForTableAlias bool
}
