package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

// DDL keywords
func (k *Keywords) getDDLKeywords() []Keyword {
	return []Keyword{
		{Word: "CREATE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ALTER", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DROP", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TRUNCATE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "RENAME", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TABLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "INDEX", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "VIEW", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "SCHEMA", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DATABASE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "SEQUENCE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "FUNCTION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "PROCEDURE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TRIGGER", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DOMAIN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TYPE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "EXTENSION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "MATERIALIZED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "TEMPORARY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "UNLOGGED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	}
}
