package keywords

import "github.com/ajitpratapsingh/GoSQLX/pkg/models"

func (k *Keywords) getSecurityKeywords() []Keyword {
	return []Keyword{
		{Word: "GRANT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "REVOKE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ROLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "USER", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "PASSWORD", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "PRIVILEGES", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "PERMISSION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ADMIN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "SECURITY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "AUTHORIZATION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "AUTHENTICATED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ENCRYPTION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "AUDIT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "POLICY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "LOGIN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "SUPERUSER", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "BYPASSRLS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "NOCREATEDB", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "NOCREATEROLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "NOLOGIN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "CREATEDB", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "CREATEROLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "NOREPLICATION", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ENCRYPTED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ACCESS", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "PERMISSIVE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "RESTRICTIVE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	}
}
