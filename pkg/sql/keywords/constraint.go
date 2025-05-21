package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

func (k *Keywords) getConstraintKeywords() []Keyword {
	return []Keyword{
		{Word: "PRIMARY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "FOREIGN", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "KEY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "UNIQUE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "CHECK", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "CONSTRAINT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "REFERENCES", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DEFERRABLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "INITIALLY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "IMMEDIATE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "DEFERRED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "ENFORCED", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "EXCLUDE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "NO", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
		{Word: "INHERIT", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	}
}
