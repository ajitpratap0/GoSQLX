package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

func (k *Keywords) getSchemaKeywords() []Keyword {
	return []Keyword{
		{"CATALOG", models.TokenTypeKeyword, true, false},
		{"SCHEMA", models.TokenTypeKeyword, true, false},
		{"DATABASE", models.TokenTypeKeyword, true, false},
		{"NAMESPACE", models.TokenTypeKeyword, true, false},
		{"MAPPING", models.TokenTypeKeyword, true, false},
		{"OWNER", models.TokenTypeKeyword, true, false},
		{"RENAME", models.TokenTypeKeyword, true, false},
		{"COMMENT", models.TokenTypeKeyword, true, false},
		{"ANALYZE", models.TokenTypeKeyword, true, false},
		{"STATISTICS", models.TokenTypeKeyword, true, false},
	}
}
