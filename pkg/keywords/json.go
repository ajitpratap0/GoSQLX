package keywords

import "GoSQLX/pkg/models"

func (k *Keywords) getJSONKeywords() []Keyword {
	return []Keyword{
		{"JSON", models.TokenTypeKeyword, true, false},
		{"JSONB", models.TokenTypeKeyword, true, false},
		{"JSON_TABLE", models.TokenTypeKeyword, true, false},
		{"OPENJSON", models.TokenTypeKeyword, true, false},
		{"WITHOUT_ARRAY_WRAPPER", models.TokenTypeKeyword, true, false},
		{"JSON_EXTRACT", models.TokenTypeKeyword, true, false},
		{"JSON_CONTAINS", models.TokenTypeKeyword, true, false},
		{"JSON_OBJECT", models.TokenTypeKeyword, true, false},
		{"JSON_ARRAY", models.TokenTypeKeyword, true, false},
		{"JSON_VALUE", models.TokenTypeKeyword, true, false},
		{"JSON_QUERY", models.TokenTypeKeyword, true, false},
		{"JSON_EXISTS", models.TokenTypeKeyword, true, false},
	}
}
