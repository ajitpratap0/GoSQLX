package keywords

import (
	"GoSQLX/pkg/models"
)

// DML keywords
func (k *Keywords) getDMLKeywords() []Keyword {
	return []Keyword{
		// SELECT keywords
		{"SELECT", models.TokenTypeSelect, true, false},
		{"FROM", models.TokenTypeFrom, true, false},
		{"WHERE", models.TokenTypeWhere, true, false},
		{"GROUP", models.TokenTypeGroup, true, false},
		{"HAVING", models.TokenTypeHaving, true, false},
		{"ORDER", models.TokenTypeOrder, true, false},
		{"BY", models.TokenTypeBy, true, false},
		{"AS", models.TokenTypeKeyword, true, true},
		{"COUNT", models.TokenTypeCount, false, false},
		{"DISTINCT", models.TokenTypeDistinct, true, false},
		{"ALL", models.TokenTypeAll, true, false},
		{"LIMIT", models.TokenTypeLimit, true, false},
		{"OFFSET", models.TokenTypeOffset, true, false},
		{"FETCH", models.TokenTypeFetch, true, false},
		{"NEXT", models.TokenTypeNext, true, false},
		{"ROWS", models.TokenTypeRows, true, false},
		{"ONLY", models.TokenTypeOnly, true, false},
		{"WITH", models.TokenTypeWith, true, false},
		{"TIES", models.TokenTypeTies, true, false},
		{"ASC", models.TokenTypeAsc, true, false},
		{"DESC", models.TokenTypeDesc, true, false},
		{"NULLS", models.TokenTypeNulls, true, false},
		{"FIRST", models.TokenTypeFirst, true, false},
		{"LAST", models.TokenTypeLast, true, false},

		// DML keywords
		{"INSERT", models.TokenTypeKeyword, true, false},
		{"UPDATE", models.TokenTypeKeyword, true, false},
		{"DELETE", models.TokenTypeKeyword, true, false},
		{"MERGE", models.TokenTypeKeyword, true, false},
		{"INTO", models.TokenTypeKeyword, true, false},
		{"VALUES", models.TokenTypeKeyword, true, false},
		{"SET", models.TokenTypeKeyword, true, false},
		{"REPLACE", models.TokenTypeKeyword, true, false},
		{"UPSERT", models.TokenTypeKeyword, true, false},
		{"OVERWRITE", models.TokenTypeKeyword, true, false},
		{"IGNORE", models.TokenTypeKeyword, true, false},
		{"RETURNING", models.TokenTypeKeyword, true, false},
		{"DEFAULT", models.TokenTypeKeyword, true, false},
		{"MATCHED", models.TokenTypeKeyword, true, false},
		{"UNMATCHED", models.TokenTypeKeyword, true, false},
		{"SOURCE", models.TokenTypeKeyword, true, false},
		{"TARGET", models.TokenTypeKeyword, true, false},
		{"MODIFY", models.TokenTypeKeyword, true, false},
		{"DUPLICATE", models.TokenTypeKeyword, true, false},
		{"FORCE", models.TokenTypeKeyword, true, false},
		{"LOW_PRIORITY", models.TokenTypeKeyword, true, false},
		{"HIGH_PRIORITY", models.TokenTypeKeyword, true, false},
		{"DELAYED", models.TokenTypeKeyword, true, false},
	}
}
