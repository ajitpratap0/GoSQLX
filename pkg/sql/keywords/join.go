package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
)

func (k *Keywords) getJoinKeywords() []Keyword {
	return []Keyword{
		{"JOIN", models.TokenTypeJoin, true, false},
		{"INNER", models.TokenTypeInner, true, false},
		{"LEFT", models.TokenTypeLeft, true, false},
		{"RIGHT", models.TokenTypeRight, true, false},
		{"OUTER", models.TokenTypeOuter, true, false},
		{"FULL", models.TokenTypeKeyword, true, false},
		{"CROSS", models.TokenTypeKeyword, true, false},
		{"ON", models.TokenTypeOn, true, false},
		{"USING", models.TokenTypeKeyword, true, false},
		{"LATERAL", models.TokenTypeKeyword, true, false},
		{"NATURAL", models.TokenTypeKeyword, true, false},
		{"SEMI", models.TokenTypeKeyword, true, false},
		{"ANTI", models.TokenTypeKeyword, true, false},
	}
}
