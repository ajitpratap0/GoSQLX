package keywords

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Operator keywords
func (k *Keywords) getOperatorKeywords() []Keyword {
	return []Keyword{
		// Logical Operators
		{"AND", models.TokenTypeKeyword, true, false},
		{"OR", models.TokenTypeKeyword, true, false},
		{"NOT", models.TokenTypeKeyword, true, false},
		{"BETWEEN", models.TokenTypeKeyword, true, false},
		{"IN", models.TokenTypeIn, true, false},
		{"LIKE", models.TokenTypeKeyword, true, false},
		{"IS", models.TokenTypeKeyword, true, false},
		{"NULL", models.TokenTypeKeyword, true, false},
		{"EXISTS", models.TokenTypeKeyword, true, false},
		{"ANY", models.TokenTypeKeyword, true, false},
		{"SOME", models.TokenTypeKeyword, true, false},

		// Comparison Operators
		{"=", models.TokenTypeKeyword, true, false},
		{"<>", models.TokenTypeKeyword, true, false},
		{"!=", models.TokenTypeKeyword, true, false},
		{">", models.TokenTypeKeyword, true, false},
		{"<", models.TokenTypeKeyword, true, false},
		{">=", models.TokenTypeKeyword, true, false},
		{"<=", models.TokenTypeKeyword, true, false},
		{"<=>", models.TokenTypeKeyword, true, false},
		{"ILIKE", models.TokenTypeKeyword, true, false},
		{"SIMILAR TO", models.TokenTypeKeyword, true, false},
		{"NOT LIKE", models.TokenTypeKeyword, true, false},
		{"NOT ILIKE", models.TokenTypeKeyword, true, false},
		{"NOT SIMILAR TO", models.TokenTypeKeyword, true, false},
	}
}
