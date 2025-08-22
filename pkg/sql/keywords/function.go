package keywords

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Function keywords
func (k *Keywords) getFunctionKeywords() []Keyword {
	return []Keyword{
		// Mathematical Functions
		{"ABS", models.TokenTypeKeyword, false, false},
		{"CEIL", models.TokenTypeKeyword, false, false},
		{"FLOOR", models.TokenTypeKeyword, false, false},
		{"ROUND", models.TokenTypeKeyword, false, false},
		{"POWER", models.TokenTypeKeyword, false, false},
		{"MOD", models.TokenTypeKeyword, false, false},
		{"LN", models.TokenTypeKeyword, false, false},
		{"LOG", models.TokenTypeKeyword, false, false},
		{"SQRT", models.TokenTypeKeyword, false, false},
		{"EXP", models.TokenTypeKeyword, false, false},

		// String Functions
		{"LOWER", models.TokenTypeKeyword, false, false},
		{"UPPER", models.TokenTypeKeyword, false, false},
		{"TRIM", models.TokenTypeKeyword, false, false},
		{"SUBSTRING", models.TokenTypeKeyword, false, false},
		{"POSITION", models.TokenTypeKeyword, false, false},
		{"OVERLAY", models.TokenTypeKeyword, false, false},

		// Other Functions
		{"COALESCE", models.TokenTypeKeyword, false, false},
		{"NULLIF", models.TokenTypeKeyword, false, false},
		{"CAST", models.TokenTypeKeyword, false, false},
		{"CONVERT", models.TokenTypeKeyword, false, false},
	}
}
