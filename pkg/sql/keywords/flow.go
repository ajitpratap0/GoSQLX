package keywords

import "github.com/ajitpratapsingh/GoSQLX/pkg/models"

func (k *Keywords) getFlowControlKeywords() []Keyword {
	return []Keyword{
		{"CASE", models.TokenTypeCase, true, false},
		{"WHEN", models.TokenTypeWhen, true, false},
		{"THEN", models.TokenTypeThen, true, false},
		{"ELSE", models.TokenTypeElse, true, false},
		{"END", models.TokenTypeEnd, true, false},
		{"IF", models.TokenTypeKeyword, true, false},
		{"LOOP", models.TokenTypeKeyword, true, false},
		{"WHILE", models.TokenTypeKeyword, true, false},
		{"BEGIN BLOCK", models.TokenTypeKeyword, true, false},
		{"CONTINUE", models.TokenTypeKeyword, true, false},
		{"RETURN", models.TokenTypeKeyword, true, false},
		{"EXCEPTION", models.TokenTypeKeyword, true, false},
		{"RAISE", models.TokenTypeKeyword, true, false},
		{"DECLARE", models.TokenTypeKeyword, true, false},
		{"TRY", models.TokenTypeKeyword, true, false},
		{"CATCH", models.TokenTypeKeyword, true, false},
	}
}
