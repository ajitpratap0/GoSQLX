package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

func (k *Keywords) getTransactionKeywords() []Keyword {
	return []Keyword{
		{"BEGIN", models.TokenTypeKeyword, true, false},
		{"COMMIT", models.TokenTypeKeyword, true, false},
		{"ROLLBACK", models.TokenTypeKeyword, true, false},
		{"SAVEPOINT", models.TokenTypeKeyword, true, false},
		{"TRANSACTION", models.TokenTypeKeyword, true, false},
		{"ISOLATION", models.TokenTypeKeyword, true, false},
		{"LEVEL", models.TokenTypeKeyword, true, false},
		{"READ", models.TokenTypeKeyword, true, false},
		{"WRITE", models.TokenTypeKeyword, true, false},
		{"SERIALIZABLE", models.TokenTypeKeyword, true, false},
		{"REPEATABLE", models.TokenTypeKeyword, true, false},
		{"COMMITTED", models.TokenTypeKeyword, true, false},
		{"UNCOMMITTED", models.TokenTypeKeyword, true, false},
		{"WORK", models.TokenTypeKeyword, true, false},
		{"CHAIN", models.TokenTypeKeyword, true, false},
	}
}
