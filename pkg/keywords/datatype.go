package keywords

import (
	"GoSQLX/pkg/models"
)

// Datatype keywords
func (k *Keywords) getDataTypeKeywords() []Keyword {
	return []Keyword{
		// Numeric Types
		{"INT", models.TokenTypeKeyword, false, false},
		{"INTEGER", models.TokenTypeKeyword, false, false},
		{"SMALLINT", models.TokenTypeKeyword, false, false},
		{"BIGINT", models.TokenTypeKeyword, false, false},
		{"TINYINT", models.TokenTypeKeyword, false, false},
		{"DECIMAL", models.TokenTypeKeyword, false, false},
		{"NUMERIC", models.TokenTypeKeyword, false, false},
		{"FLOAT", models.TokenTypeKeyword, false, false},
		{"REAL", models.TokenTypeKeyword, false, false},
		{"DOUBLE", models.TokenTypeKeyword, false, false},
		{"BIT", models.TokenTypeKeyword, false, false},

		// String Types
		{"CHAR", models.TokenTypeKeyword, false, false},
		{"VARCHAR", models.TokenTypeKeyword, false, false},
		{"TEXT", models.TokenTypeKeyword, false, false},
		{"NCHAR", models.TokenTypeKeyword, false, false},
		{"NVARCHAR", models.TokenTypeKeyword, false, false},
		{"NTEXT", models.TokenTypeKeyword, false, false},
		{"BINARY", models.TokenTypeKeyword, false, false},
		{"VARBINARY", models.TokenTypeKeyword, false, false},
		{"IMAGE", models.TokenTypeKeyword, false, false},

		// Date/Time Types
		{"DATE", models.TokenTypeKeyword, false, false},
		{"TIME", models.TokenTypeKeyword, false, false},
		{"DATETIME", models.TokenTypeKeyword, false, false},
		{"TIMESTAMP", models.TokenTypeKeyword, false, false},
		{"YEAR", models.TokenTypeKeyword, false, false},
		{"INTERVAL", models.TokenTypeKeyword, false, false},

		// Other Types
		{"BOOLEAN", models.TokenTypeKeyword, false, false},
		{"JSON", models.TokenTypeKeyword, false, false},
		{"XML", models.TokenTypeKeyword, false, false},
		{"UUID", models.TokenTypeKeyword, false, false},
		{"ARRAY", models.TokenTypeKeyword, false, false},
		{"ENUM", models.TokenTypeKeyword, false, false},
		{"SET", models.TokenTypeKeyword, false, false},
		{"GEOMETRY", models.TokenTypeKeyword, false, false},
		{"GEOGRAPHY", models.TokenTypeKeyword, false, false},
	}
}
