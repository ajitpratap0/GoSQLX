package keywords

import "github.com/ajitpratapsingh/GoSQLX/pkg/models"

// KeywordCategory represents a logical grouping of SQL keywords
type KeywordCategory struct {
	Name     string
	Keywords []Keyword
}

var (
	// DMLKeywords contains Data Manipulation Language keywords
	DMLKeywords = KeywordCategory{
		Name: "DML",
		Keywords: []Keyword{
			{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true},
			{Word: "INSERT", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "UPDATE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "DELETE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "MERGE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "UPSERT", Type: models.TokenTypeKeyword, Reserved: true},
		},
	}

	// DDLKeywords contains Data Definition Language keywords
	DDLKeywords = KeywordCategory{
		Name: "DDL",
		Keywords: []Keyword{
			{Word: "CREATE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ALTER", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "DROP", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "TRUNCATE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "RENAME", Type: models.TokenTypeKeyword, Reserved: true},
		},
	}

	// JoinKeywords contains keywords related to JOIN operations
	JoinKeywords = KeywordCategory{
		Name: "JOIN",
		Keywords: []Keyword{
			{Word: "JOIN", Type: models.TokenTypeJoin, Reserved: true},
			{Word: "INNER", Type: models.TokenTypeInner, Reserved: true},
			{Word: "LEFT", Type: models.TokenTypeLeft, Reserved: true},
			{Word: "RIGHT", Type: models.TokenTypeRight, Reserved: true},
			{Word: "FULL", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "OUTER", Type: models.TokenTypeOuter, Reserved: true},
			{Word: "CROSS", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "NATURAL", Type: models.TokenTypeKeyword, Reserved: true},
		},
	}

	// PredicateKeywords contains keywords used in WHERE clauses and conditions
	PredicateKeywords = KeywordCategory{
		Name: "PREDICATE",
		Keywords: []Keyword{
			{Word: "IN", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "BETWEEN", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "LIKE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ILIKE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "SIMILAR", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "REGEXP", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "NULL", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ANY", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ALL", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "SOME", Type: models.TokenTypeKeyword, Reserved: true},
		},
	}

	// AggregateKeywords contains keywords for aggregate functions
	AggregateKeywords = KeywordCategory{
		Name: "AGGREGATE",
		Keywords: []Keyword{
			{Word: "COUNT", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "SUM", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "AVG", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "MIN", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "MAX", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "GROUP", Type: models.TokenTypeGroup, Reserved: true},
			{Word: "HAVING", Type: models.TokenTypeHaving, Reserved: true},
		},
	}

	// WindowKeywords contains keywords for window functions
	WindowKeywords = KeywordCategory{
		Name: "WINDOW",
		Keywords: []Keyword{
			{Word: "OVER", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "PARTITION", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ROWS", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "RANGE", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "PRECEDING", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "FOLLOWING", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "UNBOUNDED", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "CURRENT", Type: models.TokenTypeKeyword, Reserved: true},
			{Word: "ROW", Type: models.TokenTypeKeyword, Reserved: true},
		},
	}
)

// AllCategories returns all keyword categories
func AllCategories() []KeywordCategory {
	return []KeywordCategory{
		DMLKeywords,
		DDLKeywords,
		JoinKeywords,
		PredicateKeywords,
		AggregateKeywords,
		WindowKeywords,
	}
}
