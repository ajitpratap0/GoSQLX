package keywords

import "github.com/ajitpratapsingh/GoSQLX/pkg/models"

// SQLDialect represents different SQL dialects
type SQLDialect int

const (
	DialectGeneric SQLDialect = iota
	DialectMySQL
	DialectPostgreSQL
	DialectSQLite
)

// MySQL specific keywords
var MYSQL_SPECIFIC = []Keyword{
	{Word: "BINARY", Type: models.TokenTypeKeyword},
	{Word: "CHAR", Type: models.TokenTypeKeyword},
	{Word: "DATETIME", Type: models.TokenTypeKeyword},
	{Word: "DECIMAL", Type: models.TokenTypeKeyword},
	{Word: "UNSIGNED", Type: models.TokenTypeKeyword},
	{Word: "ZEROFILL", Type: models.TokenTypeKeyword},
	{Word: "FORCE", Type: models.TokenTypeKeyword},
	{Word: "IGNORE", Type: models.TokenTypeKeyword},
	{Word: "INDEX", Type: models.TokenTypeKeyword},
	{Word: "KEY", Type: models.TokenTypeKeyword},
	{Word: "KEYS", Type: models.TokenTypeKeyword},
	{Word: "KILL", Type: models.TokenTypeKeyword},
	{Word: "OPTION", Type: models.TokenTypeKeyword},
	{Word: "PURGE", Type: models.TokenTypeKeyword},
	{Word: "READ", Type: models.TokenTypeKeyword},
	{Word: "WRITE", Type: models.TokenTypeKeyword},
	{Word: "STATUS", Type: models.TokenTypeKeyword},
	{Word: "VARIABLES", Type: models.TokenTypeKeyword},
}

// PostgreSQL specific keywords
var POSTGRESQL_SPECIFIC = []Keyword{
	{Word: "MATERIALIZED", Type: models.TokenTypeKeyword},
	{Word: "ILIKE", Type: models.TokenTypeKeyword},
	{Word: "SIMILAR", Type: models.TokenTypeKeyword},
	{Word: "FREEZE", Type: models.TokenTypeKeyword},
	{Word: "ANALYSE", Type: models.TokenTypeKeyword},
	{Word: "ANALYZE", Type: models.TokenTypeKeyword},
	{Word: "CONCURRENTLY", Type: models.TokenTypeKeyword},
	{Word: "REINDEX", Type: models.TokenTypeKeyword},
	{Word: "TOAST", Type: models.TokenTypeKeyword},
	{Word: "NOWAIT", Type: models.TokenTypeKeyword},
	{Word: "RECURSIVE", Type: models.TokenTypeKeyword},
	{Word: "RETURNING", Type: models.TokenTypeKeyword},
}

// SQLite specific keywords
var SQLITE_SPECIFIC = []Keyword{
	{Word: "ABORT", Type: models.TokenTypeKeyword},
	{Word: "ACTION", Type: models.TokenTypeKeyword},
	{Word: "AFTER", Type: models.TokenTypeKeyword},
	{Word: "ATTACH", Type: models.TokenTypeKeyword},
	{Word: "AUTOINCREMENT", Type: models.TokenTypeKeyword},
	{Word: "CONFLICT", Type: models.TokenTypeKeyword},
	{Word: "DATABASE", Type: models.TokenTypeKeyword},
	{Word: "DETACH", Type: models.TokenTypeKeyword},
	{Word: "EXCLUSIVE", Type: models.TokenTypeKeyword},
	{Word: "INDEXED", Type: models.TokenTypeKeyword},
	{Word: "INSTEAD", Type: models.TokenTypeKeyword},
	{Word: "PLAN", Type: models.TokenTypeKeyword},
	{Word: "QUERY", Type: models.TokenTypeKeyword},
	{Word: "RAISE", Type: models.TokenTypeKeyword},
	{Word: "REPLACE", Type: models.TokenTypeKeyword},
	{Word: "TEMP", Type: models.TokenTypeKeyword},
	{Word: "TEMPORARY", Type: models.TokenTypeKeyword},
	{Word: "VACUUM", Type: models.TokenTypeKeyword},
	{Word: "VIRTUAL", Type: models.TokenTypeKeyword},
}
