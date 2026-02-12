package keywords

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// SQLDialect represents different SQL database dialects.
// Each dialect may have specific keywords that are not part of standard SQL.
type SQLDialect string

const (
	// DialectUnknown represents an unknown or unspecified SQL dialect
	DialectUnknown SQLDialect = "unknown"

	// DialectGeneric represents standard SQL keywords common to all dialects
	DialectGeneric SQLDialect = "generic"

	// DialectMySQL represents MySQL-specific keywords and extensions
	DialectMySQL SQLDialect = "mysql"

	// DialectPostgreSQL represents PostgreSQL-specific keywords and extensions.
	// v1.6.0 includes: MATERIALIZED, ILIKE, LATERAL, RETURNING, and more.
	DialectPostgreSQL SQLDialect = "postgresql"

	// DialectSQLite represents SQLite-specific keywords and extensions
	DialectSQLite SQLDialect = "sqlite"

	// DialectSQLServer represents SQL Server-specific keywords and extensions
	DialectSQLServer SQLDialect = "sqlserver"

	// DialectOracle represents Oracle-specific keywords and extensions
	DialectOracle SQLDialect = "oracle"

	// DialectSnowflake represents Snowflake-specific keywords and extensions.
	// Includes semi-structured data types (VARIANT, OBJECT), Snowflake objects
	// (WAREHOUSE, STREAM, TASK, PIPE, STAGE), time travel (BEFORE, AT),
	// data loading (COPY, PUT, GET), and Snowflake-specific functions (IFF, NVL, etc.)
	DialectSnowflake SQLDialect = "snowflake"

	// DialectBigQuery represents Google BigQuery-specific keywords and extensions
	DialectBigQuery SQLDialect = "bigquery"

	// DialectRedshift represents Amazon Redshift-specific keywords and extensions
	DialectRedshift SQLDialect = "redshift"
)

// DialectKeywords returns the additional keywords for a specific dialect.
// This is a convenience function for retrieving dialect-specific keyword lists
// without constructing a full Keywords instance.
//
// Returns nil for DialectGeneric and unrecognized dialects.
//
// Example:
//
//	snowflakeKws := keywords.DialectKeywords(keywords.DialectSnowflake)
//	for _, kw := range snowflakeKws {
//	    fmt.Println(kw.Word)
//	}
func DialectKeywords(dialect SQLDialect) []Keyword {
	switch dialect {
	case DialectSnowflake:
		return SNOWFLAKE_SPECIFIC
	case DialectMySQL:
		return MYSQL_SPECIFIC
	case DialectPostgreSQL:
		return POSTGRESQL_SPECIFIC
	case DialectSQLite:
		return SQLITE_SPECIFIC
	default:
		return nil
	}
}

// AllDialects returns all supported SQL dialect identifiers.
// This includes both fully implemented dialects (with dialect-specific keywords)
// and placeholder dialects that currently use only the base keyword set.
//
// Example:
//
//	for _, d := range keywords.AllDialects() {
//	    fmt.Println(d)
//	}
func AllDialects() []SQLDialect {
	return []SQLDialect{
		DialectGeneric,
		DialectPostgreSQL,
		DialectMySQL,
		DialectSQLServer,
		DialectOracle,
		DialectSQLite,
		DialectSnowflake,
		DialectBigQuery,
		DialectRedshift,
	}
}

// GetCompoundKeywords returns the compound keywords map.
// Compound keywords are multi-word SQL keywords like "GROUP BY", "ORDER BY",
// "GROUPING SETS", "MATERIALIZED VIEW", etc.
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	compounds := kw.GetCompoundKeywords()
//	for keyword, tokenType := range compounds {
//	    fmt.Printf("%s -> %v\n", keyword, tokenType)
//	}
func (k *Keywords) GetCompoundKeywords() KeywordCategory {
	return k.CompoundKeywords
}

// IsCompoundKeywordStart checks if a word can start a compound keyword.
// This is useful during tokenization to determine if lookahead is needed
// to recognize multi-word keywords.
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	kw.IsCompoundKeywordStart("GROUP")  // true - could be "GROUP BY"
//	kw.IsCompoundKeywordStart("SELECT") // false - not a compound keyword start
func (k *Keywords) IsCompoundKeywordStart(word string) bool {
	if k.ignoreCase {
		word = strings.ToUpper(word)
	}
	for compound := range k.CompoundKeywords {
		if strings.HasPrefix(compound, word+" ") {
			return true
		}
	}
	return false
}

// MYSQL_SPECIFIC contains MySQL-specific keywords and extensions.
// These keywords are recognized when using DialectMySQL.
//
// Examples: ZEROFILL, UNSIGNED, FORCE, IGNORE
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

// POSTGRESQL_SPECIFIC contains PostgreSQL-specific keywords and extensions.
// These keywords are recognized when using DialectPostgreSQL.
//
// v1.6.0 additions: MATERIALIZED, LATERAL (already in base keywords), RETURNING (in base)
// Examples: ILIKE, MATERIALIZED, SIMILAR, FREEZE, RECURSIVE, RETURNING
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

// SQLITE_SPECIFIC contains SQLite-specific keywords and extensions.
// These keywords are recognized when using DialectSQLite.
//
// Examples: AUTOINCREMENT, VACUUM, ATTACH, DETACH
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
