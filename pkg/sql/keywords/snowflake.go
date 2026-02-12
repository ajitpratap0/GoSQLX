package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// SNOWFLAKE_SPECIFIC contains Snowflake-specific keywords and extensions.
// These keywords are recognized when using DialectSnowflake.
//
// These extend the base SQL keywords with Snowflake-specific syntax for:
//   - Semi-structured data types (VARIANT, OBJECT)
//   - Semi-structured data functions (FLATTEN, PARSE_JSON, TYPEOF)
//   - Snowflake-specific clauses (CHANGES, STREAM, TASK, PIPE, STAGE)
//   - Snowflake DDL (WAREHOUSE, CLONE, UNDROP, RECLUSTER)
//   - Time travel (BEFORE, AT, STATEMENT)
//   - Data loading (COPY, PUT, GET, REMOVE)
//   - Access control (ROLE, GRANT, REVOKE, OWNERSHIP)
//   - Snowflake functions (IFF, IFNULL, NVL, NVL2, TRY_CAST, etc.)
//
// Keywords that already exist in the base keyword set (RESERVED_FOR_TABLE_ALIAS
// or ADDITIONAL_KEYWORDS) are NOT duplicated here. The following base keywords
// overlap with Snowflake features but are already defined:
//   - ARRAY (TokenTypeArray), LATERAL (TokenTypeLateral), QUALIFY, SAMPLE
//   - CLUSTER, OFFSET (TokenTypeOffset), SHARE (TokenTypeShare), LIST
//
// Examples: VARIANT, FLATTEN, WAREHOUSE, CLONE, IFF, RESULT_SCAN
var SNOWFLAKE_SPECIFIC = []Keyword{
	// Semi-structured data types
	{Word: "VARIANT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "OBJECT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Semi-structured data functions
	{Word: "FLATTEN", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "PARSE_JSON", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "STRIP_NULL_VALUE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TYPEOF", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Snowflake-specific clauses and objects
	{Word: "CHANGES", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "STREAM", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TASK", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "PIPE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "STAGE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "FILE_FORMAT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Snowflake DDL
	{Word: "WAREHOUSE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "DATABASE", Type: models.TokenTypeDatabase, Reserved: false, ReservedForTableAlias: false},
	{Word: "CLONE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "UNDROP", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	{Word: "RECLUSTER", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Time Travel
	{Word: "BEFORE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "AT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TIMESTAMP", Type: models.TokenTypeTimestamp, Reserved: false, ReservedForTableAlias: false},
	{Word: "STATEMENT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Data Loading
	{Word: "COPY", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: false},
	{Word: "PUT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "GET", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "REMOVE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Access Control
	{Word: "ROLE", Type: models.TokenTypeRole, Reserved: false, ReservedForTableAlias: false},
	{Word: "GRANT", Type: models.TokenTypeGrant, Reserved: true, ReservedForTableAlias: false},
	{Word: "REVOKE", Type: models.TokenTypeRevoke, Reserved: true, ReservedForTableAlias: false},
	{Word: "OWNERSHIP", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Snowflake-specific functions
	{Word: "IFF", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "IFNULL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NVL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NVL2", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "ZEROIFNULL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "EQUAL_NULL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TRY_CAST", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TRY_TO_NUMBER", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TRY_TO_DATE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Snowflake utility functions and metadata
	{Word: "RESULT_SCAN", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "GENERATOR", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "ROWCOUNT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "LAST_QUERY_ID", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "SYSTEM", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
}
