// Package keywords provides SQL keyword definitions and categorization for multiple SQL dialects.
//
// This package offers comprehensive SQL keyword management with support for multiple database
// dialects including PostgreSQL, MySQL, SQL Server, Oracle, and SQLite. It handles keyword
// categorization, case-insensitive matching, and dialect-specific extensions.
//
// # Key Features
//
//   - Multi-dialect keyword support (PostgreSQL, MySQL, SQLite, SQL Server, Oracle)
//   - Case-insensitive keyword matching (SQL standard behavior)
//   - Comprehensive keyword categorization (reserved, DML, DDL, window functions)
//   - Compound keyword recognition (e.g., "GROUP BY", "GROUPING SETS")
//   - v1.6.0 PostgreSQL extensions (LATERAL, FILTER, RETURNING, MATERIALIZED)
//   - Window function keywords (OVER, PARTITION BY, ROWS, RANGE, etc.)
//   - SQL-99 grouping operations (ROLLUP, CUBE, GROUPING SETS)
//   - MERGE statement support (SQL:2003 F312)
//
// # Keyword Categories
//
// Keywords are organized into several categories:
//
//   - Reserved Keywords: Cannot be used as identifiers (SELECT, FROM, WHERE, etc.)
//   - Table Alias Reserved: Keywords reserved specifically for table alias context
//   - DML Keywords: Data Manipulation Language keywords (INSERT, UPDATE, DELETE)
//   - DDL Keywords: Data Definition Language keywords (CREATE, ALTER, DROP)
//   - Window Function Keywords: Window function specific keywords (OVER, PARTITION BY, etc.)
//   - Aggregate Keywords: Aggregate function keywords (COUNT, SUM, AVG, MIN, MAX)
//   - Compound Keywords: Multi-word keywords (GROUP BY, ORDER BY, GROUPING SETS)
//
// # SQL Dialects
//
// The package supports multiple SQL dialects with dialect-specific keywords:
//
//   - DialectGeneric: Standard SQL keywords common across all dialects
//   - DialectPostgreSQL: PostgreSQL-specific keywords (ILIKE, MATERIALIZED, LATERAL, RETURNING)
//   - DialectMySQL: MySQL-specific keywords (ZEROFILL, UNSIGNED, FORCE)
//   - DialectSQLite: SQLite-specific keywords (AUTOINCREMENT, VACUUM)
//
// # New in v1.6.0
//
// PostgreSQL Extensions:
//   - LATERAL: Correlated subqueries in FROM clause
//   - FILTER: Conditional aggregation (SQL:2003 T612)
//   - RETURNING: Return modified rows from INSERT/UPDATE/DELETE
//   - MATERIALIZED: Materialized view support
//   - DISTINCT ON: PostgreSQL-specific row selection
//
// DDL Operations:
//   - TRUNCATE: TRUNCATE TABLE statement (SQL:2008)
//   - FETCH: FETCH FIRST/NEXT clause (SQL-99 F861, F862)
//   - OFFSET: Result set pagination
//
// Grouping Operations:
//   - ROLLUP: Hierarchical subtotals (SQL-99 T431)
//   - CUBE: All possible grouping combinations (SQL-99 T431)
//   - GROUPING SETS: Explicit grouping combinations (SQL-99 T431)
//
// # Basic Usage
//
// Create a keywords instance and check for keyword recognition:
//
//	// Create keywords for generic SQL dialect
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// Check if a word is a keyword
//	if kw.IsKeyword("SELECT") {
//	    fmt.Println("SELECT is a keyword")
//	}
//
//	// Get the token type for a keyword
//	tokenType := kw.GetTokenType("WHERE")
//	fmt.Printf("Token type: %v\n", tokenType)
//
//	// Check if a keyword is reserved
//	if kw.IsReserved("FROM") {
//	    fmt.Println("FROM is reserved")
//	}
//
// # Dialect-Specific Keywords
//
// Use dialect-specific keyword recognition for PostgreSQL, MySQL, or SQLite:
//
//	// PostgreSQL dialect
//	pgKw := keywords.New(keywords.DialectPostgreSQL, true)
//	if pgKw.IsKeyword("LATERAL") {
//	    fmt.Println("LATERAL is a PostgreSQL keyword")
//	}
//
//	// MySQL dialect
//	mysqlKw := keywords.New(keywords.DialectMySQL, true)
//	if mysqlKw.IsKeyword("ZEROFILL") {
//	    fmt.Println("ZEROFILL is a MySQL keyword")
//	}
//
//	// SQLite dialect
//	sqliteKw := keywords.New(keywords.DialectSQLite, true)
//	if sqliteKw.IsKeyword("AUTOINCREMENT") {
//	    fmt.Println("AUTOINCREMENT is a SQLite keyword")
//	}
//
// # Case-Insensitive Matching
//
// All keyword matching is case-insensitive by default, following SQL standard behavior:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// All of these are recognized as the same keyword
//	kw.IsKeyword("SELECT")  // true
//	kw.IsKeyword("select")  // true
//	kw.IsKeyword("Select")  // true
//	kw.IsKeyword("SeLeCt")  // true
//
// # Token Type Mapping
//
// Keywords map to specific token types for the parser:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// Get token type for keywords
//	selectType := kw.GetTokenType("SELECT")   // models.TokenTypeSelect
//	fromType := kw.GetTokenType("FROM")       // models.TokenTypeFrom
//	whereType := kw.GetTokenType("WHERE")     // models.TokenTypeWhere
//	lateralType := kw.GetTokenType("LATERAL") // models.TokenTypeLateral (v1.6.0)
//
// # Compound Keywords
//
// Recognize multi-word SQL keywords:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// Check compound keywords
//	compoundKws := kw.GetCompoundKeywords()
//
//	// Examples of compound keywords:
//	// - "GROUP BY"
//	// - "ORDER BY"
//	// - "GROUPING SETS" (SQL-99)
//	// - "MATERIALIZED VIEW" (PostgreSQL)
//	// - "IF NOT EXISTS"
//	// - "PARTITION BY"
//
// # Reserved vs Non-Reserved Keywords
//
// The package distinguishes between reserved and non-reserved keywords:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// Reserved keywords (cannot be used as identifiers)
//	kw.IsReserved("SELECT")  // true - reserved
//	kw.IsReserved("FROM")    // true - reserved
//	kw.IsReserved("WHERE")   // true - reserved
//
//	// Non-reserved keywords (can be used as identifiers in some contexts)
//	kw.IsReserved("ROW_NUMBER")  // false - window function name
//	kw.IsReserved("RANK")        // false - window function name
//	kw.IsReserved("LAG")         // false - window function name
//
// # Window Function Support
//
// Full support for SQL-99 window function keywords:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//
//	// Window specification keywords
//	kw.GetTokenType("OVER")      // OVER clause
//	kw.GetTokenType("PARTITION") // PARTITION BY
//	kw.GetTokenType("ROWS")      // ROWS frame mode
//	kw.GetTokenType("RANGE")     // RANGE frame mode
//
//	// Frame boundary keywords
//	kw.GetTokenType("CURRENT")   // CURRENT ROW
//	kw.GetTokenType("UNBOUNDED") // UNBOUNDED PRECEDING/FOLLOWING
//	kw.GetTokenType("PRECEDING") // N PRECEDING
//	kw.GetTokenType("FOLLOWING") // N FOLLOWING
//
//	// Window function names (non-reserved)
//	kw.IsKeyword("ROW_NUMBER")   // true
//	kw.IsKeyword("RANK")         // true
//	kw.IsKeyword("DENSE_RANK")   // true
//	kw.IsKeyword("NTILE")        // true
//	kw.IsKeyword("LAG")          // true
//	kw.IsKeyword("LEAD")         // true
//	kw.IsKeyword("FIRST_VALUE")  // true
//	kw.IsKeyword("LAST_VALUE")   // true
//
// # PostgreSQL JSON Operators
//
// While JSON operators (->>, @>, etc.) are handled by the tokenizer as operators
// rather than keywords, dialect-specific keyword support enables proper parsing
// of PostgreSQL JSON features in context.
//
// # Performance Considerations
//
// Keyword lookup is optimized with:
//   - Pre-computed hash maps for O(1) keyword lookup
//   - Case-insensitive matching with uppercase normalization
//   - Minimal memory footprint with shared keyword definitions
//   - No allocations during keyword checking operations
//
// # Thread Safety
//
// Keywords instances are safe for concurrent read access after initialization.
// Create separate instances for different dialects rather than modifying
// a shared instance.
//
// # Integration with Tokenizer
//
// This package is used by the tokenizer (pkg/sql/tokenizer) to classify
// words as keywords and assign appropriate token types during lexical analysis.
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
//	)
//
//	// Create keywords for PostgreSQL
//	kw := keywords.New(keywords.DialectPostgreSQL, true)
//
//	// Create tokenizer with keyword support
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)
//
//	// Tokenizer uses keywords to classify tokens
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users WHERE active = true"))
//
// # SQL Standards Compliance
//
// The keyword definitions follow SQL standards:
//   - SQL-92: Core reserved keywords (SELECT, FROM, WHERE, etc.)
//   - SQL-99: Window functions, ROLLUP, CUBE, GROUPING SETS
//   - SQL:2003: MERGE statements, FILTER clause
//   - SQL:2008: TRUNCATE TABLE, FETCH FIRST/NEXT
//   - PostgreSQL 12+: LATERAL, MATERIALIZED, JSON operators
//
// # See Also
//
//   - pkg/models: Token type definitions
//   - pkg/sql/tokenizer: Lexical analysis using keywords
//   - pkg/sql/parser: Parser using token types from keywords
//   - docs/SQL_COMPATIBILITY.md: Complete SQL compatibility matrix
package keywords
