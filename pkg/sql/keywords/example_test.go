package keywords_test

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Example demonstrates basic keyword detection and token type identification.
func Example() {
	// Create a keywords instance for generic SQL dialect
	kw := keywords.New(keywords.DialectGeneric, true)

	// Check if a word is a SQL keyword
	if kw.IsKeyword("SELECT") {
		fmt.Println("SELECT is a keyword")
	}

	// Get the token type for a keyword
	tokenType := kw.GetTokenType("WHERE")
	fmt.Printf("WHERE token type: %v\n", tokenType)

	// Check if a keyword is reserved
	if kw.IsReserved("FROM") {
		fmt.Println("FROM is a reserved keyword")
	}

	// Output:
	// SELECT is a keyword
	// WHERE token type: WHERE
	// FROM is a reserved keyword
}

// Example_dialectSupport demonstrates SQL dialect-specific keyword recognition.
func Example_dialectSupport() {
	// Create keywords instance for PostgreSQL
	pgKw := keywords.New(keywords.DialectPostgreSQL, true)

	// PostgreSQL-specific keywords
	if pgKw.IsKeyword("ILIKE") {
		fmt.Println("ILIKE is a PostgreSQL keyword")
	}

	// Create keywords instance for MySQL
	mysqlKw := keywords.New(keywords.DialectMySQL, true)

	// MySQL-specific keywords
	if mysqlKw.IsKeyword("ZEROFILL") {
		fmt.Println("ZEROFILL is a MySQL keyword")
	}

	// Create keywords instance for SQLite
	sqliteKw := keywords.New(keywords.DialectSQLite, true)

	// SQLite-specific keywords
	if sqliteKw.IsKeyword("AUTOINCREMENT") {
		fmt.Println("AUTOINCREMENT is a SQLite keyword")
	}

	// Output:
	// ILIKE is a PostgreSQL keyword
	// ZEROFILL is a MySQL keyword
	// AUTOINCREMENT is a SQLite keyword
}

// Example_caseInsensitivity demonstrates case-insensitive keyword matching.
func Example_caseInsensitivity() {
	// Create keywords with case-insensitive matching (default)
	kw := keywords.New(keywords.DialectGeneric, true)

	// All of these should match
	examples := []string{"SELECT", "select", "Select", "SeLeCt"}

	for _, word := range examples {
		if kw.IsKeyword(word) {
			fmt.Printf("%s is recognized as SELECT keyword\n", word)
		}
	}

	// Output:
	// SELECT is recognized as SELECT keyword
	// select is recognized as SELECT keyword
	// Select is recognized as SELECT keyword
	// SeLeCt is recognized as SELECT keyword
}

// Example_tokenTypeMapping demonstrates mapping keywords to token types.
func Example_tokenTypeMapping() {
	kw := keywords.New(keywords.DialectGeneric, true)

	// Different keywords map to different token types
	keywords := map[string]models.TokenType{
		"SELECT": models.TokenTypeSelect,
		"FROM":   models.TokenTypeFrom,
		"WHERE":  models.TokenTypeWhere,
		"JOIN":   models.TokenTypeJoin,
		"GROUP":  models.TokenTypeGroup,
		"ORDER":  models.TokenTypeOrder,
	}

	for word, expectedType := range keywords {
		actualType := kw.GetTokenType(word)
		if actualType == expectedType {
			fmt.Printf("%s → %v ✓\n", word, actualType)
		}
	}

	// Unordered output:
	// SELECT → SELECT ✓
	// FROM → FROM ✓
	// WHERE → WHERE ✓
	// JOIN → JOIN ✓
	// GROUP → GROUP ✓
	// ORDER → ORDER ✓
}

// Example_reservedVsNonReserved demonstrates distinction between reserved and non-reserved keywords.
func Example_reservedVsNonReserved() {
	kw := keywords.New(keywords.DialectGeneric, true)

	// Reserved keywords (cannot be used as identifiers)
	reserved := []string{"SELECT", "FROM", "WHERE", "JOIN"}
	fmt.Println("Reserved keywords:")
	for _, word := range reserved {
		if kw.IsReserved(word) {
			fmt.Printf("  - %s\n", word)
		}
	}

	// Non-reserved keywords (window functions - can be used as identifiers in some contexts)
	nonReserved := []string{"ROW_NUMBER", "RANK", "DENSE_RANK"}
	fmt.Println("Non-reserved keywords:")
	for _, word := range nonReserved {
		if kw.IsKeyword(word) && !kw.IsReserved(word) {
			fmt.Printf("  - %s\n", word)
		}
	}

	// Output:
	// Reserved keywords:
	//   - SELECT
	//   - FROM
	//   - WHERE
	//   - JOIN
	// Non-reserved keywords:
	//   - ROW_NUMBER
	//   - RANK
	//   - DENSE_RANK
}

// Example_dialectComparison demonstrates differences between SQL dialects.
func Example_dialectComparison() {
	// Generic SQL
	generic := keywords.New(keywords.DialectGeneric, true)

	// PostgreSQL
	postgres := keywords.New(keywords.DialectPostgreSQL, true)

	// MySQL
	mysql := keywords.New(keywords.DialectMySQL, true)

	// Check dialect-specific keywords
	testWords := []string{"ILIKE", "ZEROFILL", "MATERIALIZED"}

	for _, word := range testWords {
		genericMatch := generic.IsKeyword(word)
		postgresMatch := postgres.IsKeyword(word)
		mysqlMatch := mysql.IsKeyword(word)

		fmt.Printf("%s: Generic=%v, PostgreSQL=%v, MySQL=%v\n",
			word, genericMatch, postgresMatch, mysqlMatch)
	}

	// Output:
	// ILIKE: Generic=false, PostgreSQL=true, MySQL=false
	// ZEROFILL: Generic=false, PostgreSQL=false, MySQL=true
	// MATERIALIZED: Generic=false, PostgreSQL=true, MySQL=false
}
