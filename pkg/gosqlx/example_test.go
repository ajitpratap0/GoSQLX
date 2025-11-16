package gosqlx_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// ExampleParse demonstrates basic SQL parsing.
func ExampleParse() {
	sql := "SELECT * FROM users WHERE active = true"
	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed %d statement(s)\n", len(ast.Statements))
	// Output: Parsed 1 statement(s)
}

// ExampleValidate demonstrates SQL validation.
func ExampleValidate() {
	sql := "SELECT * FROM users"
	if err := gosqlx.Validate(sql); err != nil {
		fmt.Printf("Invalid SQL: %v\n", err)
		return
	}

	fmt.Println("Valid SQL")
	// Output: Valid SQL
}

// ExampleParseMultiple demonstrates parsing multiple SQL statements efficiently.
func ExampleParseMultiple() {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
		"SELECT * FROM products",
	}

	asts, err := gosqlx.ParseMultiple(queries)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed %d queries\n", len(asts))
	// Output: Parsed 3 queries
}

// ExampleFormat demonstrates SQL formatting with options.
func ExampleFormat() {
	sql := "SELECT * FROM users WHERE active = true"

	opts := gosqlx.DefaultFormatOptions()
	opts.AddSemicolon = true

	formatted, err := gosqlx.Format(sql, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Formatted SQL ends with semicolon: %v\n", formatted[len(formatted)-1] == ';')
	// Output: Formatted SQL ends with semicolon: true
}

// ExampleParseWithContext demonstrates parsing with context for cancellation.
func ExampleParseWithContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sql := "SELECT * FROM users"
	ast, err := gosqlx.ParseWithContext(ctx, sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed with context: %d statement(s)\n", len(ast.Statements))
	// Output: Parsed with context: 1 statement(s)
}

// ExampleParseWithTimeout demonstrates parsing with a timeout.
func ExampleParseWithTimeout() {
	sql := "SELECT * FROM users"
	ast, err := gosqlx.ParseWithTimeout(sql, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed with timeout: %d statement(s)\n", len(ast.Statements))
	// Output: Parsed with timeout: 1 statement(s)
}

// ExampleMustParse demonstrates MustParse for SQL literals.
func ExampleMustParse() {
	// Use MustParse only with SQL literals you control
	ast := gosqlx.MustParse("SELECT 1")

	fmt.Printf("Type: %T\n", ast)
	// Output: Type: *ast.AST
}

// ExampleParseBytes demonstrates parsing from a byte slice.
func ExampleParseBytes() {
	sqlBytes := []byte("SELECT * FROM users")

	ast, err := gosqlx.ParseBytes(sqlBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed from bytes: %d statement(s)\n", len(ast.Statements))
	// Output: Parsed from bytes: 1 statement(s)
}

// ExampleValidateMultiple demonstrates validating multiple SQL statements.
func ExampleValidateMultiple() {
	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO users (name) VALUES ('test')",
		"UPDATE users SET active = true WHERE id = 1",
	}

	if err := gosqlx.ValidateMultiple(queries); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}

	fmt.Println("All queries valid")
	// Output: All queries valid
}

// ExampleExtractTables demonstrates extracting table names from a query.
func ExampleExtractTables() {
	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	tables := gosqlx.ExtractTables(ast)
	fmt.Printf("Found %d tables\n", len(tables))
	// Output: Found 2 tables
}

// ExampleExtractColumns demonstrates extracting column names from a query.
func ExampleExtractColumns() {
	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true ORDER BY u.created_at"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	columns := gosqlx.ExtractColumns(ast)
	fmt.Printf("Found %d columns\n", len(columns))
	// Output: Found 4 columns
}

// ExampleExtractFunctions demonstrates extracting function names from a query.
func ExampleExtractFunctions() {
	sql := "SELECT COUNT(*), AVG(salary), UPPER(name) FROM employees"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	functions := gosqlx.ExtractFunctions(ast)
	fmt.Printf("Found %d functions\n", len(functions))
	// Output: Found 3 functions
}

// ExampleExtractMetadata demonstrates extracting comprehensive metadata from a query.
func ExampleExtractMetadata() {
	sql := `SELECT u.name, COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.name
		HAVING COUNT(o.id) > 5`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	metadata := gosqlx.ExtractMetadata(ast)
	fmt.Printf("Tables: %d, Columns: %d, Functions: %d\n",
		len(metadata.Tables), len(metadata.Columns), len(metadata.Functions))
	// Output: Tables: 2, Columns: 4, Functions: 1
}

// ExampleExtractTablesQualified demonstrates extracting qualified table names.
func ExampleExtractTablesQualified() {
	sql := "SELECT * FROM users JOIN orders ON users.id = orders.user_id"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	tables := gosqlx.ExtractTablesQualified(ast)
	fmt.Printf("Found %d tables\n", len(tables))
	// Output: Found 2 tables
}

// ExampleExtractColumnsQualified demonstrates extracting qualified column names.
func ExampleExtractColumnsQualified() {
	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	columns := gosqlx.ExtractColumnsQualified(ast)
	fmt.Printf("Found %d qualified columns\n", len(columns))
	// Output: Found 3 qualified columns
}

// Example_simple demonstrates the simplest way to parse SQL.
func Example_simple() {
	sql := "SELECT * FROM users"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed %d statement(s)\n", len(ast.Statements))
	// Output: Parsed 1 statement(s)
}

// Example_validate demonstrates SQL validation.
func Example_validate() {
	// Valid SQL
	if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
		fmt.Println("Invalid SQL")
	} else {
		fmt.Println("Valid SQL")
	}

	// Invalid SQL
	if err := gosqlx.Validate("INVALID SQL"); err != nil {
		fmt.Println("Invalid SQL detected")
	}

	// Output:
	// Valid SQL
	// Invalid SQL detected
}

// Example_batch demonstrates parsing multiple SQL statements efficiently.
func Example_batch() {
	queries := []string{
		"SELECT * FROM users",
		"SELECT * FROM orders",
		"SELECT * FROM products",
	}

	asts, err := gosqlx.ParseMultiple(queries)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully parsed %d queries\n", len(asts))
	// Output: Successfully parsed 3 queries
}

// Example_errorHandling demonstrates proper error handling.
func Example_errorHandling() {
	sql := "SELECT * FROM" // Invalid: missing table name

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		fmt.Println("Parse error occurred")
		// In real code: log detailed error message
		_ = err
		return
	}

	_ = ast
	// Output: Parse error occurred
}

// Example_mustParse demonstrates MustParse for SQL literals.
func Example_mustParse() {
	// Use MustParse only with SQL literals you control
	// (e.g., in tests or initialization code)
	ast := gosqlx.MustParse("SELECT 1")

	fmt.Printf("Type: %T\n", ast)
	// Output: Type: *ast.AST
}

// Example_complexQuery demonstrates parsing a complex SQL query.
func Example_complexQuery() {
	sql := `
		SELECT
			u.id,
			u.name,
			COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.id, u.name
		ORDER BY order_count DESC
	`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed complex query with %d statement(s)\n", len(ast.Statements))
	// Output: Parsed complex query with 1 statement(s)
}

// Example_windowFunctions demonstrates parsing SQL with window functions.
func Example_windowFunctions() {
	sql := "SELECT name, salary, ROW_NUMBER() OVER (ORDER BY salary DESC) as rank FROM employees"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully parsed window function query\n")
	_ = ast
	// Output: Successfully parsed window function query
}

// Example_cte demonstrates parsing Common Table Expressions (CTEs).
func Example_cte() {
	sql := `
		WITH active_users AS (
			SELECT * FROM users WHERE active = true
		)
		SELECT * FROM active_users
	`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Successfully parsed CTE query\n")
	_ = ast
	// Output: Successfully parsed CTE query
}

// Example_validateMultiple demonstrates validating multiple SQL statements.
func Example_validateMultiple() {
	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO users (name) VALUES ('test')",
		"UPDATE users SET active = true WHERE id = 1",
	}

	if err := gosqlx.ValidateMultiple(queries); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}

	fmt.Println("All queries are valid")
	// Output: All queries are valid
}

// Example_parseBytes demonstrates parsing from a byte slice.
func Example_parseBytes() {
	// Useful when SQL is already in byte form (e.g., from file I/O)
	sqlBytes := []byte("SELECT * FROM users")

	ast, err := gosqlx.ParseBytes(sqlBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed from bytes: %d statement(s)\n", len(ast.Statements))
	// Output: Parsed from bytes: 1 statement(s)
}

// Example_format demonstrates SQL formatting with options.
func Example_format() {
	sql := "SELECT * FROM users WHERE active = true"

	// Use default formatting options
	opts := gosqlx.DefaultFormatOptions()
	opts.AddSemicolon = true

	formatted, err := gosqlx.Format(sql, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Formatted SQL length: %d\n", len(formatted))
	// Output: Formatted SQL length: 40
}

// Example_formatWithOptions demonstrates custom formatting options.
func Example_formatWithOptions() {
	sql := "SELECT id, name FROM users"

	opts := gosqlx.FormatOptions{
		IndentSize:        4,
		UppercaseKeywords: true,
		AddSemicolon:      true,
		SingleLineLimit:   80,
	}

	formatted, err := gosqlx.Format(sql, opts)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Formatted with custom options: %d chars\n", len(formatted))
	// Output: Formatted with custom options: 27 chars
}

// Example_migrationFromLowLevel demonstrates migrating from low-level API.
func Example_migrationFromLowLevel() {
	// Instead of manually managing tokenizer and parser:
	// tkz := tokenizer.GetTokenizer()
	// defer tokenizer.PutTokenizer(tkz)
	// tokens, err := tkz.Tokenize([]byte(sql))
	// ...
	// p := parser.NewParser()
	// defer p.Release()
	// ast, err := p.Parse(tokens)

	// Simply use:
	ast, err := gosqlx.Parse("SELECT * FROM users")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Migrated to simple API: %d statement(s)\n", len(ast.Statements))
	// Output: Migrated to simple API: 1 statement(s)
}

// Example_realWorldUsage demonstrates a realistic use case.
func Example_realWorldUsage() {
	// Validate user input before executing
	userSQL := "SELECT * FROM users WHERE id = 1"

	// First validate
	if err := gosqlx.Validate(userSQL); err != nil {
		fmt.Println("Invalid SQL from user")
		return
	}

	// Parse to inspect structure
	ast, err := gosqlx.Parse(userSQL)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Valid query with %d statement(s)\n", len(ast.Statements))
	// Output: Valid query with 1 statement(s)
}

// Example_batchValidation demonstrates validating multiple queries.
func Example_batchValidation() {
	queries := []string{
		"SELECT * FROM users",
		"INSERT INTO logs (message) VALUES ('test')",
		"UPDATE users SET active = false WHERE id = 1",
		"DELETE FROM temp_data WHERE created_at < NOW()",
	}

	if err := gosqlx.ValidateMultiple(queries); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}

	fmt.Printf("All %d queries are valid\n", len(queries))
	// Output: All 4 queries are valid
}

// Example_advancedFeatures demonstrates parsing advanced SQL features.
func Example_advancedFeatures() {
	// Window functions
	windowSQL := "SELECT name, ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) as rank FROM employees"
	ast1, err := gosqlx.Parse(windowSQL)
	if err != nil {
		log.Fatal(err)
	}

	// CTEs
	cteSQL := "WITH active AS (SELECT * FROM users WHERE active = true) SELECT * FROM active"
	ast2, err := gosqlx.Parse(cteSQL)
	if err != nil {
		log.Fatal(err)
	}

	// JOINs
	joinSQL := "SELECT u.name, o.total FROM users u INNER JOIN orders o ON u.id = o.user_id"
	ast3, err := gosqlx.Parse(joinSQL)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Parsed window: %d, CTE: %d, JOIN: %d\n", len(ast1.Statements), len(ast2.Statements), len(ast3.Statements))
	// Output: Parsed window: 1, CTE: 1, JOIN: 1
}

// Example_extractTables demonstrates extracting table names from a query.
func Example_extractTables() {
	sql := "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	tables := gosqlx.ExtractTables(ast)
	fmt.Printf("Found %d tables\n", len(tables))
	// Output: Found 2 tables
}

// Example_extractColumns demonstrates extracting column names from a query.
func Example_extractColumns() {
	sql := "SELECT u.name, u.email FROM users u WHERE u.active = true ORDER BY u.created_at"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	columns := gosqlx.ExtractColumns(ast)
	fmt.Printf("Found %d columns\n", len(columns))
	// Output: Found 4 columns
}

// Example_extractFunctions demonstrates extracting function names from a query.
func Example_extractFunctions() {
	sql := "SELECT COUNT(*), AVG(salary), UPPER(name) FROM employees"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	functions := gosqlx.ExtractFunctions(ast)
	fmt.Printf("Found %d functions\n", len(functions))
	// Output: Found 3 functions
}

// Example_extractMetadata demonstrates extracting comprehensive metadata from a query.
func Example_extractMetadata() {
	sql := `SELECT u.name, COUNT(o.id) as order_count
		FROM users u
		LEFT JOIN orders o ON u.id = o.user_id
		WHERE u.active = true
		GROUP BY u.name
		HAVING COUNT(o.id) > 5`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	metadata := gosqlx.ExtractMetadata(ast)
	fmt.Printf("Tables: %d, Columns: %d, Functions: %d\n",
		len(metadata.Tables), len(metadata.Columns), len(metadata.Functions))
	// Output: Tables: 2, Columns: 4, Functions: 1
}

// Example_extractTablesQualified demonstrates extracting qualified table names.
func Example_extractTablesQualified() {
	sql := "SELECT * FROM users JOIN orders ON users.id = orders.user_id"

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	tables := gosqlx.ExtractTablesQualified(ast)
	fmt.Printf("Found %d tables\n", len(tables))
	// Output: Found 2 tables
}

// Example_analyzeQuery demonstrates using extraction for query analysis.
func Example_analyzeQuery() {
	sql := `SELECT
		u.username,
		COUNT(o.id) as total_orders,
		SUM(o.amount) as total_spent,
		UPPER(u.email) as email_upper
	FROM users u
	LEFT JOIN orders o ON u.id = o.user_id
	WHERE u.active = true AND o.status = 'completed'
	GROUP BY u.id, u.username, u.email
	HAVING COUNT(o.id) > 10
	ORDER BY total_spent DESC`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	metadata := gosqlx.ExtractMetadata(ast)

	fmt.Printf("Query Analysis:\n")
	fmt.Printf("- Joins %d tables\n", len(metadata.Tables))
	fmt.Printf("- References %d columns\n", len(metadata.Columns))
	fmt.Printf("- Uses %d functions\n", len(metadata.Functions))
	// Output:
	// Query Analysis:
	// - Joins 2 tables
	// - References 8 columns
	// - Uses 3 functions
}

// Example_extractFromCTE demonstrates extracting from queries with CTEs.
func Example_extractFromCTE() {
	sql := `WITH active_users AS (
		SELECT id, name FROM users WHERE active = true
	)
	SELECT name, COUNT(*) FROM active_users GROUP BY name`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	metadata := gosqlx.ExtractMetadata(ast)
	fmt.Printf("Tables found: %d\n", len(metadata.Tables))
	// Output: Tables found: 2
}

// Example_validationWithExtraction demonstrates combining validation with metadata extraction.
func Example_validationWithExtraction() {
	userSQL := "SELECT u.id, u.name FROM users u WHERE u.status = 'active'"

	// First validate
	if err := gosqlx.Validate(userSQL); err != nil {
		fmt.Println("Invalid SQL")
		return
	}

	// Parse and extract metadata
	ast, err := gosqlx.Parse(userSQL)
	if err != nil {
		log.Fatal(err)
	}

	metadata := gosqlx.ExtractMetadata(ast)

	// Check if accessing sensitive tables
	sensitiveTable := "users"
	for _, table := range metadata.Tables {
		if table == sensitiveTable {
			fmt.Printf("Query accesses sensitive table: %s\n", sensitiveTable)
		}
	}
	// Output: Query accesses sensitive table: users
}

// Example_extractWindowFunctions demonstrates extracting window functions.
func Example_extractWindowFunctions() {
	sql := `SELECT
		name,
		salary,
		ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rank,
		AVG(salary) OVER (PARTITION BY department) as dept_avg
	FROM employees`

	ast, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatal(err)
	}

	functions := gosqlx.ExtractFunctions(ast)
	fmt.Printf("Window functions found: %d\n", len(functions))
	// Output: Window functions found: 2
}
