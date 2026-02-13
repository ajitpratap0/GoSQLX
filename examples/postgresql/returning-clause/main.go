// Package main demonstrates PostgreSQL RETURNING clause parsing capabilities
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	fmt.Println("PostgreSQL RETURNING Clause Examples")
	fmt.Println("=====================================")
	fmt.Println()
	fmt.Println("The RETURNING clause allows DML statements (INSERT, UPDATE, DELETE)")
	fmt.Println("to return data from modified rows, avoiding the need for separate queries.")
	fmt.Println()

	examples := []struct {
		name        string
		sql         string
		description string
	}{
		// INSERT with RETURNING
		{
			name:        "Basic INSERT RETURNING",
			sql:         `INSERT INTO users (name, email) VALUES ('John Doe', 'john@example.com') RETURNING id`,
			description: "Return auto-generated ID after INSERT",
		},
		{
			name:        "INSERT RETURNING Multiple Columns",
			sql:         `INSERT INTO users (name, email, status) VALUES ('Jane Doe', 'jane@example.com', 'active') RETURNING id, created_at, status`,
			description: "Return multiple columns including defaults",
		},
		{
			name:        "INSERT RETURNING All Columns",
			sql:         `INSERT INTO products (name, price, category) VALUES ('Widget', 29.99, 'Electronics') RETURNING *`,
			description: "Return all columns using *",
		},
		{
			name: "INSERT with Expression in RETURNING",
			sql: `INSERT INTO orders (customer_id, subtotal, tax_rate)
VALUES (123, 100.00, 0.08)
RETURNING id, subtotal, tax_rate, subtotal * tax_rate AS tax_amount`,
			description: "Return computed expressions",
		},
		{
			name: "Multi-row INSERT RETURNING",
			sql: `INSERT INTO tags (name, category) VALUES
    ('golang', 'language'),
    ('postgresql', 'database'),
    ('docker', 'devops')
RETURNING id, name, category`,
			description: "Return data from multiple inserted rows",
		},

		// UPDATE with RETURNING
		{
			name:        "Basic UPDATE RETURNING",
			sql:         `UPDATE users SET last_login = NOW() WHERE id = 1 RETURNING id, name, last_login`,
			description: "Return updated values",
		},
		{
			name: "UPDATE RETURNING Old and New Values",
			sql: `UPDATE products
SET price = price * 1.1
WHERE category = 'Electronics'
RETURNING id, name, price AS new_price`,
			description: "Return new values after price increase",
		},
		{
			name: "UPDATE with Subquery RETURNING",
			sql: `UPDATE orders o
SET status = 'processed'
WHERE customer_id = 100
RETURNING o.id, o.status`,
			description: "UPDATE with alias and RETURNING",
		},

		// DELETE with RETURNING
		{
			name:        "Basic DELETE RETURNING",
			sql:         `DELETE FROM sessions WHERE expired_at < NOW() RETURNING id, user_id, expired_at`,
			description: "Return deleted session info",
		},
		{
			name:        "DELETE RETURNING All",
			sql:         `DELETE FROM temp_data WHERE created_at < '2024-01-01' RETURNING *`,
			description: "Return all columns from deleted rows",
		},
		{
			name: "DELETE with Complex Condition RETURNING",
			sql: `DELETE FROM audit_logs
WHERE log_date < '2024-01-01'
AND log_level = 'DEBUG'
RETURNING id, log_date, message`,
			description: "Selective DELETE with RETURNING",
		},

		// Advanced patterns
		{
			name: "INSERT ON CONFLICT RETURNING",
			sql: `INSERT INTO user_preferences (user_id, preference_key, preference_value)
VALUES (1, 'theme', 'dark')
ON CONFLICT (user_id, preference_key)
DO UPDATE SET preference_value = EXCLUDED.preference_value
RETURNING id, user_id, preference_key, preference_value`,
			description: "UPSERT with RETURNING",
		},
		{
			name: "RETURNING with CTE for Logging",
			sql: `WITH deleted_users AS (
    DELETE FROM users
    WHERE last_login < '2022-01-01'
    AND status = 'inactive'
    RETURNING *
)
SELECT COUNT(*) FROM deleted_users`,
			description: "Use RETURNING in CTE for data archival",
		},
		{
			name: "RETURNING with Function Calls",
			sql: `INSERT INTO documents (title, content)
VALUES ('My Document', 'Lorem ipsum dolor sit amet')
RETURNING id, title, length(content) AS content_length`,
			description: "RETURNING with function calls",
		},
		{
			name: "Chained Operations with RETURNING",
			sql: `WITH new_order AS (
    INSERT INTO orders (customer_id, status)
    VALUES (100, 'new')
    RETURNING id, customer_id
)
SELECT * FROM new_order`,
			description: "Chain INSERTs using RETURNING in CTEs",
		},

		// Real-world use cases
		{
			name: "Inventory Management",
			sql: `UPDATE inventory
SET quantity = quantity - 5
WHERE product_id = 42 AND quantity >= 5
RETURNING product_id, quantity AS remaining_stock`,
			description: "Stock update with remaining count",
		},
		{
			name: "Queue Processing",
			sql: `DELETE FROM job_queue
WHERE id = 1
RETURNING id, job_type, payload`,
			description: "Atomic dequeue with RETURNING",
		},
	}

	for i, ex := range examples {
		fmt.Printf("%d. %s\n", i+1, ex.name)
		fmt.Printf("   Description: %s\n", ex.description)
		fmt.Println("   SQL:")
		printReturningSQL(ex.sql)
		fmt.Println()
		parseAndDisplayReturning(ex.sql)
		fmt.Println()
	}

	// Summary
	fmt.Println("RETURNING Clause Benefits")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Println("1. Avoid separate SELECT query after DML operations")
	fmt.Println("2. Atomic operation - no race conditions")
	fmt.Println("3. Get auto-generated values (IDs, timestamps, defaults)")
	fmt.Println("4. Useful in CTEs for chaining operations")
	fmt.Println("5. Can include expressions and computed columns")
	fmt.Println("6. Works with INSERT, UPDATE, DELETE statements")
	fmt.Println("7. Essential for UPSERT pattern (INSERT ON CONFLICT)")
}

func printReturningSQL(sql string) {
	lines := splitReturningLines(sql)
	for _, line := range lines {
		fmt.Printf("      %s\n", line)
	}
}

func splitReturningLines(s string) []string {
	var lines []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, string(current))
			current = nil
		} else {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		lines = append(lines, string(current))
	}
	return lines
}

func parseAndDisplayReturning(sql string) {
	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokensWithSpan, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		log.Printf("   Tokenize error: %v", err)
		return
	}

	// Convert tokens
	//lint:ignore SA1019 intentional use during #215 migration
	tokens, err := parser.ConvertTokensForParser(tokensWithSpan) //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
	if err != nil {
		log.Printf("   Token conversion error: %v", err)
		return
	}

	// Parse
	p := parser.NewParser()
	defer p.Release()

	astObj, err := p.Parse(tokens)
	if err != nil {
		log.Printf("   Parse error: %v", err)
		return
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		log.Println("   No statements parsed")
		return
	}

	stmt := astObj.Statements[0]
	fmt.Println("   Parsed Successfully!")
	fmt.Printf("   - Statement Type: %s\n", getReturningStatementType(stmt))
	fmt.Printf("   - Token Count: %d\n", len(tokens))

	// Check for RETURNING clause
	hasReturning := checkReturningClause(stmt)
	if hasReturning {
		fmt.Println("   - RETURNING Clause: present")
		returnCols := getReturningColumns(stmt)
		if returnCols > 0 {
			fmt.Printf("   - RETURNING Columns: %d\n", returnCols)
		}
	}

	// Check for CTE
	if hasCTE(sql) {
		fmt.Println("   - CTE (WITH clause): present")
	}

	// Check for ON CONFLICT
	if hasOnConflict(sql) {
		fmt.Println("   - ON CONFLICT (UPSERT): present")
	}
}

func getReturningStatementType(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.InsertStatement:
		return "INSERT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	default:
		return fmt.Sprintf("%T", stmt)
	}
}

func checkReturningClause(stmt ast.Statement) bool {
	switch s := stmt.(type) {
	case *ast.InsertStatement:
		return len(s.Returning) > 0
	case *ast.UpdateStatement:
		return len(s.Returning) > 0
	case *ast.DeleteStatement:
		return len(s.Returning) > 0
	}
	return false
}

func getReturningColumns(stmt ast.Statement) int {
	switch s := stmt.(type) {
	case *ast.InsertStatement:
		return len(s.Returning)
	case *ast.UpdateStatement:
		return len(s.Returning)
	case *ast.DeleteStatement:
		return len(s.Returning)
	}
	return 0
}

func hasCTE(sql string) bool {
	// Simple check for WITH keyword at the start
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == ' ' || c == '\n' || c == '\t' {
			continue
		}
		if i+4 <= len(sql) {
			word := sql[i : i+4]
			return word == "WITH" || word == "with"
		}
		break
	}
	return false
}

func hasOnConflict(sql string) bool {
	searchTerm := "ON CONFLICT"
	for i := 0; i <= len(sql)-len(searchTerm); i++ {
		if len(sql) >= i+len(searchTerm) {
			substr := sql[i : i+len(searchTerm)]
			if substr == "ON CONFLICT" || substr == "on conflict" || substr == "On Conflict" {
				return true
			}
		}
	}
	return false
}
