// Package main demonstrates PostgreSQL FILTER clause parsing capabilities
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	fmt.Println("PostgreSQL FILTER Clause Examples")
	fmt.Println("==================================")
	fmt.Println()
	fmt.Println("The FILTER clause (SQL:2003) allows conditional aggregation,")
	fmt.Println("providing a cleaner alternative to CASE expressions in aggregates.")
	fmt.Println()

	examples := []struct {
		name        string
		sql         string
		description string
	}{
		// Basic FILTER usage
		{
			name: "Basic COUNT with FILTER",
			sql: `SELECT
    COUNT(*) AS total_orders,
    COUNT(*) FILTER (WHERE status = 'completed') AS completed_orders,
    COUNT(*) FILTER (WHERE status = 'pending') AS pending_orders
FROM orders`,
			description: "Count orders by status using FILTER",
		},
		{
			name: "SUM with FILTER",
			sql: `SELECT
    customer_id,
    SUM(amount) AS total_sales,
    SUM(amount) FILTER (WHERE sale_date >= '2024-01-01') AS ytd_sales
FROM sales
GROUP BY customer_id`,
			description: "Calculate total and YTD sales",
		},
		{
			name: "AVG with FILTER",
			sql: `SELECT
    product_category,
    AVG(rating) AS overall_avg,
    AVG(rating) FILTER (WHERE verified_purchase = true) AS verified_avg
FROM reviews
GROUP BY product_category`,
			description: "Compare average ratings across segments",
		},

		// Multiple FILTER conditions
		{
			name: "Multiple Conditions in FILTER",
			sql: `SELECT
    region,
    COUNT(*) FILTER (WHERE status = 'active' AND plan = 'premium') AS active_premium,
    COUNT(*) FILTER (WHERE status = 'active' AND plan = 'basic') AS active_basic
FROM subscriptions
GROUP BY region`,
			description: "FILTER with compound conditions",
		},
		{
			name: "FILTER with IN Clause",
			sql: `SELECT
    department,
    SUM(salary) AS total_salary,
    SUM(salary) FILTER (WHERE job_title IN ('Manager', 'Director', 'VP')) AS management_salary
FROM employees
GROUP BY department`,
			description: "FILTER with IN operator",
		},

		// Pivot-like query
		{
			name: "Pivot-like Query with FILTER",
			sql: `SELECT
    year,
    SUM(amount) FILTER (WHERE quarter = 1) AS q1,
    SUM(amount) FILTER (WHERE quarter = 2) AS q2,
    SUM(amount) FILTER (WHERE quarter = 3) AS q3,
    SUM(amount) FILTER (WHERE quarter = 4) AS q4
FROM orders
GROUP BY year
ORDER BY year`,
			description: "Create pivot table using FILTER",
		},

		// Combining with other features
		{
			name: "FILTER with CTE",
			sql: `WITH monthly_data AS (
    SELECT
        region,
        SUM(amount) AS total
    FROM sales
    GROUP BY region
)
SELECT
    SUM(total) AS total_sales,
    SUM(total) FILTER (WHERE region = 'North') AS north_sales,
    SUM(total) FILTER (WHERE region = 'South') AS south_sales
FROM monthly_data`,
			description: "FILTER within CTE-based query",
		},

		// Comparison with CASE
		{
			name: "FILTER vs CASE Comparison",
			sql: `SELECT
    department,
    COUNT(*) FILTER (WHERE salary > 100000) AS high_earners_filter,
    COUNT(CASE WHEN salary > 100000 THEN 1 END) AS high_earners_case
FROM employees
GROUP BY department`,
			description: "Compare FILTER syntax with traditional CASE",
		},

		// Real-world use cases
		{
			name: "E-commerce Dashboard Metrics",
			sql: `SELECT
    COUNT(*) AS total_orders,
    COUNT(*) FILTER (WHERE status = 'delivered') AS delivered,
    COUNT(*) FILTER (WHERE status = 'returned') AS returned,
    SUM(total) FILTER (WHERE status = 'delivered') AS delivered_revenue
FROM orders`,
			description: "Dashboard metrics for e-commerce",
		},
		{
			name: "User Engagement Analysis",
			sql: `SELECT
    user_segment,
    COUNT(*) AS total_users,
    COUNT(*) FILTER (WHERE last_login > '2024-01-01') AS active_users,
    AVG(session_duration) FILTER (WHERE device_type = 'mobile') AS avg_mobile_session
FROM users
GROUP BY user_segment`,
			description: "User engagement metrics with FILTER",
		},
	}

	for i, ex := range examples {
		fmt.Printf("%d. %s\n", i+1, ex.name)
		fmt.Printf("   Description: %s\n", ex.description)
		fmt.Println("   SQL:")
		printFilterSQL(ex.sql)
		fmt.Println()
		parseAndDisplayFilter(ex.sql)
		fmt.Println()
	}

	// Summary
	fmt.Println("FILTER Clause Benefits")
	fmt.Println("======================")
	fmt.Println()
	fmt.Println("1. Cleaner syntax than CASE expressions")
	fmt.Println("2. More readable conditional aggregations")
	fmt.Println("3. Works with all aggregate functions (COUNT, SUM, AVG, etc.)")
	fmt.Println("4. Works with window functions")
	fmt.Println("5. Can contain any valid WHERE clause condition")
	fmt.Println("6. SQL:2003 standard - portable across databases")
}

func printFilterSQL(sql string) {
	lines := splitFilterLines(sql)
	for _, line := range lines {
		fmt.Printf("      %s\n", line)
	}
}

func splitFilterLines(s string) []string {
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

func parseAndDisplayFilter(sql string) {
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
	tokens, err := parser.ConvertTokensForParser(tokensWithSpan)
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

	fmt.Println("   Parsed Successfully!")
	fmt.Printf("   - Statement Type: %s\n", getFilterStatementType(astObj.Statements[0]))
	fmt.Printf("   - Token Count: %d\n", len(tokens))

	// Count FILTER clauses
	filterCount := countFilterClauses(sql)
	if filterCount > 0 {
		fmt.Printf("   - FILTER Clauses: %d\n", filterCount)
	}

	// Show aggregate functions used
	aggs := findAggregates(sql)
	if len(aggs) > 0 {
		fmt.Printf("   - Aggregate Functions: %v\n", aggs)
	}
}

func getFilterStatementType(stmt ast.Statement) string {
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

func countFilterClauses(sql string) int {
	count := 0
	searchTerm := "FILTER"
	for i := 0; i <= len(sql)-len(searchTerm); i++ {
		if len(sql) >= i+len(searchTerm) {
			substr := sql[i : i+len(searchTerm)]
			if (substr == "FILTER" || substr == "filter") &&
				(i == 0 || !isAlphaNum(sql[i-1])) &&
				(i+len(searchTerm) >= len(sql) || !isAlphaNum(sql[i+len(searchTerm)])) {
				count++
			}
		}
	}
	return count
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func findAggregates(sql string) []string {
	aggregates := []string{"COUNT", "SUM", "AVG", "MIN", "MAX", "STDDEV", "VARIANCE"}
	found := make(map[string]bool)

	for _, agg := range aggregates {
		// Simple case-insensitive search
		for i := 0; i <= len(sql)-len(agg); i++ {
			match := true
			for j := 0; j < len(agg); j++ {
				c := sql[i+j]
				if c >= 'a' && c <= 'z' {
					c -= 32 // to uppercase
				}
				if c != agg[j] {
					match = false
					break
				}
			}
			if match && (i+len(agg) < len(sql) && sql[i+len(agg)] == '(') {
				found[agg] = true
				break
			}
		}
	}

	result := make([]string, 0, len(found))
	for agg := range found {
		result = append(result, agg)
	}
	return result
}
