// Package main demonstrates PostgreSQL LATERAL JOIN parsing capabilities
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	fmt.Println("PostgreSQL LATERAL JOIN Examples")
	fmt.Println("=================================")
	fmt.Println()

	examples := []struct {
		name        string
		sql         string
		description string
	}{
		{
			name: "Basic LATERAL Subquery",
			sql: `SELECT u.name, recent.order_date, recent.total
FROM users u,
LATERAL (
    SELECT order_date, total
    FROM orders o
    WHERE o.user_id = u.id
    ORDER BY order_date DESC
    LIMIT 3
) AS recent`,
			description: "Get the 3 most recent orders for each user",
		},
		{
			name: "LATERAL with LEFT JOIN",
			sql: `SELECT d.dept_name, top_emp.name, top_emp.salary
FROM departments d
LEFT JOIN LATERAL (
    SELECT name, salary
    FROM employees e
    WHERE e.dept_id = d.id
    ORDER BY salary DESC
    LIMIT 1
) AS top_emp ON true`,
			description: "Get the highest-paid employee in each department",
		},
		{
			name: "LATERAL with CROSS JOIN",
			sql: `SELECT p.product_name, price_history.price, price_history.effective_date
FROM products p
CROSS JOIN LATERAL (
    SELECT price, effective_date
    FROM price_changes pc
    WHERE pc.product_id = p.id
    ORDER BY effective_date DESC
    LIMIT 5
) AS price_history`,
			description: "Get the last 5 price changes for each product",
		},
		{
			name: "Multiple LATERAL Joins",
			sql: `SELECT c.customer_name, orders.order_count, items.avg_price
FROM customers c,
LATERAL (
    SELECT COUNT(*) as order_count
    FROM orders o
    WHERE o.customer_id = c.id
) AS orders,
LATERAL (
    SELECT AVG(price) as avg_price
    FROM order_items oi
    JOIN orders o ON oi.order_id = o.id
    WHERE o.customer_id = c.id
) AS items`,
			description: "Combine multiple LATERAL subqueries",
		},
		{
			name: "LATERAL with Aggregation",
			sql: `SELECT region, city, population, ranking.rank
FROM cities c
CROSS JOIN LATERAL (
    SELECT COUNT(*) + 1 as rank
    FROM cities c2
    WHERE c2.region = c.region
    AND c2.population > c.population
) AS ranking
ORDER BY region, ranking.rank`,
			description: "Rank cities within each region by population",
		},
		{
			name: "Complex LATERAL with Window",
			sql: `SELECT u.username, activity.action_type, activity.action_count
FROM users u
LEFT JOIN LATERAL (
    SELECT action_type, COUNT(*) as action_count
    FROM user_actions ua
    WHERE ua.user_id = u.id
    GROUP BY action_type
    ORDER BY action_count DESC
) AS activity ON true`,
			description: "LATERAL for user activity analysis",
		},
	}

	for i, ex := range examples {
		fmt.Printf("%d. %s\n", i+1, ex.name)
		fmt.Printf("   Description: %s\n", ex.description)
		fmt.Printf("   SQL:\n")
		printSQL(ex.sql)
		fmt.Println()
		parseAndDisplayLateral(ex.sql)
		fmt.Println()
	}
}

func printSQL(sql string) {
	lines := splitLines(sql)
	for _, line := range lines {
		fmt.Printf("      %s\n", line)
	}
}

func splitLines(s string) []string {
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

func parseAndDisplayLateral(sql string) {
	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokensWithSpan, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		log.Printf("   Tokenize error: %v", err)
		return
	}

	// Convert tokens using the exported function
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

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		log.Printf("   Expected SelectStatement, got %T", astObj.Statements[0])
		return
	}

	fmt.Println("   Parsed Successfully!")
	fmt.Printf("   - SELECT Columns: %d\n", len(stmt.Columns))
	fmt.Printf("   - FROM Sources: %d\n", len(stmt.From))

	// Count LATERAL sources
	lateralCount := 0
	for _, from := range stmt.From {
		if from.Lateral {
			lateralCount++
		}
	}
	if lateralCount > 0 {
		fmt.Printf("   - LATERAL Subqueries: %d\n", lateralCount)
	}

	// Check for JOINs
	if len(stmt.Joins) > 0 {
		fmt.Printf("   - JOIN Clauses: %d\n", len(stmt.Joins))
	}

	if stmt.Where != nil {
		fmt.Println("   - WHERE: present")
	}
	if len(stmt.OrderBy) > 0 {
		fmt.Printf("   - ORDER BY: %d columns\n", len(stmt.OrderBy))
	}
}
