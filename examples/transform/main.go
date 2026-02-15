// Package main demonstrates the GoSQLX Query Rewriting/Transform API.
//
// This example shows 5 key transformation patterns:
// 1. Multi-tenant row filtering (adding WHERE clauses)
// 2. Column projection control (adding/removing columns)
// 3. JOIN injection for data enrichment
// 4. Pagination (LIMIT/OFFSET/ORDER BY)
// 5. Table migration (renaming tables)
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/transform"
)

func main() {
	// Example 1: Multi-tenant row filtering
	// Add a tenant_id filter to any query for row-level security
	fmt.Println("=== Example 1: Multi-Tenant Row Filtering ===")
	tree, err := transform.ParseSQL("SELECT id, name, email FROM users WHERE active = true")
	if err != nil {
		log.Fatal(err)
	}
	stmt := tree.Statements[0]
	err = transform.Apply(stmt, transform.AddWhereFromSQL("tenant_id = 42"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(stmt))
	fmt.Println()

	// Example 2: Column projection — remove sensitive columns
	fmt.Println("=== Example 2: Column Projection ===")
	tree, err = transform.ParseSQL("SELECT id, name, ssn, email, password FROM users")
	if err != nil {
		log.Fatal(err)
	}
	stmt = tree.Statements[0]
	err = transform.Apply(stmt,
		transform.RemoveColumn("ssn"),
		transform.RemoveColumn("password"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(stmt))
	fmt.Println()

	// Example 3: JOIN injection for data enrichment
	fmt.Println("=== Example 3: JOIN Injection ===")
	tree, err = transform.ParseSQL("SELECT users.id, users.name FROM users")
	if err != nil {
		log.Fatal(err)
	}
	stmt = tree.Statements[0]
	err = transform.Apply(stmt,
		transform.AddJoinFromSQL("LEFT JOIN orders ON orders.user_id = users.id"),
		transform.AddColumn(&ast.FunctionCall{
			Name:      "COUNT",
			Arguments: []ast.Expression{&ast.Identifier{Name: "id", Table: "orders"}},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(stmt))
	fmt.Println()

	// Example 4: Pagination — add LIMIT, OFFSET, ORDER BY
	fmt.Println("=== Example 4: Pagination ===")
	tree, err = transform.ParseSQL("SELECT * FROM products WHERE category = 'electronics'")
	if err != nil {
		log.Fatal(err)
	}
	stmt = tree.Statements[0]
	err = transform.Apply(stmt,
		transform.AddOrderBy("price", true), // ORDER BY price DESC
		transform.SetLimit(20),
		transform.SetOffset(40),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(stmt))
	fmt.Println()

	// Example 5: Table migration — rename table references
	fmt.Println("=== Example 5: Table Migration ===")
	tree, err = transform.ParseSQL("SELECT users.id, users.name FROM users WHERE users.active = true")
	if err != nil {
		log.Fatal(err)
	}
	stmt = tree.Statements[0]
	err = transform.Apply(stmt, transform.ReplaceTable("users", "accounts"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(transform.FormatSQL(stmt))
}
