// Package main demonstrates PostgreSQL DISTINCT ON clause parsing
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func main() {
	fmt.Println("PostgreSQL DISTINCT ON Clause Example")
	fmt.Println("=====================================")

	// Example 1: Basic DISTINCT ON with single column
	example1 := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "DISTINCT", Literal: "DISTINCT"},
		{Type: "ON", Literal: "ON"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "dept_id"},
		{Type: ")", Literal: ")"},
		{Type: "IDENT", Literal: "dept_id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "salary"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "employees"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "dept_id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "salary"},
		{Type: "DESC", Literal: "DESC"},
	}

	fmt.Println("Example 1: Basic DISTINCT ON")
	fmt.Println("SQL: SELECT DISTINCT ON (dept_id) dept_id, name, salary FROM employees ORDER BY dept_id, salary DESC")
	parseAndDisplay(example1)

	// Example 2: DISTINCT ON with multiple columns
	example2 := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "DISTINCT", Literal: "DISTINCT"},
		{Type: "ON", Literal: "ON"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "user_id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "category"},
		{Type: ")", Literal: ")"},
		{Type: "*", Literal: "*"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "purchases"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "user_id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "category"},
	}

	fmt.Println("\nExample 2: DISTINCT ON with Multiple Columns")
	fmt.Println("SQL: SELECT DISTINCT ON (user_id, category) * FROM purchases ORDER BY user_id, category")
	parseAndDisplay(example2)

	// Example 3: Regular DISTINCT (should still work)
	example3 := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "DISTINCT", Literal: "DISTINCT"},
		{Type: "IDENT", Literal: "country"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "customers"},
	}

	fmt.Println("\nExample 3: Regular DISTINCT (backward compatibility)")
	fmt.Println("SQL: SELECT DISTINCT country FROM customers")
	parseAndDisplay(example3)
}

func parseAndDisplay(tokens []token.Token) {
	p := parser.NewParser()
	defer p.Release()

	astObj, err := p.Parse(tokens)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		log.Fatal("No statements parsed")
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		log.Fatalf("Expected SelectStatement, got %T", astObj.Statements[0])
	}

	fmt.Println("Parsed Successfully!")
	fmt.Printf("  - Distinct: %v\n", stmt.Distinct)

	if len(stmt.DistinctOnColumns) > 0 {
		fmt.Printf("  - DISTINCT ON Columns: %d\n", len(stmt.DistinctOnColumns))
		for i, col := range stmt.DistinctOnColumns {
			if ident, ok := col.(*ast.Identifier); ok {
				if ident.Table != "" {
					fmt.Printf("    %d. %s.%s\n", i+1, ident.Table, ident.Name)
				} else {
					fmt.Printf("    %d. %s\n", i+1, ident.Name)
				}
			} else if funcCall, ok := col.(*ast.FunctionCall); ok {
				fmt.Printf("    %d. %s(...)\n", i+1, funcCall.Name)
			}
		}
	} else {
		fmt.Println("  - DISTINCT ON Columns: 0 (regular DISTINCT)")
	}

	fmt.Printf("  - SELECT Columns: %d\n", len(stmt.Columns))
	fmt.Printf("  - FROM Tables: %d\n", len(stmt.From))
	fmt.Printf("  - ORDER BY: %d\n", len(stmt.OrderBy))
}
