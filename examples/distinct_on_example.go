// Package main demonstrates PostgreSQL DISTINCT ON clause parsing
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
)

func main() {
	fmt.Println("PostgreSQL DISTINCT ON Clause Example")
	fmt.Println("=====================================")

	// Example 1: Basic DISTINCT ON with single column
	example1 := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "name"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "salary"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "employees"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "dept_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "salary"},
		{Type: models.TokenTypeDesc, Literal: "DESC"},
	}

	fmt.Println("Example 1: Basic DISTINCT ON")
	fmt.Println("SQL: SELECT DISTINCT ON (dept_id) dept_id, name, salary FROM employees ORDER BY dept_id, salary DESC")
	parseAndDisplay(example1)

	// Example 2: DISTINCT ON with multiple columns
	example2 := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeOn, Literal: "ON"},
		{Type: models.TokenTypeLParen, Literal: "("},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
		{Type: models.TokenTypeRParen, Literal: ")"},
		{Type: models.TokenTypeAsterisk, Literal: "*"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "purchases"},
		{Type: models.TokenTypeOrder, Literal: "ORDER"},
		{Type: models.TokenTypeBy, Literal: "BY"},
		{Type: models.TokenTypeIdentifier, Literal: "user_id"},
		{Type: models.TokenTypeComma, Literal: ","},
		{Type: models.TokenTypeIdentifier, Literal: "category"},
	}

	fmt.Println("\nExample 2: DISTINCT ON with Multiple Columns")
	fmt.Println("SQL: SELECT DISTINCT ON (user_id, category) * FROM purchases ORDER BY user_id, category")
	parseAndDisplay(example2)

	// Example 3: Regular DISTINCT (should still work)
	example3 := []token.Token{
		{Type: models.TokenTypeSelect, Literal: "SELECT"},
		{Type: models.TokenTypeDistinct, Literal: "DISTINCT"},
		{Type: models.TokenTypeIdentifier, Literal: "country"},
		{Type: models.TokenTypeFrom, Literal: "FROM"},
		{Type: models.TokenTypeIdentifier, Literal: "customers"},
	}

	fmt.Println("\nExample 3: Regular DISTINCT (backward compatibility)")
	fmt.Println("SQL: SELECT DISTINCT country FROM customers")
	parseAndDisplay(example3)
}

func parseAndDisplay(tokens []token.Token) {
	p := parser.NewParser()

	astObj, err := p.Parse(tokens)
	if err != nil {
		p.Release()
		log.Fatalf("Parse error: %v", err)
	}

	displayAST(p, astObj)
}

func displayAST(p *parser.Parser, astObj *ast.AST) {
	defer p.Release()
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		fmt.Println("No statements parsed")
		return
	}

	stmt, ok := astObj.Statements[0].(*ast.SelectStatement)
	if !ok {
		fmt.Printf("Expected SelectStatement, got %T\n", astObj.Statements[0])
		return
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
