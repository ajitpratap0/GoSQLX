package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQL is a helper function to tokenize and parse SQL
func parseSQL(sql string) (*ast.AST, error) {
	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize SQL
	tokensWithSpan, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %v", err)
	}

	// Convert to parser tokens
	tokens := make([]token.Token, 0, len(tokensWithSpan))
	for _, t := range tokensWithSpan {
		var tokenType token.Type

		switch t.Token.Type {
		case 14: // TokenTypeIdentifier
			tokenType = "IDENT"
		case 200: // TokenTypeKeyword
			tokenType = token.Type(t.Token.Value)
		case 30: // TokenTypeString
			tokenType = "STRING"
		case 11: // TokenTypeNumber
			tokenType = "INT"
		case 50: // TokenTypeOperator
			tokenType = token.Type(t.Token.Value)
		case 67: // TokenTypeLParen
			tokenType = "("
		case 68: // TokenTypeRParen
			tokenType = ")"
		case 51: // TokenTypeComma
			tokenType = ","
		case 69: // TokenTypePeriod
			tokenType = "."
		case 52: // TokenTypeEq
			tokenType = "="
		default:
			if t.Token.Value != "" {
				tokenType = token.Type(t.Token.Value)
			}
		}

		if tokenType != "" && t.Token.Value != "" {
			tokens = append(tokens, token.Token{
				Type:    tokenType,
				Literal: t.Token.Value,
			})
		}
	}

	// Parse tokens
	p := &parser.Parser{}
	return p.Parse(tokens)
}

func main() {
	fmt.Println("GoSQLX Phase 2 Features Demo")
	fmt.Println("============================")

	// Example 1: Simple CTE
	fmt.Println("\n1. Simple Common Table Expression (CTE):")
	cteSQL := `WITH sales_summary AS (SELECT region, total FROM sales) SELECT region FROM sales_summary`
	fmt.Printf("SQL: %s\n", cteSQL)

	ast1, err := parseSQL(cteSQL)
	if err != nil {
		log.Printf("Error parsing CTE: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed CTE with %d statement(s)\n", len(ast1.Statements))
		defer ast.ReleaseAST(ast1)
	}

	// Example 2: Recursive CTE
	fmt.Println("\n2. Recursive Common Table Expression:")
	recursiveSQL := `WITH RECURSIVE employee_hierarchy AS (SELECT emp_id FROM employees) SELECT emp_id FROM employee_hierarchy`
	fmt.Printf("SQL: %s\n", recursiveSQL)

	ast2, err := parseSQL(recursiveSQL)
	if err != nil {
		log.Printf("Error parsing recursive CTE: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed recursive CTE with %d statement(s)\n", len(ast2.Statements))
		defer ast.ReleaseAST(ast2)
	}

	// Example 3: UNION set operation
	fmt.Println("\n3. UNION Set Operation:")
	unionSQL := `SELECT name FROM customers UNION SELECT name FROM suppliers`
	fmt.Printf("SQL: %s\n", unionSQL)

	ast3, err := parseSQL(unionSQL)
	if err != nil {
		log.Printf("Error parsing UNION: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed UNION with %d statement(s)\n", len(ast3.Statements))
		defer ast.ReleaseAST(ast3)
	}

	// Example 4: UNION ALL
	fmt.Println("\n4. UNION ALL Set Operation:")
	unionAllSQL := `SELECT id FROM orders UNION ALL SELECT id FROM invoices`
	fmt.Printf("SQL: %s\n", unionAllSQL)

	ast4, err := parseSQL(unionAllSQL)
	if err != nil {
		log.Printf("Error parsing UNION ALL: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed UNION ALL with %d statement(s)\n", len(ast4.Statements))
		defer ast.ReleaseAST(ast4)
	}

	// Example 5: EXCEPT operation
	fmt.Println("\n5. EXCEPT Set Operation:")
	exceptSQL := `SELECT product FROM inventory EXCEPT SELECT product FROM discontinued`
	fmt.Printf("SQL: %s\n", exceptSQL)

	ast5, err := parseSQL(exceptSQL)
	if err != nil {
		log.Printf("Error parsing EXCEPT: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed EXCEPT with %d statement(s)\n", len(ast5.Statements))
		defer ast.ReleaseAST(ast5)
	}

	// Example 6: INTERSECT operation
	fmt.Println("\n6. INTERSECT Set Operation:")
	intersectSQL := `SELECT customer_id FROM orders INTERSECT SELECT customer_id FROM payments`
	fmt.Printf("SQL: %s\n", intersectSQL)

	ast6, err := parseSQL(intersectSQL)
	if err != nil {
		log.Printf("Error parsing INTERSECT: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed INTERSECT with %d statement(s)\n", len(ast6.Statements))
		defer ast.ReleaseAST(ast6)
	}

	// Example 7: Multiple set operations (left-associative)
	fmt.Println("\n7. Multiple Set Operations:")
	multipleSQL := `SELECT name FROM users UNION SELECT name FROM customers INTERSECT SELECT name FROM employees`
	fmt.Printf("SQL: %s\n", multipleSQL)

	ast7, err := parseSQL(multipleSQL)
	if err != nil {
		log.Printf("Error parsing multiple set operations: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed multiple set operations with %d statement(s)\n", len(ast7.Statements))
		defer ast.ReleaseAST(ast7)
	}

	// Example 8: CTE with set operations
	fmt.Println("\n8. CTE with Set Operations:")
	cteSetSQL := `WITH regional AS (SELECT region FROM sales) SELECT region FROM regional UNION SELECT region FROM returns`
	fmt.Printf("SQL: %s\n", cteSetSQL)

	ast8, err := parseSQL(cteSetSQL)
	if err != nil {
		log.Printf("Error parsing CTE with set operations: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed CTE with set operations with %d statement(s)\n", len(ast8.Statements))
		defer ast.ReleaseAST(ast8)
	}

	// Example 9: Multiple CTEs
	fmt.Println("\n9. Multiple CTEs:")
	multipleCTESQL := `WITH first_cte AS (SELECT region FROM sales), second_cte AS (SELECT region FROM first_cte) SELECT region FROM second_cte`
	fmt.Printf("SQL: %s\n", multipleCTESQL)

	ast9, err := parseSQL(multipleCTESQL)
	if err != nil {
		log.Printf("Error parsing multiple CTEs: %v", err)
	} else {
		fmt.Printf("✅ Successfully parsed multiple CTEs with %d statement(s)\n", len(ast9.Statements))
		defer ast.ReleaseAST(ast9)
	}

	fmt.Println("\n🎉 GoSQLX Phase 2 Implementation Complete!")
	fmt.Println("Features implemented:")
	fmt.Println("  • Common Table Expressions (CTE)")
	fmt.Println("  • Recursive CTEs")
	fmt.Println("  • UNION / UNION ALL")
	fmt.Println("  • EXCEPT")
	fmt.Println("  • INTERSECT")
	fmt.Println("  • Multiple CTEs")
	fmt.Println("  • CTE with Set Operations")
	fmt.Println("  • Left-associative set operation parsing")
}
