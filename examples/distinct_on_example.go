// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main demonstrates PostgreSQL DISTINCT ON clause parsing
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
	fmt.Println("PostgreSQL DISTINCT ON Clause Example")
	fmt.Println("=====================================")

	// Example 1: Basic DISTINCT ON with single column
	sql1 := "SELECT DISTINCT ON (dept_id) dept_id, name, salary FROM employees ORDER BY dept_id, salary DESC"
	fmt.Println("Example 1: Basic DISTINCT ON")
	fmt.Printf("SQL: %s\n", sql1)
	parseAndDisplay(sql1)

	// Example 2: DISTINCT ON with multiple columns
	sql2 := "SELECT DISTINCT ON (user_id, category) * FROM purchases ORDER BY user_id, category"
	fmt.Println("\nExample 2: DISTINCT ON with Multiple Columns")
	fmt.Printf("SQL: %s\n", sql2)
	parseAndDisplay(sql2)

	// Example 3: Regular DISTINCT (should still work)
	sql3 := "SELECT DISTINCT country FROM customers"
	fmt.Println("\nExample 3: Regular DISTINCT (backward compatibility)")
	fmt.Printf("SQL: %s\n", sql3)
	parseAndDisplay(sql3)
}

func parseAndDisplay(sql string) {
	astObj, err := gosqlx.Parse(sql)
	if err != nil {
		log.Fatalf("Parse error: %v", err)
	}

	displayAST(astObj)
}

func displayAST(astObj *ast.AST) {
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
