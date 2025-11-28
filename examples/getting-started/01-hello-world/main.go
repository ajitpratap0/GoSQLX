// Hello World - The simplest GoSQLX example
//
// This example shows the absolute minimum code needed to parse SQL with GoSQLX.
// Perfect for beginners!
//
// Run: go run main.go

package main

import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

func main() {
	ast, _ := gosqlx.Parse("SELECT * FROM users")
	println("Parsed successfully!")

	// Let's also print the number of statements
	println("Statements parsed:", len(ast.Statements))
}
