package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// Parse SQL into an AST
	ast, err := gosqlx.Parse("SELECT * FROM users WHERE active = true")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("parsed %d statement(s)\n", len(ast.Statements))
}
