package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// Validate SQL syntax
	if err := gosqlx.Validate("SELECT * FROM users"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("SQL is valid!")
}
