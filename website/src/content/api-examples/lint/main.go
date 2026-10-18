package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// Lint SQL for best practices
	result, err := gosqlx.Lint("SELECT * FROM orders")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range result.Violations {
		fmt.Printf("[%s] %s: %s\n", v.Rule, v.RuleName, v.Message)
	}
}
