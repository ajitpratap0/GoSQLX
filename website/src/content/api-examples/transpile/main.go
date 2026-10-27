package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func main() {
	// Rewrite MySQL for PostgreSQL: quotes, escapes and operators
	pg, err := gosqlx.Transpile(
		"SELECT `Order Id`, a ^ b FROM t WHERE note = 'it\\'s'",
		keywords.DialectMySQL,
		keywords.DialectPostgreSQL,
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pg)
	// SELECT "Order Id", a # b FROM t WHERE note = 'it''s'
}
