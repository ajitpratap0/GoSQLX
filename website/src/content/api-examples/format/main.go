package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// Format messy SQL
	formatted, err := gosqlx.Format("select id,name from users where id>5", gosqlx.DefaultFormatOptions())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(formatted)
}
