package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// Format messy SQL; comments are kept
	opts := gosqlx.DefaultFormatOptions()
	formatted, err := gosqlx.Format("-- active users\nselect id,name from users where id>5", opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(formatted)
	// -- active users
	// SELECT id, name
	// FROM users
	// WHERE id > 5
}
