package main

import (
	"fmt"
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/tokenizer"
)

// Example demonstrates the Unicode support in the SQL tokenizer
func Example() ([]models.TokenWithSpan, error) {
	// Sample SQL query with Unicode identifiers and string literals
	query := `
		SELECT
			"名前" as name,
			"年齢" as age,
			COUNT(*) as order_count
		FROM "ユーザー" u
		JOIN "注文" o ON u.id = o.user_id
		WHERE
			u."国" = '日本'
			AND u."都市" = '東京'
			AND o."価格" > 1000
		GROUP BY "名前", "年齢"
		HAVING COUNT(*) > 5
		ORDER BY order_count DESC;
	`

	// Create a new tokenizer
	t, err := tokenizer.New()
	if err != nil {
		return nil, fmt.Errorf("error creating tokenizer: %v", err)
	}

	// Tokenize the query
	tokens, err := t.Tokenize([]byte(query))
	if err != nil {
		return nil, fmt.Errorf("error tokenizing query: %v", err)
	}

	return tokens, nil
}

func main() {
	// Run the example
	tokens, err := Example()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Print the tokens
	fmt.Println("Query tokens:")
	for i, t := range tokens {
		// Skip the EOF token
		if t.Token.Type == models.TokenTypeEOF {
			continue
		}
		fmt.Printf("%3d. Type: %-20v Value: %q\n", i+1, t.Token.Type, t.Token.Value)
	}
}
