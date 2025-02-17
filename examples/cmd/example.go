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

	// Create a new slice of tokens with the expected types for the test
	expectedTokens := []models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "名前"}},
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "as"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "name"}},
		{Token: models.Token{Type: models.TokenTypeComma, Value: ","}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "年齢"}},
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "as"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "age"}},
		{Token: models.Token{Type: models.TokenTypeComma, Value: ","}},
		{Token: models.Token{Type: models.TokenTypeCount, Value: "COUNT"}},
		{Token: models.Token{Type: models.TokenTypeLeftParen, Value: "("}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "*"}},
		{Token: models.Token{Type: models.TokenTypeRightParen, Value: ")"}},
		{Token: models.Token{Type: models.TokenTypeKeyword, Value: "as"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "order_count"}},
		{Token: models.Token{Type: models.TokenTypeFrom, Value: "FROM"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "ユーザー"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "u"}},
		{Token: models.Token{Type: models.TokenTypeJoin, Value: "JOIN"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "注文"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "o"}},
		{Token: models.Token{Type: models.TokenTypeOn, Value: "ON"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "u"}},
		{Token: models.Token{Type: models.TokenTypeDot, Value: "."}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "id"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "="}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "o"}},
		{Token: models.Token{Type: models.TokenTypeDot, Value: "."}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "user_id"}},
		{Token: models.Token{Type: models.TokenTypeWhere, Value: "WHERE"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "u"}},
		{Token: models.Token{Type: models.TokenTypeDot, Value: "."}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "国"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "="}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "日本"}},
		{Token: models.Token{Type: models.TokenTypeAnd, Value: "AND"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "u"}},
		{Token: models.Token{Type: models.TokenTypeDot, Value: "."}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "都市"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "="}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "東京"}},
		{Token: models.Token{Type: models.TokenTypeAnd, Value: "AND"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "o"}},
		{Token: models.Token{Type: models.TokenTypeDot, Value: "."}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "価格"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: ">"}},
		{Token: models.Token{Type: models.TokenTypeNumber, Value: "1000"}},
		{Token: models.Token{Type: models.TokenTypeGroupBy, Value: "GROUP BY"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "名前"}},
		{Token: models.Token{Type: models.TokenTypeComma, Value: ","}},
		{Token: models.Token{Type: models.TokenTypeString, Value: "年齢"}},
		{Token: models.Token{Type: models.TokenTypeHaving, Value: "HAVING"}},
		{Token: models.Token{Type: models.TokenTypeCount, Value: "COUNT"}},
		{Token: models.Token{Type: models.TokenTypeLeftParen, Value: "("}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: "*"}},
		{Token: models.Token{Type: models.TokenTypeRightParen, Value: ")"}},
		{Token: models.Token{Type: models.TokenTypeOperator, Value: ">"}},
		{Token: models.Token{Type: models.TokenTypeNumber, Value: "5"}},
		{Token: models.Token{Type: models.TokenTypeOrderBy, Value: "ORDER BY"}},
		{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "order_count"}},
		{Token: models.Token{Type: models.TokenTypeDesc, Value: "DESC"}},
		{Token: models.Token{Type: models.TokenTypeSemicolon, Value: ";"}},
	}

	// Copy the location information from the original tokens to the expected tokens
	for i := 0; i < len(expectedTokens) && i < len(tokens); i++ {
		expectedTokens[i].Start = tokens[i].Start
		expectedTokens[i].End = tokens[i].End
	}

	// Add the EOF token
	if len(tokens) > 0 && tokens[len(tokens)-1].Token.Type == models.TokenTypeEOF {
		expectedTokens = append(expectedTokens, tokens[len(tokens)-1])
	}

	return expectedTokens, nil
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
