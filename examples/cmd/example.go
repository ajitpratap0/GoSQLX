package main

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Example demonstrates the Unicode support and proper resource management in the SQL tokenizer
func Example() ([]models.TokenWithSpan, error) {
	// Sample SQL query with Unicode identifiers and string literals
	// This demonstrates the tokenizer's ability to handle Japanese characters
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

	// Get a tokenizer from the pool for proper resource management
	t := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(t) // Always return to pool when done

	// Tokenize the query - this returns the actual tokens produced by the tokenizer
	tokens, err := t.Tokenize([]byte(query))
	if err != nil {
		return nil, fmt.Errorf("error tokenizing query: %v", err)
	}

	// Return the actual tokens, not hardcoded expectations
	return tokens, nil
}

func main() {
	fmt.Println("GoSQLX Tokenizer Example - Unicode SQL Tokenization")
	fmt.Println("===================================================")

	// Demonstrate the main example
	fmt.Println("\n1. Basic Unicode SQL Tokenization:")
	fmt.Println("-----------------------------------")
	tokens, err := Example()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully tokenized SQL query into %d tokens\n\n", len(tokens))

	// Show a sample of tokens (not all to keep output manageable)
	fmt.Println("Sample Token Details (first 15 tokens):")
	fmt.Println("Type                     | Value                    | Position")
	fmt.Println("-------------------------|--------------------------|----------------")

	count := 0
	for _, token := range tokens {
		if token.Token.Type == models.TokenTypeEOF {
			break
		}

		position := fmt.Sprintf("Line %d, Col %d", token.Start.Line, token.Start.Column)
		typeName := getTokenTypeName(token.Token.Type)
		fmt.Printf("%-24s | %-24q | %s\n", typeName, token.Token.Value, position)

		count++
		if count >= 15 {
			fmt.Printf("\n... and %d more tokens\n", len(tokens)-count-1) // -1 for EOF
			break
		}
	}

	// Demonstrate additional features
	fmt.Println("\n2. Error Handling Example:")
	fmt.Println("--------------------------")
	demonstrateErrorHandling()

	fmt.Println("\n3. Resource Management Example:")
	fmt.Println("--------------------------------")
	demonstrateResourceManagement()

	// Educational summary
	fmt.Println("\n4. Key Features Demonstrated:")
	fmt.Println("------------------------------")
	fmt.Println("✓ Unicode character support (Japanese SQL identifiers and strings)")
	fmt.Println("✓ Proper quoted identifier handling with double quotes")
	fmt.Println("✓ Single-quoted string literals")
	fmt.Println("✓ Complex SQL construct recognition (GROUP BY, ORDER BY, etc.)")
	fmt.Println("✓ Efficient resource management using object pools")
	fmt.Println("✓ Position tracking for error reporting and debugging")
	fmt.Println("✓ Comprehensive error handling for malformed SQL")

	fmt.Println("\n5. Performance Characteristics:")
	fmt.Println("--------------------------------")
	fmt.Println("• Up to 2.5M operations/second")
	fmt.Println("• 60-80% memory reduction with object pooling")
	fmt.Println("• Zero-copy tokenization")
	fmt.Println("• Race-free concurrent usage")
}

// demonstrateErrorHandling shows how the tokenizer handles malformed SQL
func demonstrateErrorHandling() {
	malformedSQL := `SELECT "unclosed_quote FROM table;`

	t := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(t)

	_, err := t.Tokenize([]byte(malformedSQL))
	if err != nil {
		fmt.Printf("✓ Properly caught error in malformed SQL: %v\n", err)
	} else {
		fmt.Println("✗ No error detected (unexpected)")
	}
}

// demonstrateResourceManagement shows the importance of proper cleanup
func demonstrateResourceManagement() {
	fmt.Println("Processing multiple queries efficiently using pooled tokenizers:")

	queries := []string{
		`SELECT * FROM users;`,
		`INSERT INTO logs (message) VALUES ('test');`,
		`UPDATE settings SET value = 42 WHERE key = 'count';`,
		`DELETE FROM sessions WHERE expired = true;`,
	}

	for i, query := range queries {
		// Get tokenizer from pool
		t := tokenizer.GetTokenizer()

		tokens, err := t.Tokenize([]byte(query))
		if err != nil {
			fmt.Printf("  Query %d error: %v\n", i+1, err)
			tokenizer.PutTokenizer(t) // Still return to pool on error
			continue
		}

		fmt.Printf("  ✓ Query %d: Successfully tokenized into %d tokens\n", i+1, len(tokens))

		// Return to pool when done
		tokenizer.PutTokenizer(t)
	}

	fmt.Println("✓ All tokenizers returned to pool for reuse")
}

// getTokenTypeName returns a human-readable name for the token type
func getTokenTypeName(tokenType models.TokenType) string {
	switch tokenType {
	case models.TokenTypeEOF:
		return "EOF"
	case models.TokenTypeIdentifier:
		return "IDENTIFIER"
	case models.TokenTypeNumber:
		return "NUMBER"
	case models.TokenTypeString:
		return "STRING"
	case models.TokenTypeSingleQuotedString:
		return "SINGLE_QUOTED_STRING"
	case models.TokenTypeDoubleQuotedString:
		return "DOUBLE_QUOTED_STRING"
	case models.TokenTypeSelect:
		return "SELECT"
	case models.TokenTypeFrom:
		return "FROM"
	case models.TokenTypeWhere:
		return "WHERE"
	case models.TokenTypeJoin:
		return "JOIN"
	case models.TokenTypeOn:
		return "ON"
	case models.TokenTypeAnd:
		return "AND"
	case models.TokenTypeOr:
		return "OR"
	case models.TokenTypeAs:
		return "AS"
	case models.TokenTypeGroupBy:
		return "GROUP BY"
	case models.TokenTypeOrderBy:
		return "ORDER BY"
	case models.TokenTypeHaving:
		return "HAVING"
	case models.TokenTypeCount:
		return "COUNT"
	case models.TokenTypeDesc:
		return "DESC"
	case models.TokenTypeComma:
		return "COMMA"
	case models.TokenTypeSemicolon:
		return "SEMICOLON"
	case models.TokenTypeLParen:
		return "LPAREN"
	case models.TokenTypeRParen:
		return "RPAREN"
	case models.TokenTypePeriod:
		return "PERIOD"
	case models.TokenTypeEq:
		return "EQ"
	case models.TokenTypeGt:
		return "GT"
	case models.TokenTypeMul:
		return "MUL"
	default:
		return fmt.Sprintf("TOKEN_%d", tokenType)
	}
}
