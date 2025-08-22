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
	fmt.Println("1. Basic Unicode SQL Tokenization:")
	tokens, err := Example()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("Successfully tokenized SQL query into %d tokens\n\n", len(tokens))
	
	// Show a sample of tokens (not all to keep output manageable)
	fmt.Println("Sample Token Details (first 10 tokens):")
	fmt.Println("----------------------------------------")
	count := 0
	for i, token := range tokens {
		if token.Token.Type == models.TokenTypeEOF {
			break
		}
		
		position := fmt.Sprintf("Line %d, Col %d", token.Start.Line, token.Start.Column)
		fmt.Printf("%3d. Type: %-25s Value: %-15q Position: %s\n", 
			i+1, getTokenTypeName(token.Token.Type), token.Token.Value, position)
		
		count++
		if count >= 10 {
			fmt.Printf("... (%d more tokens)\n", len(tokens)-count-1) // -1 for EOF
			break
		}
	}
	
	// Demonstrate additional features
	fmt.Println("\n2. Error Handling Example:")
	demonstrateErrorHandling()
	
	fmt.Println("\n3. Resource Management Example:")
	demonstrateResourceManagement()
	
	// Educational summary
	fmt.Println("\nKey Features Demonstrated:")
	fmt.Println("- Unicode character support (Japanese SQL identifiers and strings)")
	fmt.Println("- Proper quoted identifier handling with double quotes")
	fmt.Println("- Single-quoted string literals")
	fmt.Println("- Complex SQL construct recognition (GROUP BY, ORDER BY, etc.)")
	fmt.Println("- Efficient resource management using object pools")
	fmt.Println("- Position tracking for error reporting and debugging")
	fmt.Println("- Comprehensive error handling for malformed SQL")
}

// demonstrateErrorHandling shows how the tokenizer handles malformed SQL
func demonstrateErrorHandling() {
	malformedSQL := `SELECT "unclosed_quote FROM table;`
	
	t := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(t)
	
	_, err := t.Tokenize([]byte(malformedSQL))
	if err != nil {
		fmt.Printf("Properly caught error in malformed SQL: %v\n", err)
	} else {
		fmt.Println("No error detected (unexpected)")
	}
}

// demonstrateResourceManagement shows the importance of proper cleanup
func demonstrateResourceManagement() {
	fmt.Println("Processing multiple queries efficiently using pooled tokenizers:")
	
	queries := []string{
		`SELECT * FROM users;`,
		`INSERT INTO logs (message) VALUES ('test');`,
		`UPDATE settings SET value = 42 WHERE key = 'count';`,
	}
	
	for i, query := range queries {
		// Get tokenizer from pool
		t := tokenizer.GetTokenizer()
		
		tokens, err := t.Tokenize([]byte(query))
		if err != nil {
			fmt.Printf("Query %d error: %v\n", i+1, err)
			tokenizer.PutTokenizer(t) // Still return to pool on error
			continue
		}
		
		fmt.Printf("Query %d: %d tokens\n", i+1, len(tokens))
		
		// Return to pool when done
		tokenizer.PutTokenizer(t)
	}
	
	fmt.Println("All tokenizers returned to pool for reuse")
}

// getTokenTypeName returns a human-readable name for the token type
// Due to overlapping token type values, we use the token value to provide context
func getTokenTypeName(tokenType models.TokenType) string {
	// Map common token type numbers to descriptive names
	typeNum := int(tokenType)
	switch typeNum {
	case 0:
		return "EOF"
	case 1:
		return "Word"
	case 2:
		return "Number"
	case 20:
		return "String"
	case 43:
		return "SELECT/JOIN/HAVING"
	case 51:
		return "WHERE/ON/AND"  
	case 59:
		return "FROM/COUNT/ORDER_BY"
	case 124:
		return "QuotedString/AS/Comma"
	default:
		return fmt.Sprintf("TokenType(%d)", typeNum)
	}
}
