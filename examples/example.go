package main

import (
    "fmt"
    "GoSQLX/pkg"
)

func main() {
    // Sample SQL query
    query := `SELECT id, name FROM users WHERE age > 18;`

    // Create a lexer with default configuration
    lexer := pkg.NewLexer(query, pkg.LexerConfig{})

    // Tokenize the query
    tokens, err := lexer.Tokenize()
    if err != nil {
        fmt.Printf("Error tokenizing query: %v\n", err)
        return
    }

    // Print the tokens
    fmt.Println("Tokens:")
    for _, token := range tokens {
        fmt.Printf("Type: %v, Value: %q\n", token.Type, token.Value)
    }
}
