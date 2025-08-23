package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	var (
		input   = flag.String("input", "", "Input SQL file")
		output  = flag.String("output", "", "Output file (default: stdout)")
		indent  = flag.Int("indent", 2, "Indentation spaces")
		upper   = flag.Bool("upper", true, "Uppercase keywords")
		compact = flag.Bool("compact", false, "Compact format")
	)
	flag.Parse()

	if *input == "" && flag.NArg() == 0 {
		fmt.Println("SQL Formatter - Format SQL queries using GoSQLX")
		fmt.Println("\nUsage:")
		fmt.Println("  sql-formatter -input query.sql")
		fmt.Println("  sql-formatter -input query.sql -output formatted.sql")
		fmt.Println("  sql-formatter \"SELECT * FROM users\"")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var sql string
	if *input != "" {
		content, err := os.ReadFile(*input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		sql = string(content)
	} else {
		sql = strings.Join(flag.Args(), " ")
	}

	formatted, err := formatSQL(sql, FormatOptions{
		IndentSize: *indent,
		Uppercase:  *upper,
		Compact:    *compact,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting SQL: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		err = os.WriteFile(*output, []byte(formatted), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Formatted SQL written to %s\n", *output)
	} else {
		fmt.Println(formatted)
	}
}

type FormatOptions struct {
	IndentSize int
	Uppercase  bool
	Compact    bool
}

func formatSQL(sql string, opts FormatOptions) (string, error) {
	// Tokenize
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}

	var result strings.Builder
	indentLevel := 0
	newLine := true
	lastWasKeyword := false

	// Keywords that increase indent
	indentKeywords := map[string]bool{
		"SELECT": true, "FROM": true, "WHERE": true,
		"GROUP": true, "HAVING": true, "ORDER": true,
		"JOIN": true, "LEFT": true, "RIGHT": true,
		"INNER": true, "OUTER": true, "ON": true,
	}

	// Keywords that should be on new line
	newLineKeywords := map[string]bool{
		"SELECT": true, "FROM": true, "WHERE": true,
		"GROUP": true, "HAVING": true, "ORDER": true,
		"JOIN": true, "LEFT": true, "RIGHT": true,
		"INNER": true, "OUTER": true, "LIMIT": true,
		"UNION": true, "INTERSECT": true, "EXCEPT": true,
	}

	for i, token := range tokens {
		value := string(token.Token.Value)
		upperValue := strings.ToUpper(value)

		// Check if it's a keyword
		isKeyword := isKeyword(upperValue)

		// Handle formatting
		if !opts.Compact {
			// Check if we need a new line
			if isKeyword && newLineKeywords[upperValue] && i > 0 {
				result.WriteString("\n")
				newLine = true
			}

			// Add indentation
			if newLine && !opts.Compact {
				result.WriteString(strings.Repeat(" ", indentLevel*opts.IndentSize))
				newLine = false
			}
		}

		// Write the token
		if isKeyword && opts.Uppercase {
			result.WriteString(upperValue)
		} else {
			result.WriteString(value)
		}

		// Add space after token (except for last token or special characters)
		if i < len(tokens)-1 {
			nextValue := string(tokens[i+1].Token.Value)
			if !isSpecialChar(value) && !isSpecialChar(nextValue) {
				result.WriteString(" ")
			}
		}

		lastWasKeyword = isKeyword
	}

	return result.String(), nil
}

func isKeyword(word string) bool {
	keywords := []string{
		"SELECT", "FROM", "WHERE", "AND", "OR", "NOT",
		"INSERT", "INTO", "VALUES", "UPDATE", "SET",
		"DELETE", "CREATE", "TABLE", "INDEX", "VIEW",
		"ALTER", "DROP", "JOIN", "LEFT", "RIGHT",
		"INNER", "OUTER", "ON", "AS", "GROUP", "BY",
		"HAVING", "ORDER", "LIMIT", "OFFSET", "UNION",
		"ALL", "DISTINCT", "CASE", "WHEN", "THEN",
		"ELSE", "END", "NULL", "IS", "IN", "EXISTS",
		"BETWEEN", "LIKE", "ASC", "DESC",
	}

	for _, k := range keywords {
		if k == word {
			return true
		}
	}
	return false
}

func isSpecialChar(s string) bool {
	return s == "(" || s == ")" || s == "," || s == ";" || s == "."
}