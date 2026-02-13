package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	var (
		file    = flag.String("file", "", "SQL file to validate")
		query   = flag.String("query", "", "SQL query to validate")
		dialect = flag.String("dialect", "postgres", "SQL dialect (postgres, mysql, mssql, oracle, sqlite)")
		verbose = flag.Bool("verbose", false, "Show detailed output")
	)
	flag.Parse()

	if *file == "" && *query == "" {
		fmt.Println("SQL Validator - Validate SQL syntax using GoSQLX")
		fmt.Println("\nUsage:")
		fmt.Println("  sql-validator -query \"SELECT * FROM users\"")
		fmt.Println("  sql-validator -file queries.sql")
		fmt.Println("  cat queries.sql | sql-validator")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var input string
	if *file != "" {
		content, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		input = string(content)
	} else if *query != "" {
		input = *query
	} else {
		// Read from stdin
		reader := bufio.NewReader(os.Stdin)
		content, err := io.ReadAll(reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		input = string(content)
	}

	// Split by semicolon for multiple queries
	queries := splitQueries(input)

	fmt.Printf("Validating %d SQL %s using %s dialect...\n",
		len(queries),
		pluralize("query", len(queries)),
		*dialect)

	errors := 0
	warnings := 0

	for i, query := range queries {
		if strings.TrimSpace(query) == "" {
			continue
		}

		if *verbose {
			fmt.Printf("\n--- Query %d ---\n", i+1)
			fmt.Println(truncate(query, 100))
		}

		result := validateSQL(query, *dialect, *verbose)

		if result.Error != nil {
			errors++
			fmt.Printf("❌ Query %d: INVALID\n", i+1)
			fmt.Printf("   Error: %v\n", result.Error)
			if result.Line > 0 {
				fmt.Printf("   Location: Line %d, Column %d\n", result.Line, result.Column)
			}
		} else {
			fmt.Printf("✅ Query %d: VALID\n", i+1)
			if *verbose {
				fmt.Printf("   Type: %s\n", result.StatementType)
				fmt.Printf("   Tokens: %d\n", result.TokenCount)
				if len(result.Tables) > 0 {
					fmt.Printf("   Tables: %s\n", strings.Join(result.Tables, ", "))
				}
			}
		}

		if len(result.Warnings) > 0 {
			warnings += len(result.Warnings)
			for _, warning := range result.Warnings {
				fmt.Printf("   ⚠️  Warning: %s\n", warning)
			}
		}
	}

	// Summary
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total queries: %d\n", len(queries))
	fmt.Printf("Valid: %d\n", len(queries)-errors)
	fmt.Printf("Invalid: %d\n", errors)
	if warnings > 0 {
		fmt.Printf("Warnings: %d\n", warnings)
	}

	if errors > 0 {
		os.Exit(1)
	}
}

type ValidationResult struct {
	Valid         bool
	Error         error
	Line          int
	Column        int
	StatementType string
	TokenCount    int
	Tables        []string
	Warnings      []string
}

func validateSQL(sql string, dialect string, verbose bool) ValidationResult {
	result := ValidationResult{Valid: true}

	// Get tokenizer
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		result.Valid = false
		result.Error = err
		// Try to extract position from error
		if tokErr, ok := err.(*errors.Error); ok {
			result.Line = tokErr.Location.Line
			result.Column = tokErr.Location.Column
		}
		return result
	}

	result.TokenCount = len(tokens)

	// Parse
	p := parser.NewParser()
	defer p.Release()

	// Convert tokens for parser
	parserTokens := make([]token.Token, len(tokens))
	for i, t := range tokens {
		parserTokens[i] = token.Token{
			//lint:ignore SA1019 intentional use during #215 migration
			Type:    token.Type(t.Token.Value), //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
			Literal: string(t.Token.Value),
		}
	}

	ast, err := p.Parse(parserTokens)
	if err != nil {
		result.Valid = false
		result.Error = err
		return result
	}

	// Extract metadata
	if ast != nil {
		result.StatementType = detectStatementType(parserTokens)
		result.Tables = extractTableNames(parserTokens)
		result.Warnings = checkForWarnings(parserTokens, dialect)
	}

	return result
}

func detectStatementType(tokens []token.Token) string {
	if len(tokens) == 0 {
		return "UNKNOWN"
	}

	switch strings.ToUpper(tokens[0].Literal) {
	case "SELECT":
		return "SELECT"
	case "INSERT":
		return "INSERT"
	case "UPDATE":
		return "UPDATE"
	case "DELETE":
		return "DELETE"
	case "CREATE":
		if len(tokens) > 1 {
			return "CREATE " + strings.ToUpper(tokens[1].Literal)
		}
		return "CREATE"
	case "ALTER":
		return "ALTER"
	case "DROP":
		return "DROP"
	default:
		return "OTHER"
	}
}

func extractTableNames(tokens []token.Token) []string {
	tables := []string{}
	fromNext := false
	joinNext := false

	for _, token := range tokens {
		upper := strings.ToUpper(token.Literal)
		if upper == "FROM" || upper == "INTO" || upper == "UPDATE" {
			fromNext = true
		} else if upper == "JOIN" {
			joinNext = true
		} else if fromNext || joinNext {
			if token.Type != "" { // Identifier (non-empty type)
				tables = append(tables, token.Literal)
				fromNext = false
				joinNext = false
			}
		}
	}

	return tables
}

func checkForWarnings(tokens []token.Token, dialect string) []string {
	warnings := []string{}

	// Check for dialect-specific issues
	for _, token := range tokens {
		upper := strings.ToUpper(token.Literal)

		// MySQL-specific
		if dialect != "mysql" && strings.Contains(token.Literal, "`") {
			warnings = append(warnings, "Backtick identifiers are MySQL-specific")
		}

		// PostgreSQL-specific
		if dialect != "postgres" && (upper == "RETURNING" || upper == "ARRAY") {
			warnings = append(warnings, fmt.Sprintf("%s is PostgreSQL-specific", upper))
		}

		// SQL Server-specific
		if dialect != "mssql" && strings.HasPrefix(token.Literal, "[") {
			warnings = append(warnings, "Bracket identifiers are SQL Server-specific")
		}
	}

	return warnings
}

func splitQueries(input string) []string {
	// Simple split by semicolon (doesn't handle semicolons in strings)
	queries := strings.Split(input, ";")
	result := []string{}

	for _, q := range queries {
		trimmed := strings.TrimSpace(q)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}
