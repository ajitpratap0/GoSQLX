package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sql-validator <file-or-directory>")
		fmt.Println("\nExamples:")
		fmt.Println("  sql-validator query.sql")
		fmt.Println("  sql-validator ./migrations")
		fmt.Println("  sql-validator .")
		os.Exit(1)
	}

	target := os.Args[1]

	// Check if target exists
	info, err := os.Stat(target) // #nosec G703
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var results []ValidationResult

	// Process file or directory
	if info.IsDir() {
		fmt.Printf("Scanning directory: %s\n", target)
		results, err = ValidateDirectory(target)
		if err != nil {
			fmt.Printf("Error scanning directory: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Validating file: %s\n", target)
		result := ValidateFile(target)
		results = []ValidationResult{result}
	}

	// Print results
	PrintResults(results)

	// Exit with error code if any files are invalid
	for _, result := range results {
		if !result.Valid {
			os.Exit(1)
		}
	}

	fmt.Println("\nAll SQL files are valid!")
	os.Exit(0)
}
