package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "format":
		formatCommand()
	case "init":
		initCommand()
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("SQL Formatter - Format SQL files with custom rules")
	fmt.Println("\nUsage:")
	fmt.Println("  sql-formatter format [options] <file>")
	fmt.Println("  sql-formatter init")
	fmt.Println("  sql-formatter help")
	fmt.Println("\nFormat Options:")
	fmt.Println("  -i           Format file in-place")
	fmt.Println("  -c <config>  Use custom config file (default: .sqlformat.json)")
	fmt.Println("\nExamples:")
	fmt.Println("  sql-formatter format query.sql")
	fmt.Println("  sql-formatter format -i query.sql")
	fmt.Println("  sql-formatter format -c myconfig.json query.sql")
	fmt.Println("  sql-formatter init  # Create default config file")
}

func initCommand() {
	configPath := ".sqlformat.json"

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("Config file already exists: %s\n", configPath)
		fmt.Println("Delete it first or use a different name.")
		os.Exit(1)
	}

	// Save default config
	config := DefaultConfig()
	if err := SaveConfig(config, configPath); err != nil {
		fmt.Printf("Error creating config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Created default config file: %s\n", configPath)
	fmt.Println("\nEdit this file to customize formatting rules:")
	fmt.Printf("  {\n")
	fmt.Printf("    \"keyword_case\": \"upper\",\n")
	fmt.Printf("    \"indent_spaces\": 4,\n")
	fmt.Printf("    \"max_line_length\": 80,\n")
	fmt.Printf("    \"comma_style\": \"leading\",\n")
	fmt.Printf("    \"space_around_operators\": true,\n")
	fmt.Printf("    \"align_joins\": true,\n")
	fmt.Printf("    \"uppercase_functions\": true\n")
	fmt.Printf("  }\n")
}

func formatCommand() {
	var (
		inPlace    bool
		configPath string
		filePath   string
	)

	// Parse arguments
	configPath = ".sqlformat.json"
	args := os.Args[2:]

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-i":
			inPlace = true
		case "-c":
			if i+1 >= len(args) {
				fmt.Println("Error: -c requires a config file path")
				os.Exit(1)
			}
			configPath = args[i+1]
			i++
		default:
			filePath = arg
		}
	}

	if filePath == "" {
		fmt.Println("Error: No file specified")
		printUsage()
		os.Exit(1)
	}

	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Read SQL file
	content, err := os.ReadFile(filePath) // #nosec G304
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Format SQL
	formatter := NewFormatter(config)
	formatted, err := formatter.Format(string(content))
	if err != nil {
		fmt.Printf("Error formatting SQL: %v\n", err)
		os.Exit(1)
	}

	// Output or write to file
	if inPlace {
		if err := os.WriteFile(filePath, []byte(formatted), 0600); err != nil {
			fmt.Printf("Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Formatted: %s\n", filePath)
	} else {
		fmt.Print(formatted)
	}
}
