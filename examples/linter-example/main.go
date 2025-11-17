package main

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

func main() {
	// Example SQL with various linting issues
	sql := `SELECT id, name, email
FROM users
	WHERE active = true
  AND created_at > '2024-01-01'
ORDER BY name

`

	fmt.Println("SQL Linting Example")
	fmt.Println("===================")
	fmt.Println("Input SQL:")
	fmt.Println(sql)
	fmt.Println("\n" + string(make([]byte, 80, 80)) + "\n")

	// Create linter with rules
	l := linter.New(
		whitespace.NewTrailingWhitespaceRule(),
		whitespace.NewMixedIndentationRule(),
		whitespace.NewLongLinesRule(80),
	)

	// Lint the SQL
	result := l.LintString(sql, "example.sql")

	// Display results
	fmt.Printf("Found %d violation(s):\n\n", len(result.Violations))

	for i, violation := range result.Violations {
		fmt.Printf("%d. %s\n", i+1, linter.FormatViolation(violation))
	}

	// Test auto-fix
	if len(result.Violations) > 0 {
		fmt.Println("\nAttempting auto-fix...")

		for _, rule := range l.Rules() {
			if rule.CanAutoFix() {
				fixed, err := rule.Fix(sql, result.Violations)
				if err == nil && fixed != sql {
					fmt.Printf("\nFixed by %s (%s):\n", rule.Name(), rule.ID())
					fmt.Println(fixed)
					sql = fixed
				}
			}
		}
	}
}
