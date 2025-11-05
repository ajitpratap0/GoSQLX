package main

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func main() {
	fmt.Println("==========================================================")
	fmt.Println("GoSQLX Enhanced Error Messages Demonstration")
	fmt.Println("==========================================================")
	fmt.Println()

	// Example 1: Simple typo in single-line SQL
	fmt.Println("Example 1: Common Typo Detection")
	fmt.Println("----------------------------------------------------------")
	sql1 := "SELECT * FORM users WHERE age > 18"
	err1 := errors.ExpectedTokenError("FROM", "FORM", models.Location{Line: 1, Column: 10}, sql1)
	fmt.Println(err1.Error())
	fmt.Println()

	// Example 2: Multi-line SQL with invalid number
	fmt.Println("Example 2: Multi-line SQL with Invalid Number")
	fmt.Println("----------------------------------------------------------")
	sql2 := `SELECT id, name, email
FROM users
WHERE age > 18.45.6
ORDER BY name`
	err2 := errors.InvalidNumberError("18.45.6", models.Location{Line: 3, Column: 13}, sql2)
	fmt.Println(err2.Error())
	fmt.Println()

	// Example 3: Unterminated string
	fmt.Println("Example 3: Unterminated String Literal")
	fmt.Println("----------------------------------------------------------")
	sql3 := "SELECT * FROM users WHERE name = 'John"
	err3 := errors.UnterminatedStringError(models.Location{Line: 1, Column: 34}, sql3)
	fmt.Println(err3.Error())
	fmt.Println()

	// Example 4: Missing clause in complex query
	fmt.Println("Example 4: Missing Required Clause")
	fmt.Println("----------------------------------------------------------")
	sql4 := `SELECT u.id, u.name, o.total
    users u
JOIN orders o ON u.id = o.user_id
WHERE u.active = true`
	err4 := errors.MissingClauseError("FROM", models.Location{Line: 2, Column: 5}, sql4)
	fmt.Println(err4.Error())
	fmt.Println()

	// Example 5: Incomplete statement
	fmt.Println("Example 5: Incomplete SQL Statement")
	fmt.Println("----------------------------------------------------------")
	sql5 := "SELECT * FROM users WHERE"
	err5 := errors.IncompleteStatementError(models.Location{Line: 1, Column: 26}, sql5)
	fmt.Println(err5.Error())
	fmt.Println()

	// Example 6: Unexpected character
	fmt.Println("Example 6: Unexpected Character")
	fmt.Println("----------------------------------------------------------")
	sql6 := "SELECT * FROM users WHERE age > 18 & active = 1"
	err6 := errors.UnexpectedCharError('&', models.Location{Line: 1, Column: 36}, sql6)
	fmt.Println(err6.Error())
	fmt.Println()

	// Example 7: Large line numbers
	fmt.Println("Example 7: Error in Large Multi-line Query")
	fmt.Println("----------------------------------------------------------")
	sql7 := `SELECT
    u.id,
    u.name,
    u.email,
    u.created_at,
    o.order_id,
    o.total_amount,
    o.status
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
WHERE u.age > 18.5.3
    AND u.active = true
    AND o.status IN ('pending', 'completed')
ORDER BY u.created_at DESC
LIMIT 100`
	err7 := errors.InvalidNumberError("18.5.3", models.Location{Line: 11, Column: 15}, sql7)
	fmt.Println(err7.Error())
	fmt.Println()

	// Show keyword suggestion capabilities
	fmt.Println("Example 8: Keyword Suggestion Capabilities")
	fmt.Println("----------------------------------------------------------")
	typos := []string{"FORM", "SELCT", "WAHER", "JION", "UPDTE", "DELET"}
	for _, typo := range typos {
		suggestion := errors.SuggestKeyword(typo)
		fmt.Printf("  '%s' → '%s'\n", typo, suggestion)
	}
	fmt.Println()

	// Show common mistake patterns
	fmt.Println("Example 9: Common Mistake Patterns")
	fmt.Println("----------------------------------------------------------")
	mistakeNames := []string{
		"string_instead_of_number",
		"missing_comma_in_list",
		"missing_join_condition",
		"ambiguous_column",
	}
	for _, name := range mistakeNames {
		if mistake, ok := errors.GetMistakeExplanation(name); ok {
			fmt.Println(errors.FormatMistakeExample(mistake))
		}
	}

	fmt.Println("==========================================================")
	fmt.Println("End of Demonstration")
	fmt.Println("==========================================================")
}
