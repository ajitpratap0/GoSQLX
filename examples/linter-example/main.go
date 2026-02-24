// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	fmt.Println("\n" + string(make([]byte, 80)) + "\n")

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
