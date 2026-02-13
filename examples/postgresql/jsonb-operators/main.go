// Package main demonstrates PostgreSQL JSON/JSONB operator parsing capabilities
package main

import (
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	fmt.Println("PostgreSQL JSON/JSONB Operators Examples")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("GoSQLX v1.6.0 supports all PostgreSQL JSON/JSONB operators:")
	fmt.Println("  -> (get JSON element), ->> (get text)")
	fmt.Println("  #> (get path), #>> (get path as text)")
	fmt.Println("  @> (contains), <@ (contained by)")
	fmt.Println("  ? (key exists), ?| (any key), ?& (all keys)")
	fmt.Println("  #- (delete path)")
	fmt.Println()

	examples := []struct {
		name        string
		sql         string
		description string
	}{
		// Basic extraction operators
		{
			name:        "Arrow Operator (->)",
			sql:         `SELECT data->'name' AS name_json FROM users WHERE id = 1`,
			description: "Extract JSON object field as JSON",
		},
		{
			name:        "Double Arrow Operator (->>)",
			sql:         `SELECT data->>'name' AS name_text FROM users WHERE data->>'status' = 'active'`,
			description: "Extract JSON object field as text",
		},
		{
			name:        "Array Index Access",
			sql:         `SELECT tags->0 AS first_tag FROM posts`,
			description: "Access array elements by index",
		},
		{
			name:        "Chained Extraction",
			sql:         `SELECT config->'database'->'connection'->>'host' AS db_host FROM settings`,
			description: "Chain multiple extractions for nested access",
		},

		// Path operators
		{
			name:        "Hash Arrow Path (#>)",
			sql:         `SELECT data#>'{address,city}' AS city_json FROM customers`,
			description: "Extract at path as JSON",
		},
		{
			name:        "Hash Double Arrow Path (#>>)",
			sql:         `SELECT data#>>'{address,city}' AS city_text FROM customers`,
			description: "Extract at path as text",
		},

		// Containment operators
		{
			name:        "Contains Operator (@>)",
			sql:         `SELECT * FROM products WHERE attributes @> '{"color": "red"}'`,
			description: "Check if JSONB contains specified value",
		},
		{
			name:        "Contained By Operator (<@)",
			sql:         `SELECT * FROM products WHERE '{"type": "electronics"}' <@ attributes`,
			description: "Check if value is contained by JSONB",
		},

		// Key existence operators
		{
			name:        "Key Exists (?)",
			sql:         `SELECT * FROM users WHERE profile ? 'email'`,
			description: "Check if key exists in JSONB",
		},
		{
			name:        "Any Key Exists (?|)",
			sql:         `SELECT * FROM users WHERE preferences ?| array['dark_mode', 'notifications']`,
			description: "Check if any of the keys exist",
		},
		{
			name:        "All Keys Exist (?&)",
			sql:         `SELECT * FROM users WHERE profile ?& array['name', 'email', 'phone']`,
			description: "Check if all keys exist",
		},

		// Delete/modification operator
		{
			name:        "Delete Path (#-)",
			sql:         `UPDATE users SET data = data #- '{temporary}' WHERE id = 1`,
			description: "Delete key/path from JSONB",
		},

		// Complex queries combining operators
		{
			name: "Combined JSON Operations",
			sql: `SELECT
    u.id,
    u.data->>'name' AS user_name,
    u.data->'address'->>'city' AS city
FROM users u
WHERE u.data @> '{"active": true}'`,
			description: "Combine multiple JSON operators in a query",
		},
		{
			name: "JSONB in JOIN Conditions",
			sql: `SELECT o.id, o.data->>'total' AS total, c.name
FROM orders o
JOIN customers c ON c.id = 1
WHERE o.data->'items' @> '[{"product": "Widget"}]'`,
			description: "Use JSON extraction in JOIN conditions",
		},
	}

	for i, ex := range examples {
		fmt.Printf("%d. %s\n", i+1, ex.name)
		fmt.Printf("   Description: %s\n", ex.description)
		fmt.Println("   SQL:")
		printJSONSQL(ex.sql)
		fmt.Println()
		parseAndDisplayJSON(ex.sql)
		fmt.Println()
	}

	// Summary of supported operators
	fmt.Println("Summary of Supported JSON/JSONB Operators")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("| Operator | Description                      | Example                  |")
	fmt.Println("|----------|----------------------------------|--------------------------|")
	fmt.Println("| ->       | Get JSON array element/object    | data->'key'              |")
	fmt.Println("| ->>      | Get JSON element as text         | data->>'key'             |")
	fmt.Println("| #>       | Get JSON at path                 | data#>'{a,b}'            |")
	fmt.Println("| #>>      | Get JSON at path as text         | data#>>'{a,b}'           |")
	fmt.Println("| @>       | Contains                         | data @> '{\"k\":\"v\"}'  |")
	fmt.Println("| <@       | Contained by                     | '{\"k\":\"v\"}' <@ data  |")
	fmt.Println("| ?        | Key exists                       | data ? 'key'             |")
	fmt.Println("| ?|       | Any key exists                   | data ?| array['a','b']   |")
	fmt.Println("| ?&       | All keys exist                   | data ?& array['a','b']   |")
	fmt.Println("| #-       | Delete at path                   | data #- '{key}'          |")
}

func printJSONSQL(sql string) {
	lines := splitJSONLines(sql)
	for _, line := range lines {
		fmt.Printf("      %s\n", line)
	}
}

func splitJSONLines(s string) []string {
	var lines []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, string(current))
			current = nil
		} else {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		lines = append(lines, string(current))
	}
	return lines
}

func parseAndDisplayJSON(sql string) {
	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	tokensWithSpan, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		log.Printf("   Tokenize error: %v", err)
		return
	}

	// Convert tokens
	tokens, err := parser.ConvertTokensForParser(tokensWithSpan) //nolint:staticcheck // intentional use of deprecated type for Phase 1 bridge
	if err != nil {
		log.Printf("   Token conversion error: %v", err)
		return
	}

	// Parse
	p := parser.NewParser()
	defer p.Release()

	astObj, err := p.Parse(tokens)
	if err != nil {
		log.Printf("   Parse error: %v", err)
		return
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		log.Println("   No statements parsed")
		return
	}

	fmt.Println("   Parsed Successfully!")
	fmt.Printf("   - Statement Type: %s\n", getStatementType(astObj.Statements[0]))
	fmt.Printf("   - Token Count: %d\n", len(tokens))

	// Count JSON operators in the query
	jsonOps := countJSONOperators(sql)
	if len(jsonOps) > 0 {
		fmt.Println("   - JSON Operators found:")
		for op, count := range jsonOps {
			fmt.Printf("       %s: %d\n", op, count)
		}
	}
}

func getStatementType(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.InsertStatement:
		return "INSERT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	default:
		return fmt.Sprintf("%T", stmt)
	}
}

func countJSONOperators(sql string) map[string]int {
	ops := map[string]int{}
	operators := []string{"#>>", "#>", "#-", "->>", "->", "@>", "<@", "?|", "?&", "?"}

	for _, op := range operators {
		count := 0
		for i := 0; i <= len(sql)-len(op); i++ {
			if sql[i:i+len(op)] == op {
				// Avoid double counting (e.g., ->> should not count as ->)
				if op == "->" && i+2 < len(sql) && sql[i+2] == '>' {
					continue
				}
				if op == "#>" && i+2 < len(sql) && sql[i+2] == '>' {
					continue
				}
				if op == "?" && i+1 < len(sql) && (sql[i+1] == '|' || sql[i+1] == '&') {
					continue
				}
				count++
			}
		}
		if count > 0 {
			ops[op] = count
		}
	}
	return ops
}
