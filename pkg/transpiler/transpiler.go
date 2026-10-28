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

// Package transpiler converts SQL from one dialect to another by parsing the
// input SQL, applying a chain of rewrite rules that mutate dialect-specific
// AST constructs in place, and then reformatting the result.
//
// Additional dialect-specific rewrite sets:
//   - MySQL → PostgreSQL
//   - PostgreSQL → MySQL
//   - PostgreSQL → SQLite
//
// All cross-dialect pairs apply common row-limit, operator, identifier and
// string-literal rewrites. Constructs without a safe equivalent return an error.
//
// Example:
//
//	result, err := transpiler.Transpile(
//	    "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
//	    keywords.DialectMySQL,
//	    keywords.DialectPostgreSQL,
//	)
//	// result: "CREATE TABLE t (id SERIAL PRIMARY KEY)"
package transpiler

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// RewriteRule is a function that mutates an AST statement in-place to rewrite
// dialect-specific constructs. It returns an error if rewriting fails.
type RewriteRule func(stmt ast.Statement) error

// Transpile parses sql in the from dialect, applies all registered rewrite
// rules for the (from → to) dialect pair, and returns the reformatted SQL.
//
// If from == to, the SQL is parsed and reformatted with no rewrites applied.
// All cross-dialect pairs apply common rewrites in addition to any registered
// dialect-specific rules.
// SQL Server GO batch scopes cannot be represented in other dialects and
// return an error rather than dropping boundaries or repeat counts.
// Operators and literals whose meaning depends on the dialect (^ as power or
// XOR, PostgreSQL prefix operators, SQL Server money literals, Snowflake
// object constants) are rewritten for the target or return an error; see
// retargetOperators.
func Transpile(sql string, from, to keywords.SQLDialect) (string, error) {
	// Use ParseWithDialect so the tokenizer and parser understand dialect-
	// specific syntax (e.g. MySQL backtick identifiers, PG ILIKE, etc.).
	tree, err := parser.ParseWithDialect(sql, from)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	// The tree is pooled on return: rewrite rules must not retain node
	// references beyond this call.
	defer ast.ReleaseAST(tree)
	if to != keywords.DialectSQLServer {
		for _, stmt := range tree.Statements {
			if _, ok := stmt.(*ast.BatchSeparator); ok {
				return "", fmt.Errorf("rewrite: SQL Server GO batch scopes are not supported in %s", to)
			}
		}
	}

	// Apply rules for this dialect pair.
	rules := rulesFor(from, to)
	for _, stmt := range tree.Statements {
		for _, rule := range rules {
			if err := rule(stmt); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
		}
		if err := retargetOperators(stmt, from, to); err != nil {
			return "", fmt.Errorf("rewrite: %w", err)
		}
		requoteIdentifiers(stmt, from, to)
	}

	// Re-render string literals for the target dialect (escaping and
	// introducers); see retargetStringLiterals.
	for _, stmt := range tree.Statements {
		if err := retargetStringLiterals(stmt, to); err != nil {
			return "", fmt.Errorf("rewrite: %w", err)
		}
	}

	// Format the whole tree so client batch separators retain their scope. The
	// target decides dialect-specific spellings such as MINUS versus EXCEPT
	// and set-operation grouping.
	style := ast.CompactStyle()
	style.Dialect = string(to)
	out, err := formatter.FormatASTChecked(tree, style)
	if err != nil {
		return "", fmt.Errorf("format: %w", err)
	}
	return out, nil
}
