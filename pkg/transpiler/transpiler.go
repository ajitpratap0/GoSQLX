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
// Supported dialect pairs:
//   - MySQL → PostgreSQL
//   - PostgreSQL → MySQL
//   - PostgreSQL → SQLite
//
// For unsupported dialect pairs the SQL is parsed and reformatted without any
// dialect-specific rewrites (passthrough with normalisation).
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
	"strings"

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
// If no rules are registered for the pair, the SQL is returned normalised
// (parsed and reformatted without dialect-specific changes).
func Transpile(sql string, from, to keywords.SQLDialect) (string, error) {
	// Use ParseWithDialect so the tokenizer and parser understand dialect-
	// specific syntax (e.g. MySQL backtick identifiers, PG ILIKE, etc.).
	tree, err := parser.ParseWithDialect(sql, from)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}

	// Apply rules for this dialect pair.
	rules := rulesFor(from, to)
	for _, stmt := range tree.Statements {
		for _, rule := range rules {
			if err := rule(stmt); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
		}
	}

	// Format each statement and join with ";\n".
	parts := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		parts = append(parts, formatter.FormatStatement(stmt, ast.CompactStyle()))
	}
	return strings.Join(parts, ";\n"), nil
}
