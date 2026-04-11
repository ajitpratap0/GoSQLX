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

package transform

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Rule represents an AST rewrite rule that can be applied to a single SQL statement.
// Rules modify the AST in-place and return an error if the transform cannot be
// applied (e.g., applying a SELECT-only rule to an INSERT statement).
//
// Implement this interface to create custom transform rules:
//
//	type MyRule struct{}
//
//	func (r MyRule) Apply(stmt ast.Statement) error {
//	    sel, ok := stmt.(*ast.SelectStatement)
//	    if !ok {
//	        return nil // skip non-SELECT statements
//	    }
//	    // modify sel in-place
//	    return nil
//	}
//
// Built-in rules are created by the constructor functions in this package (AddWhere,
// AddColumn, AddJoin, SetLimit, etc.). Use Apply (the package-level function) to
// chain multiple rules together.
type Rule interface {
	Apply(stmt ast.Statement) error
}

// RuleFunc is a function type that implements the Rule interface. It allows
// anonymous functions and closures to be used directly as transform rules without
// defining a named type. All built-in rule constructors (AddWhere, AddColumn, etc.)
// return a RuleFunc internally.
//
// Example:
//
//	rule := transform.RuleFunc(func(stmt ast.Statement) error {
//	    sel, ok := stmt.(*ast.SelectStatement)
//	    if !ok {
//	        return nil
//	    }
//	    sel.Distinct = true
//	    return nil
//	})
type RuleFunc func(stmt ast.Statement) error

// Apply implements the Rule interface by invoking the underlying function.
func (f RuleFunc) Apply(stmt ast.Statement) error {
	return f(stmt)
}

// Apply executes one or more rules against an AST statement in the order they are
// provided. If any rule returns a non-nil error the function stops immediately and
// returns that error without applying subsequent rules.
//
// This is the primary entry point for composing transforms:
//
//	err := transform.Apply(stmt,
//	    transform.AddWhereFromSQL("active = true"),
//	    transform.SetLimit(100),
//	    transform.AddOrderBy("created_at", true),
//	)
func Apply(stmt ast.Statement, rules ...Rule) error {
	for _, rule := range rules {
		if err := rule.Apply(stmt); err != nil {
			return err
		}
	}
	return nil
}

// ErrUnsupportedStatement is returned when a transform rule is applied to a statement
// type it does not support. For example, AddColumn only supports SelectStatement; applying
// it to an InsertStatement will produce this error.
//
// Fields:
//   - Transform: Name of the transform function that produced the error (e.g., "AddColumn")
//   - Got: Human-readable name of the statement type that was rejected (e.g., "INSERT")
type ErrUnsupportedStatement struct {
	Transform string
	Got       string
}

func (e *ErrUnsupportedStatement) Error() string {
	return fmt.Sprintf("transform %s: unsupported statement type %s", e.Transform, e.Got)
}

// parseSQL parses a full SQL statement and returns the first statement's AST.
func parseSQL(sql string) (ast.Statement, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	p := parser.NewParser()
	defer p.Release()

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	if tree == nil || len(tree.Statements) == 0 {
		return nil, fmt.Errorf("no statements parsed")
	}

	return tree.Statements[0], nil
}

// parseCondition parses a SQL condition expression by wrapping it in a SELECT.
func parseCondition(sql string) (ast.Expression, error) {
	stmt, err := parseSQL("SELECT * FROM _t WHERE " + sql)
	if err != nil {
		return nil, fmt.Errorf("parse condition %q: %w", sql, err)
	}

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil, fmt.Errorf("parse condition %q: failed to extract WHERE", sql)
	}

	return sel.Where, nil
}

// parseJoinClause parses a JOIN clause from SQL by wrapping it in a SELECT.
func parseJoinClause(sql string) (*ast.JoinClause, error) {
	stmt, err := parseSQL("SELECT * FROM _t " + sql)
	if err != nil {
		return nil, fmt.Errorf("parse join %q: %w", sql, err)
	}

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || len(sel.Joins) == 0 {
		return nil, fmt.Errorf("parse join %q: no join found", sql)
	}

	return &sel.Joins[0], nil
}

// stmtTypeName returns a human-readable name for a statement type.
func stmtTypeName(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	case *ast.InsertStatement:
		return "INSERT"
	default:
		return fmt.Sprintf("%T", stmt)
	}
}

// ParseSQL parses a SQL string into a full AST containing all statements. This is
// a convenience wrapper around the tokenizer and parser pipeline that handles
// resource pooling automatically.
//
// Use this function when you need an AST for subsequent Apply calls:
//
//	tree, err := transform.ParseSQL("SELECT id, name FROM users WHERE active = true")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	stmt := tree.Statements[0]
//	transform.Apply(stmt, transform.SetLimit(10))
//	fmt.Println(transform.FormatSQL(stmt))
//
// Returns a *ast.AST containing all parsed statements, or an error if tokenization
// or parsing fails.
func ParseSQL(sql string) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	p := parser.NewParser()
	defer p.Release()

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return tree, nil
}

// FormatSQL converts an AST statement back into a compact SQL string using the
// GoSQLX formatter. It is the inverse of ParseSQL and completes the
// parse-transform-format round-trip.
//
// The output uses compact style with minimal whitespace. Use this after applying
// transforms to obtain the final SQL to execute or log.
//
// Example:
//
//	sql := transform.FormatSQL(stmt)
//	// "SELECT id, name FROM users WHERE active = true LIMIT 10"
func FormatSQL(stmt ast.Statement) string {
	return formatter.FormatStatement(stmt, ast.CompactStyle())
}

// FormatSQLWithDialect converts an AST statement back into a compact SQL string
// using dialect-specific syntax for row-limiting clauses (TOP for SQL Server,
// FETCH FIRST for Oracle, LIMIT for PostgreSQL/MySQL/etc.).
//
// Pass keywords.DialectGeneric or an empty SQLDialect for generic behavior
// identical to FormatSQL.
//
// Example:
//
//	sql := transform.FormatSQLWithDialect(stmt, keywords.DialectSQLServer)
//	// "SELECT TOP 100 * FROM users"
func FormatSQLWithDialect(stmt ast.Statement, dialect keywords.SQLDialect) string {
	opts := ast.CompactStyle()
	opts.Dialect = string(dialect)
	return formatter.FormatStatement(stmt, opts)
}

// ParseSQLWithDialect parses a SQL string using dialect-specific tokenization and
// parsing rules. This enables correct handling of dialect-specific syntax such as
// SQL Server TOP, MySQL backtick identifiers, and Snowflake QUALIFY.
//
// Use this when the input SQL uses dialect-specific constructs that the generic
// parser would reject or misinterpret.
//
// Example:
//
//	tree, err := transform.ParseSQLWithDialect("SELECT TOP 10 * FROM users", keywords.DialectSQLServer)
func ParseSQLWithDialect(sql string, dialect keywords.SQLDialect) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	if dialect != "" {
		tkz.SetDialect(dialect)
	}

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	p := parser.NewParser(parser.WithDialect(string(dialect)))
	defer p.Release()

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return tree, nil
}
