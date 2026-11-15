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
	return transpile(sql, from, to, true)
}

func transpile(sql string, from, to keywords.SQLDialect, prefilter bool) (string, error) {
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

	// Prefilters are superset tests on source bytes: false positives only cost
	// a walk; false negatives would change output or error order.
	src := scanSource(sql)
	// The tokenizer emits TokenTypeStringConcat only for two adjacent |, and
	// the parser's OR and concatenation parsing are the only producers of
	// PipesOr and ||; no rewrite rule creates either.
	rules := rulesForSource(from, to, !prefilter || src.pipe)
	for _, stmt := range tree.Statements {
		for _, rule := range rules {
			if err := rule(stmt); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
		}
		// RetargetOperators acts on ops spellings, $ money, { objects and U& escapes.
		// Its formKeep regrouping is repeated by the formatter's dialect pass.
		// Its 512 nesting guard cannot trigger on parser-built trees without these
		// bytes: parser.MaxRecursionDepth is 100. U& is caught by '&'; <-, =>,
		// and := are conservative pairs; W7-05 owns pruning. This list mirrors
		// pkg/sql/ast/retarget_operators.go and retarget_bitwise.go.
		if !prefilter || src.ops {
			if err := retargetOperators(stmt, from, to); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
		}
		// requoteDataType (ast/data_type_quotes.go) is the identity without
		// ", ` or [. The parser inserts these only from quoted type tokens
		// (typeNameTokenSQL) or [ tokens; rules only assign bare type names.
		// SetNameQuoteStyle still runs: names can have content delimiters.
		requoteIdentifiers(stmt, from, to, !prefilter || src.typeDelim || src.nonASCII)
	}

	// Re-render string literals for the target dialect (escaping and
	// introducers); see retargetStringLiterals.
	// Type "string" is set only by parser/string_literal.go's
	// newStringLiteral; all 11 callers consume string tokens. Their openers
	// contain ', " or $, or a non-ASCII byte (Unicode quote delimiters).
	if !prefilter || src.quote || src.nonASCII {
		for _, stmt := range tree.Statements {
			if err := retargetStringLiterals(stmt, to); err != nil {
				return "", fmt.Errorf("rewrite: %w", err)
			}
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

// sourceFeatures records possible source constructs; ops indicates an operator,
// literal or nesting that ast.RetargetOperators rewrites or refuses.
type sourceFeatures struct{ pipe, quote, nonASCII, typeDelim, ops bool }

const (
	srcPipe uint8 = 1 << iota
	srcQuote
	srcNonASCII
	srcTypeDelim
	srcOps
	// srcPair marks bytes that set srcOps only when the next byte completes a
	// retargetable two-byte spelling (<<, <-, >>, ->, =>, :=).
	srcPair
)

// srcClass maps every byte to its scanSource flags, so the hot loop is one
// table load per byte and only pair-opening bytes take the branch below.
var srcClass = func() (t [256]uint8) {
	t['|'] = srcPipe | srcOps
	t['\''] = srcQuote
	t['$'] = srcQuote | srcOps
	t['"'] = srcQuote | srcTypeDelim
	t['`'] = srcTypeDelim
	t['['] = srcTypeDelim
	for _, c := range []byte("^&#~@?!{") {
		t[c] = srcOps
	}
	for _, c := range []byte("<>-=:") {
		t[c] = srcPair
	}
	for c := 0x80; c < 256; c++ {
		t[c] = srcNonASCII
	}
	return t
}()

func scanSource(sql string) sourceFeatures {
	var acc uint8
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		k := srcClass[c]
		if k == 0 {
			continue
		}
		if k&srcPair != 0 {
			if i+1 < len(sql) {
				n := sql[i+1]
				switch c {
				case '<':
					if n == '<' || n == '-' {
						acc |= srcOps
					}
				case '>', '-', '=':
					if n == '>' {
						acc |= srcOps
					}
				case ':':
					if n == '=' {
						acc |= srcOps
					}
				}
			}
			continue
		}
		acc |= k
	}
	return sourceFeatures{
		pipe:      acc&srcPipe != 0,
		quote:     acc&srcQuote != 0,
		nonASCII:  acc&srcNonASCII != 0,
		typeDelim: acc&srcTypeDelim != 0,
		ops:       acc&srcOps != 0,
	}
}
