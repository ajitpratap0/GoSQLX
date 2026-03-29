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

// Package fingerprint provides SQL query normalization and fingerprinting.
//
// Normalize replaces all literal values (strings, numbers, booleans, NULLs)
// with "?" placeholders and returns the re-formatted SQL. Two queries that are
// structurally identical but differ only in literal values will produce the
// same normalized output.
//
// Fingerprint returns the SHA-256 hex digest of the normalized form, providing
// a stable 64-character key for query deduplication, caching, and slow-query
// grouping.
//
// Existing parameter placeholders ($1, ?, :name) are always preserved
// unchanged.
//
// Example:
//
//	n, err := fingerprint.Normalize("SELECT * FROM users WHERE id = 42")
//	// n == "SELECT * FROM users WHERE id = ?"
//
//	fp, err := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 42")
//	// fp == "a3f1..." (64-char SHA-256 hex)
//	fp2, _ := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 999")
//	// fp == fp2 (same structure, different literal)
package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// literalNormalizer is an AST visitor that replaces all non-placeholder literal
// values with "?". It mutates the AST in-place; callers must not reuse the AST
// after normalization.
type literalNormalizer struct{}

// Visit implements ast.Visitor. It replaces literal values with "?" by mutating
// each LiteralValue node encountered. Placeholder nodes ($1, ?, :name) are
// left untouched.
func (n *literalNormalizer) Visit(node ast.Node) (ast.Visitor, error) {
	if node == nil {
		return nil, nil
	}
	if lit, ok := node.(*ast.LiteralValue); ok {
		// Skip existing parameter placeholders — they must be preserved.
		if strings.EqualFold(lit.Type, "placeholder") {
			return n, nil
		}
		// Replace the literal value with a bare "?" marker. Setting Type to ""
		// causes LiteralValue.SQL() to fall through to the default case which
		// returns fmt.Sprintf("%v", l.Value) == "?".
		lit.Value = "?"
		lit.Type = ""
	}
	return n, nil
}

// Normalize parses the SQL, replaces all literal values (strings, numbers,
// booleans, NULLs) with "?" placeholders, and returns the re-formatted SQL.
//
// Two queries that are structurally identical but use different literal values
// (e.g., WHERE id = 1 vs WHERE id = 42) will produce the same normalized output.
// Existing parameter placeholders ($1, ?, :name) are preserved unchanged.
//
// Returns an error if the SQL cannot be parsed.
//
// Example:
//
//	n, err := fingerprint.Normalize("SELECT * FROM users WHERE id = 42 AND name = 'alice'")
//	// n == "SELECT * FROM users WHERE id = ? AND name = ?"
func Normalize(sql string) (string, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("fingerprint: tokenization failed: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	astObj, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return "", fmt.Errorf("fingerprint: parsing failed: %w", err)
	}
	defer ast.ReleaseAST(astObj)

	// Walk the AST and replace all non-placeholder literals with "?".
	v := &literalNormalizer{}
	for _, stmt := range astObj.Statements {
		if err := ast.Walk(v, stmt); err != nil {
			return "", fmt.Errorf("fingerprint: AST walk failed: %w", err)
		}
	}

	// Format the mutated AST back to SQL using compact (single-line) style.
	opts := ast.CompactStyle()
	var parts []string
	for _, stmt := range astObj.Statements {
		parts = append(parts, formatter.FormatStatement(stmt, opts))
	}

	return strings.Join(parts, "; "), nil
}

// Fingerprint parses the SQL, normalizes all literals to "?", and returns the
// SHA-256 hex digest of the normalized form. Two structurally identical queries
// with different literal values will produce the same fingerprint.
//
// The fingerprint is stable across GoSQLX versions as long as the formatter
// output for a given AST structure does not change.
//
// Returns a 64-character lowercase hex string, or an error if SQL is invalid.
//
// Example:
//
//	fp, err := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 42")
//	fp2, _ := fingerprint.Fingerprint("SELECT * FROM users WHERE id = 999")
//	// fp == fp2 (same structure, different literal)
func Fingerprint(sql string) (string, error) {
	normalized, err := Normalize(sql)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(normalized))
	return fmt.Sprintf("%x", h), nil
}
