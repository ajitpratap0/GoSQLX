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

package fingerprint

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
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

func normalizeLegacy(sql string, dialect keywords.SQLDialect) (string, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	if dialect != "" {
		tkz.SetDialect(dialect)
	}

	tokens, err := tokscratch.String(tkz, sql)
	if err != nil {
		return "", fmt.Errorf("fingerprint: tokenization failed: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	if dialect != "" {
		p.ApplyOptions(parser.WithDialect(string(dialect)))
	}

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
		formatted, err := formatter.FormatStatementChecked(stmt, opts)
		if err != nil {
			return "", fmt.Errorf("fingerprint: formatting failed: %w", err)
		}
		parts = append(parts, formatted)
	}

	return strings.Join(parts, "; "), nil
}
