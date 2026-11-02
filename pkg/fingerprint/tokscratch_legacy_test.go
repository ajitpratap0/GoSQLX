// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// LegacyNormalizeForScratchTest preserves the public-tokenizer pipeline as a compatibility oracle.
func LegacyNormalizeForScratchTest(sql string) (string, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.TokenizeString(sql)
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
		formatted, err := formatter.FormatStatementChecked(stmt, opts)
		if err != nil {
			return "", fmt.Errorf("fingerprint: formatting failed: %w", err)
		}
		parts = append(parts, formatted)
	}

	return strings.Join(parts, "; "), nil
}
