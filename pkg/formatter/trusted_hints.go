// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/renderhint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// These hooks are reserved for parse-to-render paths that have not exposed
// the mutable tree to callers. Public formatter entry points always scan.
func init() {
	renderhint.FormatAST = trustedFormatAST
	renderhint.FormatStatement = trustedFormatStatement
}

func trustedFormatAST(tree any, mask uint64, valid bool, options any) (string, error) {
	a, ok := tree.(*ast.AST)
	if !ok || a == nil {
		return "", fmt.Errorf("invalid trusted AST %T", tree)
	}
	opts, ok := options.(ast.FormatOptions)
	if !ok {
		return "", fmt.Errorf("invalid trusted format options %T", options)
	}
	if valid {
		// The mask belongs to this parse, never to the mutable AST. Only dirty
		// statements need the exact scan; positions beyond the mask always scan.
		target := strings.ToLower(opts.Dialect)
		for i, stmt := range a.Statements {
			if target != "" && renderhint.Dirty(mask, i) && needsDialectRewrite(stmt, target) {
				return FormatASTChecked(a, opts)
			}
		}
		if len(a.Comments) > 0 && len(a.StatementEnds) == len(a.Statements) {
			return formatASTComments(a, opts, nil)
		}
		return formatAST(a, opts), nil
	}
	return FormatASTChecked(a, opts)
}

func trustedFormatStatement(tree any, index int, mask uint64, valid bool, options any) (string, error) {
	a, ok := tree.(*ast.AST)
	if !ok || a == nil || index < 0 || index >= len(a.Statements) {
		return "", fmt.Errorf("invalid trusted statement index %d", index)
	}
	opts, ok := options.(ast.FormatOptions)
	if !ok {
		return "", fmt.Errorf("invalid trusted format options %T", options)
	}
	if valid && !renderhint.Dirty(mask, index) {
		return formatStatement(a.Statements[index], opts), nil
	}
	return FormatStatementChecked(a.Statements[index], opts)
}
