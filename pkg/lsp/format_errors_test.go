// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"errors"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormattingFallbackPreservesSemanticError(t *testing.T) {
	// The wire API currently uses one dialect for both parsing and rendering.
	// Use a real cross-dialect error to exercise its semantic error branch.
	tree, err := gosqlx.ParseWithDialect("SELECT a ^ b", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	opts := ast.CompactStyle()
	opts.Dialect = "sqlite"
	_, renderErr := formatter.FormatASTChecked(tree, opts)
	if renderErr == nil {
		t.Fatal("expected unsupported XOR error")
	}
	out, err := formattingFallback("SELECT a ^ b", FormattingOptions{InsertSpaces: true, TabSize: 2}, renderErr)
	if !errors.Is(err, renderErr) || !strings.Contains(err.Error(), "formatting failed") || out != "" {
		t.Fatalf("got %q, %v; want wrapped render error", out, err)
	}
}
