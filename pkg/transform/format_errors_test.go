// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormatSQLWithDialectCheckedRejectsUnsupportedXor(t *testing.T) {
	tree, err := ParseSQLWithDialect("SELECT a ^ b", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	out, err := FormatSQLWithDialectChecked(tree.Statements[0], keywords.DialectSQLite)
	if err == nil || !strings.Contains(err.Error(), "XOR") || out != "" {
		t.Fatalf("got %q, %v; want XOR error", out, err)
	}
	if out := FormatSQLWithDialect(tree.Statements[0], keywords.DialectSQLite); out != "" {
		t.Fatalf("legacy wrapper = %q; want documented empty result", out)
	}
}
