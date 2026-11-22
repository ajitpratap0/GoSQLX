// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestSQLFormatterRejectsUnsupportedXor(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT a ^ b", keywords.DialectMySQL)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	f := NewSQLFormatter(FormatterOptions{Dialect: "sqlite"})
	for _, comments := range []bool{false, true} {
		var out string
		if comments {
			out, err = f.FormatWithComments(tree, nil, nil)
		} else {
			out, err = f.Format(tree)
		}
		if err == nil || !strings.Contains(err.Error(), "XOR") || out != "" {
			t.Fatalf("comments=%v: got %q, %v; want XOR error", comments, out, err)
		}
	}
}
