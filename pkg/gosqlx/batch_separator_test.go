// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestBatchSeparatorRoundTrip(t *testing.T) {
	tests := []struct{ name, sql string }{
		{"procedure", "CREATE PROCEDURE p AS SELECT 1\nGO\nSELECT 2\nGO 3"},
		{"view", "CREATE VIEW v AS SELECT 1 AS a\nGO\nSELECT * FROM v"},
		{"trigger", "CREATE TRIGGER tr ON t AFTER INSERT AS BEGIN SELECT 1; END\nGO\nSELECT 2"},
		{"empty batches", "GO\nGO 2\nSELECT 1\nGO\nGO"},
		{"comments", "-- lead\nCREATE PROCEDURE p AS SELECT 1;\nGO -- batch\n/* next */ SELECT 2\nGO 3 -- end"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			separators := 0
			for _, s := range tree.Statements {
				if sep, ok := s.(*ast.BatchSeparator); ok {
					if sep.RepeatCount < 0 || sep.TokenLiteral() != "GO" || len(sep.Children()) != 0 {
						t.Errorf("invalid batch separator: %#v", sep)
					}
					separators++
				}
			}
			if separators == 0 {
				t.Fatal("parser discarded GO batch boundaries")
			}
			outputs := []string{tree.SQL(), FormatAST(tree)}
			for _, semicolons := range []bool{false, true} {
				opts := ast.CompactStyle()
				opts.Dialect, opts.AddSemicolon = "sqlserver", semicolons
				outputs = append(outputs, formatter.FormatAST(tree, opts))
				options := DefaultFormatOptions()
				options.AddSemicolon = semicolons
				out, err := FormatWithDialect(tc.sql, options, keywords.DialectSQLServer)
				if err != nil {
					t.Fatalf("FormatWithDialect: %v", err)
				}
				outputs = append(outputs, out)
			}
			for _, out := range outputs {
				if strings.Contains(out, "GO;") || strings.Contains(out, "GO 3;") {
					t.Errorf("batch separator gained semicolon: %s", out)
				}
				again, err := ParseWithDialect(out, keywords.DialectSQLServer)
				if err != nil {
					t.Errorf("reparse %q: %v", out, err)
					continue
				}
				if again.SQL() != tree.SQL() {
					t.Errorf("batch meaning changed:\nwant %s\ngot %s", tree.SQL(), again.SQL())
				}
				ast.ReleaseAST(again)
			}
		})
	}
}

func TestBatchSeparatorInvalidCounts(t *testing.T) {
	for _, count := range []string{"0", "-1", "1.5", "999999999999999999999999999999"} {
		t.Run(count, func(t *testing.T) {
			tree, err := ParseWithDialect("SELECT 1\nGO "+count+"\nSELECT 2", keywords.DialectSQLServer)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("accepted invalid GO repeat count")
			}
		})
	}
}
