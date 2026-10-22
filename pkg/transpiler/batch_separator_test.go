// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspilePreservesSQLServerBatches(t *testing.T) {
	for _, sql := range []string{
		"SELECT 1\nGO\nSELECT 2\nGO 3",
		"CREATE PROCEDURE p AS SELECT 1\nGO\nSELECT 2",
		"CREATE VIEW v AS SELECT 1 AS a\nGO\nSELECT * FROM v",
		"CREATE TRIGGER tr ON t AFTER INSERT AS BEGIN SELECT 1; END\nGO\nSELECT 2",
	} {
		t.Run(sql, func(t *testing.T) {
			out, err := transpiler.Transpile(sql, keywords.DialectSQLServer, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, "GO;") || strings.Contains(out, "GO 3;") {
				t.Fatalf("transpiler terminated GO with semicolon: %q", out)
			}
			original, err := parser.ParseWithDialect(sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(original)
			reparsed, err := parser.ParseWithDialect(out, keywords.DialectSQLServer)
			if err != nil {
				t.Fatalf("reparse: %v\n%s", err, out)
			}
			defer ast.ReleaseAST(reparsed)
			if original.SQL() != reparsed.SQL() {
				t.Errorf("batch meaning changed:\n%s\n%s", original.SQL(), reparsed.SQL())
			}
		})
	}
}

func TestTranspileRejectsUnrepresentableBatchScopes(t *testing.T) {
	for _, target := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectSQLite} {
		t.Run(string(target), func(t *testing.T) {
			out, err := transpiler.Transpile("SELECT 1\nGO 3\nSELECT 2", keywords.DialectSQLServer, target)
			if err == nil || out != "" {
				t.Fatalf("expected error for target without GO semantics, got %q, %v", out, err)
			}
		})
	}
}
