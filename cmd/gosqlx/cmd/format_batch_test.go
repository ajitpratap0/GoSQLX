// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strings"
	"testing"
)

func TestFormatSQLBatchBoundaries(t *testing.T) {
	for _, input := range []string{
		"CREATE PROCEDURE p AS SELECT 1\nGO\nSELECT 2\nGO 3",
		"CREATE VIEW v AS SELECT 1 AS a\nGO -- next\nSELECT * FROM v",
		"CREATE TRIGGER tr ON t AFTER INSERT AS BEGIN SELECT 1; END\nGO\nSELECT 2",
		"SET NOCOUNT ON\nSELECT 1\nGO\nSET NOCOUNT OFF\nGO",
		"GO\nGO 2\nSELECT 1\nGO",
		"SELECT 1;\nGO\n;SELECT 2 -- hi",
	} {
		for _, compact := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/compact=%t", input, compact), func(t *testing.T) {
				opts := CLIFormatterOptions{Dialect: "sqlserver", Compact: compact, Uppercase: true, IndentSize: 2}
				out, err := formatWith(input, opts)
				if err != nil {
					t.Fatal(err)
				}
				assertRoundTrip(t, input, out, "sqlserver")
				if strings.Contains(out, "GO;") || strings.Contains(out, "GO 3;") {
					t.Fatalf("GO acquired a semicolon: %s", out)
				}
				again, err := formatWith(out, opts)
				if err != nil || again != out {
					t.Fatalf("format not idempotent: %v\n%s\n%s", err, out, again)
				}
			})
		}
	}
}
