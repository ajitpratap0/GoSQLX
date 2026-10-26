// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"strings"
	"testing"
)

// TestFormatCommentsStayWithTheirStatements checks that comments are not
// attached to the wrong statement when a statement holds ';' (a procedure or
// trigger body) or T-SQL statements are not separated by ';'.
func TestFormatCommentsStayWithTheirStatements(t *testing.T) {
	tests := []struct {
		dialect string
		input   string
		// order lists pieces of the output in the order they must appear.
		order []string
	}{
		{"sqlserver",
			"-- A\nSELECT 1\nSELECT 2;\n-- B: the proc\nCREATE PROC p AS BEGIN SELECT 1; END;\n",
			[]string{"-- A", "SELECT 1", "SELECT 2", "-- B: the proc", "CREATE PROC"}},
		{"mysql",
			"-- Section one\nSELECT 1 FROM users;\n-- Section two: trigger\nCREATE TRIGGER t AFTER INSERT ON x FOR EACH ROW BEGIN SELECT 1; SELECT 2; END;\n-- Section three\nSELECT 3 FROM orders;\n",
			[]string{"-- Section one", "SELECT 1", "users", "-- Section two: trigger", "CREATE TRIGGER", "-- Section three", "SELECT 3"}},
	}
	for _, tc := range tests {
		for _, compact := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/compact=%t", tc.dialect, compact), func(t *testing.T) {
				opts := CLIFormatterOptions{Dialect: tc.dialect, Compact: compact, Uppercase: true, IndentSize: 2}
				out, err := formatWith(tc.input, opts)
				if err != nil {
					t.Fatal(err)
				}
				rest := out
				for _, piece := range tc.order {
					i := strings.Index(rest, piece)
					if i < 0 {
						t.Fatalf("%q missing or out of order in:\n%s", piece, out)
					}
					rest = rest[i+len(piece):]
				}
				again, err := formatWith(out, opts)
				if err != nil || again != out {
					t.Fatalf("format not idempotent: %v\n%s\n%s", err, out, again)
				}
			})
		}
	}
}
