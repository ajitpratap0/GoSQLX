// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"reflect"
	"testing"
)

func TestSplitStatementsPreservesInvalidGOBatchCount(t *testing.T) {
	for _, count := range []string{"0", "999999999999999999999999999999", "1.5", "-1"} {
		t.Run(count, func(t *testing.T) {
			src := "SELECT 1\nGO " + count + "\nSELECT 2"
			if got := SplitStatements(src, "sqlserver"); !reflect.DeepEqual(got, []string{src}) {
				t.Fatalf("SplitStatements(%q) = %q; invalid GO count must reach the parser", src, got)
			}
		})
	}
}

func TestSplitStatementsConsumesValidGOBatchCount(t *testing.T) {
	for _, directive := range []string{"GO", "GO 3", "GO 3 -- repeat", "GO 3 -- repeat\r"} {
		t.Run(directive, func(t *testing.T) {
			src := "SELECT 1\r\n" + directive + "\nSELECT 2"
			want := []string{"SELECT 1\r\n", "SELECT 2"}
			if got := SplitStatements(src, "sqlserver"); !reflect.DeepEqual(got, want) {
				t.Fatalf("SplitStatements(%q) = %q, want %q", src, got, want)
			}
		})
	}
}
