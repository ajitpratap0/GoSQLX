// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import "testing"

func TestCLIUnicodeIdentifierSpelling(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	path := writeTemp(t, "unicode-name.sql", `SELECT U&"a\000Ab" FROM t`)
	result := runCLI(t, nil, "format", "--dialect", "postgresql", path)
	if result.err != nil {
		t.Fatalf("format: %v\n%s", result.err, result.stderr)
	}
	want := "SELECT U&\"a\\000Ab\"\nFROM t\n"
	if result.stdout != want {
		t.Fatalf("got %q, want %q", result.stdout, want)
	}
}
