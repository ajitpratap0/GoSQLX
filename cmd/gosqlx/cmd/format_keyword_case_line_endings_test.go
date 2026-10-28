// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestCLIFormatCRLFInPlace(t *testing.T) {
	path := writeTemp(t, "crlf.sql", "-- leading\r\nselect /* multi\r\nline */ 1 -- trailing\r\n")
	res := runCLI(t, nil, "format", "-i", path)
	if res.err != nil {
		t.Fatalf("format: %v: %s", res.err, res.stderr)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "\r") {
		t.Fatalf("mixed endings: %q", out)
	}
	for _, comment := range []string{"-- leading", "/* multi\nline */", "-- trailing"} {
		if !strings.Contains(string(out), comment) {
			t.Fatalf("lost %q in %q", comment, out)
		}
	}
}

func TestCLIFormatNoUppercaseExpressions(t *testing.T) {
	res := runCLI(t, str("select a from t where b is null and c in (1) order by a desc"), "format", "--no-uppercase")
	if res.err != nil {
		t.Fatalf("format: %v: %s", res.err, res.stderr)
	}
	for _, part := range []string{"where b is null and c in (1)", "order by a desc"} {
		if !strings.Contains(res.stdout, part) {
			t.Fatalf("missing %q: %q", part, res.stdout)
		}
	}
}
