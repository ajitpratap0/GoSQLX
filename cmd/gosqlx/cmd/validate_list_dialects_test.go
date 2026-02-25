// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestValidateListDialects(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"validate", "--list-dialects"})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("--list-dialects should not error, got: %v", err)
	}

	output := buf.String()
	for _, d := range keywords.AllDialects() {
		if !strings.Contains(output, string(d)) {
			t.Errorf("expected dialect %q in output, got: %s", d, output)
		}
	}
}
