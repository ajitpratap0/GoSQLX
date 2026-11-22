// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"io"
	"testing"
)

func TestValidatorRejectsInvalidGOBatchCount(t *testing.T) {
	for _, count := range []string{"0", "999999999999999999999999999999", "1.5", "-1"} {
		t.Run(count, func(t *testing.T) {
			v := NewValidator(io.Discard, io.Discard, ValidatorOptions{Dialect: "sqlserver"})
			src := "SELECT 1\nGO " + count + "\nSELECT 2"
			result := v.ValidateInput("batch.sql", []byte(src))
			if result.InvalidFiles != 1 || result.ValidFiles != 0 {
				t.Fatalf("ValidateInput(%q): valid=%d invalid=%d; want invalid", src, result.ValidFiles, result.InvalidFiles)
			}
		})
	}
}

func TestValidatorAcceptsValidGOBatchCount(t *testing.T) {
	for _, directive := range []string{"GO", "GO 3", "GO 3 -- repeat", "GO 3 -- repeat\r"} {
		t.Run(directive, func(t *testing.T) {
			v := NewValidator(io.Discard, io.Discard, ValidatorOptions{Dialect: "sqlserver"})
			src := "SELECT 1\r\n" + directive + "\nSELECT 2"
			result := v.ValidateInput("batch.sql", []byte(src))
			if result.ValidFiles != 1 || result.InvalidFiles != 0 {
				t.Fatalf("ValidateInput(%q): valid=%d invalid=%d, error=%v; want valid", src, result.ValidFiles, result.InvalidFiles, result.Files[0].Error)
			}
		})
	}
}
