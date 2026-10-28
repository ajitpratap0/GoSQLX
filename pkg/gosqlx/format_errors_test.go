// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"errors"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormatRejectsNumericTrailingJunk(t *testing.T) {
	for _, sql := range []string{"SELECT 1x", "SELECT 1x -- keep comment"} {
		t.Run(sql, func(t *testing.T) {
			for _, dialect := range []keywords.SQLDialect{"", keywords.DialectPostgreSQL} {
				out, err := FormatWithDialect(sql, DefaultFormatOptions(), dialect)
				if !errors.Is(err, ErrTokenize) || out != "" {
					t.Fatalf("FormatWithDialect(%q, %q) = %q, %v; want tokenize error", sql, dialect, out, err)
				}
			}
			out, err := Format(sql, DefaultFormatOptions())
			if !errors.Is(err, ErrTokenize) || out != "" {
				t.Fatalf("Format = %q, %v; want tokenize error", out, err)
			}
		})
	}
}
