// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormatSemicolonComments(t *testing.T) {
	tests := []struct {
		name        string
		dialect     keywords.SQLDialect
		sql         string
		wantDefault string
		generic     bool
	}{
		{"postgres do", keywords.DialectPostgreSQL, "-- c\nDO $$ BEGIN END $$; SELECT 1", "-- c\nDO $$ BEGIN END $$;\nSELECT 1", true},
		{"oracle block", keywords.DialectOracle, "-- c\nBEGIN NULL; END;\nSELECT 1 FROM dual", "-- c\nBEGIN NULL; END;\nSELECT 1\nFROM dual", false},
		{"postgres function", keywords.DialectPostgreSQL, "-- c\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql; SELECT 1", "-- c\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;\nSELECT 1", true},
		{"between statements", keywords.DialectPostgreSQL, "DO $$ BEGIN END $$;\n-- c\nSELECT 1", "DO $$ BEGIN END $$;\n-- c\nSELECT 1", true},
		{"trailing comment", keywords.DialectPostgreSQL, "DO $$ BEGIN END $$; -- c\nSELECT 1", "DO $$ BEGIN END $$; -- c\nSELECT 1", true},
		{"select pair", keywords.DialectPostgreSQL, "-- c\nSELECT 1; SELECT 2", "-- c\nSELECT 1;\nSELECT 2", true},
		{"batch separator", keywords.DialectSQLServer, "-- c\nSELECT 1\nGO\nSELECT 2", "-- c\nSELECT 1;\nGO\nSELECT 2", false},
	}
	stripComment := func(sql string) string {
		lines := strings.Split(sql, "\n")
		parts := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(strings.SplitN(line, "-- c", 2)[0])
			if line != "" {
				parts = append(parts, line)
			}
		}
		return strings.Join(parts, "\n")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apis := []string{"FormatWithDialect"}
			if tt.generic {
				apis = append(apis, "Format")
			}
			for _, api := range apis {
				t.Run(api, func(t *testing.T) {
					format := func(sql string, opts FormatOptions) (string, error) {
						if api == "Format" {
							return Format(sql, opts)
						}
						return FormatWithDialect(sql, opts, tt.dialect)
					}
					opts := DefaultFormatOptions()
					got, err := format(tt.sql, opts)
					if err != nil {
						t.Fatalf("default format: %v", err)
					}
					if got != tt.wantDefault {
						t.Fatalf("default format = %q, want baseline %q", got, tt.wantDefault)
					}
					opts.AddSemicolon = true
					got, err = format(tt.sql, opts)
					if err != nil {
						t.Fatalf("format with semicolons: %v", err)
					}
					plain, err := format(stripComment(tt.sql), opts)
					if err != nil {
						t.Fatalf("format without comments: %v", err)
					}
					if stripped := stripComment(got); stripped != plain {
						t.Errorf("formatted comment-free SQL = %q, want %q", stripped, plain)
					}
					if !strings.Contains(got, "-- c") || strings.Contains(got, ";;") || strings.Contains(got, "GO;") {
						t.Errorf("unexpected comments or terminators: %q", got)
					}
					input, err := ParseWithDialect(tt.sql, tt.dialect)
					if err != nil {
						t.Fatalf("parse input: %v", err)
					}
					defer ast.ReleaseAST(input)
					output, err := ParseWithDialect(got, tt.dialect)
					if err != nil {
						t.Fatalf("reparse formatted SQL %q: %v", got, err)
					}
					defer ast.ReleaseAST(output)
					if len(output.Statements) != len(input.Statements) {
						t.Errorf("statement count = %d, want %d; output %q", len(output.Statements), len(input.Statements), got)
					}
				})
			}
		})
	}
}
