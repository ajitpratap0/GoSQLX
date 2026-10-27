// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package dialectaudit

import (
	"errors"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestEmpty(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want bool
	}{
		{"", true}, {" -- line\n /* block\n comment */ -- tail", true},
		{"/* outer /* inner */ rest */", false}, {"/* unfinished", false},
		{"/* comment */ SELECT 1", false}, {"'-- literal'", false}, {";", false},
	} {
		if got := Empty(tc.sql); got != tc.want {
			t.Errorf("Empty(%q) = %v, want %v", tc.sql, got, tc.want)
		}
	}
}

func TestCheckStages(t *testing.T) {
	for _, stage := range []string{"ok", "empty", "parse", "reparse", "idempotent", "drop", "panic"} {
		t.Run(stage, func(t *testing.T) {
			calls := 0
			parse := func(string, keywords.SQLDialect) (*ast.AST, error) {
				calls++
				if stage == "panic" {
					panic("test panic")
				}
				if stage == "parse" || stage == "reparse" && calls == 2 {
					return nil, errors.New("test error")
				}
				return nil, nil
			}
			formats := 0
			format := func(*ast.AST) string {
				formats++
				if stage == "idempotent" && formats == 2 {
					return "SELECT y"
				}
				return "SELECT x"
			}
			sql := "SELECT x"
			if stage == "drop" {
				sql = "SELECT x WHERE x"
			}
			if stage == "empty" {
				sql = "/* comments only */"
			}
			got := Check(sql, keywords.DialectPostgreSQL, parse, format)
			if got.Stage != stage {
				t.Fatalf("stage = %q, want %q: %s", got.Stage, stage, got.Error)
			}
			if stage == "empty" && calls != 0 {
				t.Fatal("parsed empty statement")
			}
		})
	}
}
