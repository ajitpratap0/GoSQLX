// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestRawClausePreservesLiteralSyntax(t *testing.T) {
	tests := []struct {
		name, sql string
		dialect   keywords.SQLDialect
		want      string
	}{
		{"postgres escape", `SELECT * FROM XMLTABLE('/rows/row' PASSING XMLPARSE(DOCUMENT E'<rows/>') COLUMNS id int PATH 'id')`, keywords.DialectPostgreSQL, `DOCUMENT E'<rows/>'`},
		{"postgres dollar", `SELECT * FROM XMLTABLE('/rows/row' PASSING XMLPARSE(DOCUMENT $$<rows/>$$) COLUMNS id int PATH 'id')`, keywords.DialectPostgreSQL, `DOCUMENT $$<rows/>$$`},
		{"postgres empty", `SELECT * FROM XMLTABLE('/rows/row' PASSING XMLPARSE(DOCUMENT E'') COLUMNS id int PATH '')`, keywords.DialectPostgreSQL, `DOCUMENT E''`},
		{"mysql national", `SELECT * FROM JSON_TABLE(doc, '$[*]' COLUMNS (name VARCHAR(50) PATH '$.name' DEFAULT N'unknown' ON EMPTY)) jt`, keywords.DialectMySQL, `DEFAULT N'unknown' ON EMPTY`},
		{"mysql empty national", `SELECT * FROM JSON_TABLE(doc, '$[*]' COLUMNS (name VARCHAR(50) PATH '$.name' DEFAULT N'' ON EMPTY)) jt`, keywords.DialectMySQL, `DEFAULT N'' ON EMPTY`},
		{"mysql charset adjacent", `SELECT * FROM JSON_TABLE(doc, '$[*]' COLUMNS (name VARCHAR(50) PATH '$.name' DEFAULT _utf8mb4'text' ON EMPTY)) jt`, keywords.DialectMySQL, `DEFAULT _utf8mb4'text' ON EMPTY`},
		{"oracle q quote", `SELECT * FROM JSON_TABLE(doc, '$' COLUMNS (name VARCHAR2(50) PATH '$.name' DEFAULT q'[it's text]' ON EMPTY)) jt`, keywords.DialectOracle, `DEFAULT 'it''s text' ON EMPTY`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			got := tree.SQL()
			if !strings.Contains(got, tc.want) {
				t.Fatalf("SQL() = %q; want fragment %q", got, tc.want)
			}
			reparsed, err := ParseWithDialect(got, tc.dialect)
			if err != nil {
				t.Fatalf("reparse %q: %v", got, err)
			}
			if again := reparsed.SQL(); again != got {
				t.Errorf("literal rendering not idempotent:\n%s\n%s", got, again)
			}
			ast.ReleaseAST(reparsed)
		})
	}
}

func TestRawClauseRejectsBackslashLiteralItCannotSafelyRender(t *testing.T) {
	_, err := ParseWithDialect(`SELECT * FROM XMLTABLE('/rows/row' PASSING XMLPARSE(DOCUMENT E'back\\slash') COLUMNS id int PATH 'id')`, keywords.DialectPostgreSQL)
	if err == nil {
		t.Fatal("expected unsupported raw clause with backslash to be rejected")
	}
}
