// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseSingleAlter parses sql and returns its only statement, which must be an
// *ast.AlterStatement.
func parseSingleAlter(t *testing.T, sql string) *ast.AlterStatement {
	t.Helper()
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("parse %q: %v", sql, err)
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("parse %q: expected 1 statement, got %d", sql, len(tree.Statements))
	}
	stmt, ok := tree.Statements[0].(*ast.AlterStatement)
	if !ok {
		t.Fatalf("parse %q: expected *ast.AlterStatement, got %T", sql, tree.Statements[0])
	}
	return stmt
}

// TestFormatStatement_AlterTable verifies that ALTER TABLE operations parsed
// into *ast.AlterStatement render in full (previously they rendered as a bare
// "ALTER") and that the rendering re-parses to the same statement (#599).
func TestFormatStatement_AlterTable(t *testing.T) {
	compactUpper := ast.CompactStyle()
	compactUpper.KeywordCase = ast.KeywordUpper

	tests := []struct {
		name     string
		in       string
		compact  string
		readable string
	}{
		{
			name:     "add column with constraints",
			in:       "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0",
			compact:  "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0",
			readable: "ALTER TABLE t\nADD COLUMN c INT NOT NULL DEFAULT 0;",
		},
		{
			name:     "add named constraint",
			in:       "ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (id)",
			compact:  "ALTER TABLE t ADD CONSTRAINT pk PRIMARY KEY (id)",
			readable: "ALTER TABLE t\nADD CONSTRAINT pk PRIMARY KEY (id);",
		},
		{
			name:     "add unnamed constraint",
			in:       "ALTER TABLE t ADD CONSTRAINT UNIQUE (a, b)",
			compact:  "ALTER TABLE t ADD CONSTRAINT UNIQUE (a, b)",
			readable: "ALTER TABLE t\nADD CONSTRAINT UNIQUE (a, b);",
		},
		{
			name:     "add foreign key",
			in:       "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) ON DELETE CASCADE",
			compact:  "ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) ON DELETE CASCADE",
			readable: "ALTER TABLE t\nADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u (id) ON DELETE CASCADE;",
		},
		{
			name:     "drop column",
			in:       "ALTER TABLE t DROP COLUMN c",
			compact:  "ALTER TABLE t DROP COLUMN c",
			readable: "ALTER TABLE t\nDROP COLUMN c;",
		},
		{
			name:     "drop column cascade",
			in:       "ALTER TABLE t DROP COLUMN c CASCADE",
			compact:  "ALTER TABLE t DROP COLUMN c CASCADE",
			readable: "ALTER TABLE t\nDROP COLUMN c CASCADE;",
		},
		{
			name:     "drop constraint",
			in:       "ALTER TABLE t DROP CONSTRAINT pk",
			compact:  "ALTER TABLE t DROP CONSTRAINT pk",
			readable: "ALTER TABLE t\nDROP CONSTRAINT pk;",
		},
		{
			name:     "drop constraint cascade",
			in:       "ALTER TABLE t DROP CONSTRAINT pk CASCADE",
			compact:  "ALTER TABLE t DROP CONSTRAINT pk CASCADE",
			readable: "ALTER TABLE t\nDROP CONSTRAINT pk CASCADE;",
		},
		{
			name:     "rename table",
			in:       "ALTER TABLE t RENAME TO u",
			compact:  "ALTER TABLE t RENAME TO u",
			readable: "ALTER TABLE t\nRENAME TO u;",
		},
		{
			name:     "rename column",
			in:       "ALTER TABLE t RENAME COLUMN a TO b",
			compact:  "ALTER TABLE t RENAME COLUMN a TO b",
			readable: "ALTER TABLE t\nRENAME COLUMN a TO b;",
		},
		{
			name:     "alter column type",
			in:       "ALTER TABLE t ALTER COLUMN c TYPE BIGINT",
			compact:  "ALTER TABLE t ALTER COLUMN c TYPE BIGINT",
			readable: "ALTER TABLE t\nALTER COLUMN c TYPE BIGINT;",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmt := parseSingleAlter(t, tc.in)

			compact := formatter.FormatStatement(stmt, compactUpper)
			if compact != tc.compact {
				t.Errorf("compact:\n got: %q\nwant: %q", compact, tc.compact)
			}
			if got := formatter.FormatStatement(stmt, ast.ReadableStyle()); got != tc.readable {
				t.Errorf("readable:\n got: %q\nwant: %q", got, tc.readable)
			}

			// AlterStatement has no SQL(), so compare renderings of the
			// original and the re-parsed statement.
			reparsed := parseSingleAlter(t, compact)
			if again := formatter.FormatStatement(reparsed, compactUpper); again != compact {
				t.Errorf("render is not stable across re-parse:\nfirst:  %q\nsecond: %q", compact, again)
			}
		})
	}
}

// TestFormatStatement_AlterTable_LowerKeywords checks that keyword casing is
// applied to the ALTER TABLE keywords while identifiers and types are kept.
func TestFormatStatement_AlterTable_LowerKeywords(t *testing.T) {
	stmt := parseSingleAlter(t, "ALTER TABLE t ADD COLUMN c INT")
	opts := ast.CompactStyle()
	opts.KeywordCase = ast.KeywordLower
	const want = "alter table t add column c INT"
	got := formatter.FormatStatement(stmt, opts)
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	reparsed := parseSingleAlter(t, got)
	if again := formatter.FormatStatement(reparsed, opts); again != got {
		t.Fatalf("render is not stable across re-parse:\nfirst:  %q\nsecond: %q", got, again)
	}
}

// TestFormatStatement_AlterNonTableUnchanged checks that non-table ALTER
// statements keep their previous rendering.
func TestFormatStatement_AlterNonTableUnchanged(t *testing.T) {
	stmt := &ast.AlterStatement{Type: ast.AlterTypeRole, Name: "r"}
	if got := formatter.FormatStatement(stmt, ast.CompactStyle()); got != stmt.TokenLiteral() {
		t.Fatalf("got %q, want token literal %q", got, stmt.TokenLiteral())
	}
}
