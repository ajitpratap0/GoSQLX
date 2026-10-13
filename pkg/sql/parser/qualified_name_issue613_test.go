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

package parser_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// issue613Templates are statements with a single %s slot holding an object
// name that is parsed by parseQualifiedName.
var issue613Templates = []string{
	"SELECT * FROM %s",
	"SELECT * FROM t JOIN %s ON 1 = 1",
	"INSERT INTO %s VALUES (1)",
	"UPDATE %s SET x = 1",
	"DELETE FROM %s",
	"CREATE TABLE %s (x INT)",
	"DROP TABLE %s",
	"TRUNCATE TABLE %s",
	"CREATE VIEW %s AS SELECT 1",
	"CREATE MATERIALIZED VIEW %s AS SELECT 1",
	"CREATE INDEX i ON %s (x)",
}

func issue613Render(t *testing.T, tree *ast.AST) string {
	t.Helper()
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	r, ok := tree.Statements[0].(interface{ SQL() string })
	if !ok {
		t.Fatalf("statement %T does not implement SQL()", tree.Statements[0])
	}
	return r.SQL()
}

func TestIssue613_QualifiedNameAccepted(t *testing.T) {
	names := []string{"t", "s.t", "d.s.t", "srv.d.s.t", "a.b.c.d.e"}
	for _, tmpl := range issue613Templates {
		for _, name := range names {
			sql := fmt.Sprintf(tmpl, name)
			t.Run(sql, func(t *testing.T) {
				tree, err := gosqlx.Parse(sql)
				if err != nil {
					t.Fatalf("Parse(%q) failed: %v", sql, err)
				}
				rendered := issue613Render(t, tree)
				if !strings.Contains(rendered, name) {
					t.Fatalf("rendered %q does not contain %q", rendered, name)
				}
				tree2, err := gosqlx.Parse(rendered)
				if err != nil {
					t.Fatalf("re-parse of %q failed: %v", rendered, err)
				}
				if again := issue613Render(t, tree2); again != rendered {
					t.Fatalf("round-trip mismatch: %q vs %q", rendered, again)
				}
			})
		}
	}

	for _, name := range names {
		tree, err := gosqlx.Parse("SELECT * FROM " + name)
		if err != nil {
			t.Fatalf("Parse failed for %q: %v", name, err)
		}
		sel, ok := tree.Statements[0].(*ast.SelectStatement)
		if !ok {
			t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
		}
		if len(sel.From) != 1 || sel.From[0].Name != name {
			t.Fatalf("FROM table name = %+v, want %q", sel.From, name)
		}
	}
}

func TestIssue613_QualifiedNameSQLServerFourPart(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT * FROM srv.db.dbo.t", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("ParseWithDialect failed: %v", err)
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
	if len(sel.From) != 1 || sel.From[0].Name != "srv.db.dbo.t" {
		t.Fatalf("FROM = %+v, want name srv.db.dbo.t", sel.From)
	}
}

func TestIssue613_QualifiedNamePartLimit(t *testing.T) {
	const name = "a.b.c.d.e.f"
	for _, tmpl := range issue613Templates {
		sql := fmt.Sprintf(tmpl, name)
		t.Run(sql, func(t *testing.T) {
			_, err := gosqlx.Parse(sql)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want part-limit error", sql)
			}
			if tmpl != "SELECT * FROM %s" {
				// Most callers (JOIN, DML, DDL) discard the E2004 and re-report
				// it as an E2002 "expected table name" error; the name is still
				// rejected. Only the FROM path passes the E2004 through.
				return
			}
			var pe *goerrors.Error
			if !errors.As(err, &pe) {
				t.Fatalf("error %T is not *errors.Error: %v", err, err)
			}
			if pe.Code != goerrors.ErrCodeInvalidSyntax {
				t.Fatalf("code = %s, want %s (%v)", pe.Code, goerrors.ErrCodeInvalidSyntax, err)
			}
			if !strings.Contains(err.Error(), "qualified name has more than 5 parts") {
				t.Fatalf("unexpected message: %v", err)
			}
		})
	}
}

func TestIssue613_LongQualifiedNameFailsFast(t *testing.T) {
	name := strings.TrimSuffix(strings.Repeat("a.", 50000), ".")
	_, err := gosqlx.Parse("SELECT * FROM " + name)
	if err == nil {
		t.Fatal("SELECT with long chain succeeded, want part-limit error")
	}
	if !strings.Contains(err.Error(), "more than 5 parts") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Other callers re-wrap the error, but the chain must still be rejected.
	for _, sql := range []string{
		"DROP TABLE " + name,
		"INSERT INTO " + name + " VALUES (1)",
		"SELECT * FROM t JOIN " + name + " ON 1 = 1",
	} {
		if _, err := gosqlx.Parse(sql); err == nil {
			t.Fatalf("Parse of %d-byte chain succeeded, want error", len(sql))
		}
	}
}

func TestIssue613_TrailingDotStillIdentifierError(t *testing.T) {
	for _, sql := range []string{"SELECT * FROM a.", "SELECT * FROM a.b.c."} {
		_, err := gosqlx.Parse(sql)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", sql)
		}
		if !strings.Contains(err.Error(), "identifier after .") {
			t.Fatalf("Parse(%q) error = %v, want 'identifier after .'", sql, err)
		}
	}
}

func BenchmarkIssue613_QualifiedTableName(b *testing.B) {
	cases := []struct {
		name string
		sql  string
	}{
		{"1part", "SELECT * FROM t"},
		{"3part", "SELECT * FROM db.schema.t"},
		{"5part", "SELECT * FROM a.b.c.d.e"},
		{"chain4KB", "SELECT * FROM " + strings.TrimSuffix(strings.Repeat("a.", 2048), ".")},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// The chain case is accepted before the fix and rejected after,
				// so the error is intentionally ignored.
				_, _ = gosqlx.Parse(tc.sql)
			}
		})
	}
}
