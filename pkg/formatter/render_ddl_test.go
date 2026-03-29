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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormat_CreateSequence verifies that CREATE SEQUENCE statements are rendered
// by the dedicated formatter arm rather than falling back to stmtSQL/TokenLiteral.
func TestFormat_CreateSequence(t *testing.T) {
	sql := "CREATE SEQUENCE user_id_seq START WITH 1 INCREMENT BY 1"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("expected at least one statement")
	}
	stmt, ok := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !ok {
		t.Fatalf("expected *ast.CreateSequenceStatement, got %T", tree.Statements[0])
	}

	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "CREATE") {
		t.Errorf("expected CREATE in output, got: %q", result)
	}
	if !strings.Contains(upper, "SEQUENCE") {
		t.Errorf("expected SEQUENCE in output, got: %q", result)
	}
	if !strings.Contains(result, "user_id_seq") {
		t.Errorf("expected sequence name in output, got: %q", result)
	}
	if !strings.Contains(upper, "START WITH") {
		t.Errorf("expected START WITH in output, got: %q", result)
	}
}

// TestFormat_CreateSequence_IfNotExists verifies IF NOT EXISTS is rendered.
func TestFormat_CreateSequence_IfNotExists(t *testing.T) {
	sql := "CREATE SEQUENCE IF NOT EXISTS s2 START WITH 10"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.CreateSequenceStatement)
	if !ok {
		t.Fatalf("expected *ast.CreateSequenceStatement, got %T", tree.Statements[0])
	}
	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "IF NOT EXISTS") {
		t.Errorf("expected IF NOT EXISTS in output, got: %q", result)
	}
}

// TestFormat_AlterSequence verifies ALTER SEQUENCE statements are formatted correctly.
func TestFormat_AlterSequence(t *testing.T) {
	sql := "ALTER SEQUENCE user_id_seq RESTART WITH 100"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.AlterSequenceStatement)
	if !ok {
		t.Fatalf("expected *ast.AlterSequenceStatement, got %T", tree.Statements[0])
	}
	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "ALTER") {
		t.Errorf("expected ALTER in output, got: %q", result)
	}
	if !strings.Contains(upper, "SEQUENCE") {
		t.Errorf("expected SEQUENCE in output, got: %q", result)
	}
	if !strings.Contains(result, "user_id_seq") {
		t.Errorf("expected sequence name in output, got: %q", result)
	}
}

// TestFormat_DropSequence verifies DROP SEQUENCE statements are formatted correctly.
func TestFormat_DropSequence(t *testing.T) {
	sql := "DROP SEQUENCE IF EXISTS user_id_seq"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.DropSequenceStatement)
	if !ok {
		t.Fatalf("expected *ast.DropSequenceStatement, got %T", tree.Statements[0])
	}
	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "DROP") {
		t.Errorf("expected DROP in output, got: %q", result)
	}
	if !strings.Contains(upper, "SEQUENCE") {
		t.Errorf("expected SEQUENCE in output, got: %q", result)
	}
	if !strings.Contains(upper, "IF EXISTS") {
		t.Errorf("expected IF EXISTS in output, got: %q", result)
	}
	if !strings.Contains(result, "user_id_seq") {
		t.Errorf("expected sequence name in output, got: %q", result)
	}
}

// TestFormat_ShowStatement verifies SHOW statements are formatted correctly.
func TestFormat_ShowStatement(t *testing.T) {
	sql := "SHOW TABLES"
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.ShowStatement)
	if !ok {
		t.Fatalf("expected *ast.ShowStatement, got %T", tree.Statements[0])
	}
	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "SHOW") {
		t.Errorf("expected SHOW in output, got: %q", result)
	}
	if !strings.Contains(upper, "TABLES") {
		t.Errorf("expected TABLES in output, got: %q", result)
	}
}

// TestFormat_DescribeStatement verifies DESCRIBE statements are formatted correctly.
func TestFormat_DescribeStatement(t *testing.T) {
	sql := "DESCRIBE users"
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt, ok := tree.Statements[0].(*ast.DescribeStatement)
	if !ok {
		t.Fatalf("expected *ast.DescribeStatement, got %T", tree.Statements[0])
	}
	opts := ast.FormatOptions{}
	result := formatter.FormatStatement(stmt, opts)
	upper := strings.ToUpper(result)
	if !strings.Contains(upper, "DESCRIBE") {
		t.Errorf("expected DESCRIBE in output, got: %q", result)
	}
	if !strings.Contains(result, "users") {
		t.Errorf("expected table name 'users' in output, got: %q", result)
	}
}

// TestFormat_DDL_KeywordCase verifies that DDL formatter respects keyword casing options.
func TestFormat_DDL_KeywordCase(t *testing.T) {
	sql := "DROP SEQUENCE myseq"
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectMariaDB)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	stmt := tree.Statements[0].(*ast.DropSequenceStatement)

	upperOpts := ast.FormatOptions{KeywordCase: ast.KeywordUpper}
	result := formatter.FormatStatement(stmt, upperOpts)
	if !strings.Contains(result, "DROP SEQUENCE") {
		t.Errorf("expected uppercase keywords, got: %q", result)
	}

	lowerOpts := ast.FormatOptions{KeywordCase: ast.KeywordLower}
	result = formatter.FormatStatement(stmt, lowerOpts)
	if !strings.Contains(result, "drop sequence") {
		t.Errorf("expected lowercase keywords, got: %q", result)
	}
}
