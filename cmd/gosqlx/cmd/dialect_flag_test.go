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

// Package cmd - dialect_flag_test.go
// Tests for the shared --dialect helpers and dialect threading through the
// parse, format, and analyze commands.

package cmd

import (
	"bytes"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// mysqlLimitQuery uses MySQL's `LIMIT offset, count` syntax, which fails to
// parse under the default (PostgreSQL) dialect but succeeds under MySQL. It is a
// convenient probe for verifying that a dialect is threaded through.
const mysqlLimitQuery = "SELECT a, b FROM t LIMIT 10, 20"

func TestValidateDialectName(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		wantErr bool
	}{
		{"empty is allowed (default)", "", false},
		{"mysql", "mysql", false},
		{"sqlite", "sqlite", false},
		{"mariadb", "mariadb", false},
		{"postgresql", "postgresql", false},
		{"unknown", "bogus", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDialectName(tt.dialect)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDialectName(%q) error = %v, wantErr %v", tt.dialect, err, tt.wantErr)
			}
		})
	}
}

func TestTokenizerForDialect(t *testing.T) {
	// Default: pooled tokenizer, PostgreSQL dialect.
	tkz, release, err := tokenizerForDialect("")
	if err != nil {
		t.Fatalf("tokenizerForDialect(\"\") error = %v", err)
	}
	if tkz.Dialect() != keywords.DialectPostgreSQL {
		t.Errorf("default dialect = %q, want %q", tkz.Dialect(), keywords.DialectPostgreSQL)
	}
	release()

	// Explicit dialect: fresh tokenizer configured for MySQL.
	tkz, release, err = tokenizerForDialect("mysql")
	if err != nil {
		t.Fatalf("tokenizerForDialect(\"mysql\") error = %v", err)
	}
	defer release()
	if tkz.Dialect() != keywords.DialectMySQL {
		t.Errorf("dialect = %q, want %q", tkz.Dialect(), keywords.DialectMySQL)
	}
}

func TestParserForDialect(t *testing.T) {
	if got := parserForDialect("mysql").Dialect(); got != "mysql" {
		t.Errorf("parserForDialect(\"mysql\").Dialect() = %q, want %q", got, "mysql")
	}
}

func TestParseCommand_Dialect(t *testing.T) {
	var out, errBuf bytes.Buffer

	// Default dialect: MySQL LIMIT offset,count must NOT parse.
	def := NewParser(&out, &errBuf, CLIParserOptions{Format: "table"})
	if res, err := def.Parse(mysqlLimitQuery); err == nil {
		if res.AST != nil {
			ast.ReleaseAST(res.AST)
		}
		t.Fatal("expected parse failure under default dialect, got success")
	}

	// MySQL dialect: must parse.
	my := NewParser(&out, &errBuf, CLIParserOptions{Format: "table", Dialect: "mysql"})
	res, err := my.Parse(mysqlLimitQuery)
	if err != nil {
		t.Fatalf("expected success under mysql dialect, got error: %v", err)
	}
	if res.AST == nil {
		t.Fatal("expected non-nil AST under mysql dialect")
	}
	ast.ReleaseAST(res.AST)
}

func TestFormatCommand_Dialect(t *testing.T) {
	var out, errBuf bytes.Buffer
	f := NewFormatter(&out, &errBuf, CLIFormatterOptions{IndentSize: 2, Dialect: "mysql"})
	if _, err := f.formatSQL(mysqlLimitQuery); err != nil {
		t.Fatalf("formatSQL under mysql dialect failed: %v", err)
	}

	def := NewFormatter(&out, &errBuf, CLIFormatterOptions{IndentSize: 2})
	if _, err := def.formatSQL(mysqlLimitQuery); err == nil {
		t.Fatal("expected formatSQL failure under default dialect, got success")
	}
}

func TestAnalyzeCommand_Dialect(t *testing.T) {
	var out, errBuf bytes.Buffer
	a := NewAnalyzer(&out, &errBuf, CLIAnalyzerOptions{Format: "table", Dialect: "mysql"})
	res, err := a.Analyze(mysqlLimitQuery)
	if err != nil {
		t.Fatalf("Analyze under mysql dialect failed: %v", err)
	}
	if res.Report == nil {
		t.Fatal("expected non-nil analysis report under mysql dialect")
	}

	def := NewAnalyzer(&out, &errBuf, CLIAnalyzerOptions{Format: "table"})
	if _, err := def.Analyze(mysqlLimitQuery); err == nil {
		t.Fatal("expected Analyze failure under default dialect, got success")
	}
}
