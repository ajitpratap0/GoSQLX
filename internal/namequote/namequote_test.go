// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package namequote_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/namequote"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestMustStayQuoted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dialect keywords.SQLDialect
		want    bool
	}{
		{"KEY", keywords.DialectMySQL, true},
		{"QUALIFY", keywords.DialectMySQL, false},
		{"user", keywords.DialectMySQL, true},
		{"top", keywords.DialectSQLServer, true},
		{"TOP", "", true},
		{"top", "", false},
		{"tOp", keywords.DialectSQLServer, true},
		{"top", "mssql", true},
		{"top", "tsql", true},
		{"top", "sql_server", true},
		{"top", "sql-server", true},
		{"top", "SQLSERVER", true},
		{"top", keywords.DialectMySQL, false},
		{"Users", "", true},
		{"Users", keywords.DialectMySQL, false},
		{"USERS", keywords.DialectSnowflake, false},
		{"users", keywords.DialectSnowflake, true},
		{"my-db", keywords.DialectMySQL, true},
		{"", keywords.DialectMySQL, true},
	} {
		t.Run(string(tc.dialect)+"/"+tc.name, func(t *testing.T) {
			if got := namequote.MustStayQuoted(tc.name, tc.dialect); got != tc.want {
				t.Errorf("MustStayQuoted(%q, %q) = %v, want %v", tc.name, tc.dialect, got, tc.want)
			}
		})
	}
}

func TestFold(t *testing.T) {
	for _, tc := range []struct {
		dialect keywords.SQLDialect
		want    ast.IdentifierCaseFolding
	}{
		{"", ast.FoldLower},
		{keywords.DialectGeneric, ast.FoldLower},
		{keywords.DialectPostgreSQL, ast.FoldLower},
		{keywords.DialectRedshift, ast.FoldLower},
		{keywords.DialectOracle, ast.FoldUpper},
		{keywords.DialectSnowflake, ast.FoldUpper},
		{keywords.DialectMySQL, ast.FoldNone},
		{keywords.DialectMariaDB, ast.FoldNone},
		{keywords.DialectSQLServer, ast.FoldNone},
		{keywords.DialectSQLite, ast.FoldNone},
		{keywords.DialectClickHouse, ast.FoldNone},
		{keywords.DialectBigQuery, ast.FoldNone},
	} {
		t.Run(string(tc.dialect), func(t *testing.T) {
			if got := namequote.Fold(tc.dialect); got != tc.want {
				t.Errorf("Fold(%q) = %v, want %v", tc.dialect, got, tc.want)
			}
		})
	}
}
