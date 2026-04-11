// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package transform

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestFormatSQLWithDialect_PostgreSQL(t *testing.T) {
	tree, err := ParseSQL("SELECT * FROM users u")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, SetLimit(100)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got := FormatSQLWithDialect(stmt, keywords.DialectPostgreSQL)
	if !strings.Contains(got, "LIMIT 100") {
		t.Errorf("postgresql: expected LIMIT 100, got: %s", got)
	}
}

func TestFormatSQLWithDialect_SQLServer(t *testing.T) {
	tree, err := ParseSQL("SELECT * FROM users u")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, SetLimit(100)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got := FormatSQLWithDialect(stmt, keywords.DialectSQLServer)
	if !strings.Contains(got, "TOP 100") {
		t.Errorf("sqlserver: expected TOP 100, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("sqlserver: should not contain LIMIT, got: %s", got)
	}
}

func TestFormatSQLWithDialect_Oracle(t *testing.T) {
	tree, err := ParseSQL("SELECT * FROM users u")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, SetLimit(100)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got := FormatSQLWithDialect(stmt, keywords.DialectOracle)
	if !strings.Contains(got, "FETCH FIRST 100 ROWS ONLY") {
		t.Errorf("oracle: expected FETCH FIRST 100 ROWS ONLY, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("oracle: should not contain LIMIT, got: %s", got)
	}
}

func TestFormatSQLWithDialect_EmptyDialect(t *testing.T) {
	tree, err := ParseSQL("SELECT * FROM users")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, SetLimit(10)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Empty dialect = generic = LIMIT
	got := FormatSQLWithDialect(stmt, "")
	if !strings.Contains(got, "LIMIT 10") {
		t.Errorf("generic: expected LIMIT 10, got: %s", got)
	}
}

func TestFormatSQLWithDialect_Pagination(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		limit   int
		offset  int
		want    []string
		reject  []string
	}{
		{
			name:    "postgresql pagination",
			dialect: keywords.DialectPostgreSQL,
			limit:   10,
			offset:  20,
			want:    []string{"LIMIT 10", "OFFSET 20"},
		},
		{
			name:    "oracle pagination",
			dialect: keywords.DialectOracle,
			limit:   10,
			offset:  20,
			want:    []string{"OFFSET 20 ROWS", "FETCH FIRST 10 ROWS ONLY"},
			reject:  []string{"LIMIT"},
		},
		{
			name:    "mysql pagination",
			dialect: keywords.DialectMySQL,
			limit:   10,
			offset:  20,
			want:    []string{"LIMIT 10", "OFFSET 20"},
		},
		{
			name:    "snowflake pagination",
			dialect: keywords.DialectSnowflake,
			limit:   10,
			offset:  20,
			want:    []string{"LIMIT 10", "OFFSET 20"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := ParseSQL("SELECT * FROM users ORDER BY id")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			stmt := tree.Statements[0]
			if err := Apply(stmt, SetLimit(tt.limit), SetOffset(tt.offset)); err != nil {
				t.Fatalf("apply: %v", err)
			}

			got := FormatSQLWithDialect(stmt, tt.dialect)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("expected %q in output, got: %s", w, got)
				}
			}
			for _, r := range tt.reject {
				if strings.Contains(got, r) {
					t.Errorf("should not contain %q, got: %s", r, got)
				}
			}
		})
	}
}

func TestParseSQLWithDialect_SQLServerTop(t *testing.T) {
	tree, err := ParseSQLWithDialect("SELECT TOP 10 * FROM users", keywords.DialectSQLServer)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(tree.Statements) == 0 {
		t.Fatal("no statements parsed")
	}

	got := FormatSQLWithDialect(tree.Statements[0], keywords.DialectSQLServer)
	if !strings.Contains(got, "TOP 10") {
		t.Errorf("expected TOP 10 preserved, got: %s", got)
	}
}

func TestFormatSQLWithDialect_SQLServerOffset(t *testing.T) {
	tree, err := ParseSQL("SELECT * FROM users ORDER BY id")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	stmt := tree.Statements[0]
	if err := Apply(stmt, SetLimit(10), SetOffset(20)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	got := FormatSQLWithDialect(stmt, keywords.DialectSQLServer)
	if !strings.Contains(got, "OFFSET 20 ROWS") {
		t.Errorf("sqlserver: expected OFFSET 20 ROWS, got: %s", got)
	}
	if !strings.Contains(got, "FETCH NEXT 10 ROWS ONLY") {
		t.Errorf("sqlserver: expected FETCH NEXT 10 ROWS ONLY, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("sqlserver: should not contain LIMIT, got: %s", got)
	}
}
