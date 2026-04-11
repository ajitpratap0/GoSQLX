// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package formatter

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestDialectRenderSelect_TopClause(t *testing.T) {
	// Parsed TOP clause should always render, even without a dialect.
	limit := 10
	stmt := &ast.SelectStatement{
		Top: &ast.TopClause{
			Count: &ast.LiteralValue{Value: 100, Type: "int"},
		},
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit, // Both TOP and LIMIT present
	}

	got := FormatStatement(stmt, ast.CompactStyle())
	if !strings.Contains(got, "TOP 100") {
		t.Errorf("expected TOP 100 in output, got: %s", got)
	}
	// LIMIT should also render since no dialect normalization removes it
	if !strings.Contains(got, "LIMIT 10") {
		t.Errorf("expected LIMIT 10 in output, got: %s", got)
	}
}

func TestDialectRenderSelect_TopPercent(t *testing.T) {
	stmt := &ast.SelectStatement{
		Top: &ast.TopClause{
			Count:     &ast.LiteralValue{Value: 10, Type: "int"},
			IsPercent: true,
			WithTies:  true,
		},
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "orders"}},
	}

	got := FormatStatement(stmt, ast.CompactStyle())
	if !strings.Contains(got, "TOP 10 PERCENT WITH TIES") {
		t.Errorf("expected TOP 10 PERCENT WITH TIES, got: %s", got)
	}
}

func TestDialectRenderSelect_LimitToTop(t *testing.T) {
	// SQL Server dialect should convert LIMIT to TOP
	limit := 50
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "sqlserver"
	got := FormatStatement(stmt, opts)

	if !strings.Contains(got, "TOP 50") {
		t.Errorf("sqlserver: expected TOP 50, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("sqlserver: should not contain LIMIT, got: %s", got)
	}
}

func TestDialectRenderSelect_LimitToFetch(t *testing.T) {
	// Oracle dialect should convert LIMIT to FETCH FIRST
	limit := 100
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "oracle"
	got := FormatStatement(stmt, opts)

	if !strings.Contains(got, "FETCH FIRST 100 ROWS ONLY") {
		t.Errorf("oracle: expected FETCH FIRST 100 ROWS ONLY, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("oracle: should not contain LIMIT, got: %s", got)
	}
}

func TestDialectRenderSelect_LimitOffsetOracle(t *testing.T) {
	// Oracle: LIMIT + OFFSET -> OFFSET n ROWS FETCH FIRST m ROWS ONLY
	limit := 10
	offset := 20
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
		Offset:  &offset,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "oracle"
	got := FormatStatement(stmt, opts)

	if !strings.Contains(got, "OFFSET 20 ROWS") {
		t.Errorf("oracle: expected OFFSET 20 ROWS, got: %s", got)
	}
	if !strings.Contains(got, "FETCH FIRST 10 ROWS ONLY") {
		t.Errorf("oracle: expected FETCH FIRST 10 ROWS ONLY, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("oracle: should not contain LIMIT, got: %s", got)
	}
}

func TestDialectRenderSelect_LimitOffsetSQLServer(t *testing.T) {
	// SQL Server with OFFSET uses OFFSET/FETCH NEXT syntax
	limit := 10
	offset := 20
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		OrderBy: []ast.OrderByExpression{
			{Expression: &ast.Identifier{Name: "id"}, Ascending: true},
		},
		Limit:  &limit,
		Offset: &offset,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "sqlserver"
	got := FormatStatement(stmt, opts)

	if !strings.Contains(got, "OFFSET 20 ROWS") {
		t.Errorf("sqlserver: expected OFFSET 20 ROWS, got: %s", got)
	}
	if !strings.Contains(got, "FETCH NEXT 10 ROWS ONLY") {
		t.Errorf("sqlserver: expected FETCH NEXT 10 ROWS ONLY, got: %s", got)
	}
	if strings.Contains(got, "TOP") {
		t.Errorf("sqlserver with offset: should not contain TOP, got: %s", got)
	}
	if strings.Contains(got, "LIMIT") {
		t.Errorf("sqlserver: should not contain LIMIT, got: %s", got)
	}
}

func TestDialectRenderSelect_PostgreSQLUnchanged(t *testing.T) {
	// PostgreSQL should keep LIMIT/OFFSET as-is
	limit := 10
	offset := 5
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "id"}, &ast.Identifier{Name: "name"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
		Offset:  &offset,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "postgresql"
	got := FormatStatement(stmt, opts)

	if !strings.Contains(got, "LIMIT 10") {
		t.Errorf("postgresql: expected LIMIT 10, got: %s", got)
	}
	if !strings.Contains(got, "OFFSET 5") {
		t.Errorf("postgresql: expected OFFSET 5, got: %s", got)
	}
}

func TestDialectRenderSelect_GenericPreservesExistingTop(t *testing.T) {
	// When no dialect is set, a parsed TopClause should still render.
	stmt := &ast.SelectStatement{
		Top: &ast.TopClause{
			Count: &ast.LiteralValue{Value: 5, Type: "int"},
		},
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "t"}},
	}

	got := FormatStatement(stmt, ast.CompactStyle())
	if !strings.Contains(got, "TOP 5") {
		t.Errorf("generic: expected TOP 5 in output, got: %s", got)
	}
}

func TestDialectRenderSelect_GenericPreservesExistingFetch(t *testing.T) {
	fetchVal := int64(25)
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "t"}},
		Fetch: &ast.FetchClause{
			FetchValue: &fetchVal,
			FetchType:  "FIRST",
		},
	}

	got := FormatStatement(stmt, ast.CompactStyle())
	if !strings.Contains(got, "FETCH FIRST 25 ROWS ONLY") {
		t.Errorf("generic: expected FETCH FIRST, got: %s", got)
	}
}

func TestDialectRenderSelect_KeywordCasing(t *testing.T) {
	limit := 10
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
	}

	opts := ast.FormatOptions{
		KeywordCase: ast.KeywordUpper,
		Dialect:     "sqlserver",
	}
	got := FormatStatement(stmt, opts)
	if !strings.Contains(got, "SELECT TOP 10") {
		t.Errorf("expected uppercase SELECT TOP, got: %s", got)
	}

	opts.KeywordCase = ast.KeywordLower
	got = FormatStatement(stmt, opts)
	if !strings.Contains(got, "select top 10") {
		t.Errorf("expected lowercase select top, got: %s", got)
	}
}

func TestDialectRenderSelect_OriginalASTNotMutated(t *testing.T) {
	// Verify that dialect normalization does not mutate the original AST.
	limit := 50
	stmt := &ast.SelectStatement{
		Columns: []ast.Expression{&ast.Identifier{Name: "*"}},
		From:    []ast.TableReference{{Name: "users"}},
		Limit:   &limit,
	}

	opts := ast.CompactStyle()
	opts.Dialect = "sqlserver"
	_ = FormatStatement(stmt, opts)

	// Original should still have Limit set and Top nil
	if stmt.Limit == nil {
		t.Error("original AST Limit was mutated to nil")
	}
	if stmt.Top != nil {
		t.Error("original AST Top was mutated (should remain nil)")
	}
}
