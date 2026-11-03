//go:build !race

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

package main

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

var allocationResultSink string
var allocationParseSink ParseResult

func TestCBindingAllocations(t *testing.T) {
	sql := benchQueries[1].sql
	for _, tc := range []struct {
		name               string
		current, reference func() string
		reduction          float64
	}{
		{"parse", func() string { return callLegacyRaw(exportParse, &sql) }, func() string { return legacyParseRawForTest(sql) }, 4},
		{"lint", func() string { return lintRaw(sql, nil) }, func() string { return legacyLintRawForTest(sql) }, 10},
		{"extract_metadata", func() string { return callLegacyRaw(exportExtractMetadata, &sql) }, func() string { return legacyMetadataRawForTest(sql) }, 1},
		{"extract_tables", func() string { return callLegacyRaw(exportExtractTables, &sql) }, func() string { return legacyTablesRawForTest(sql) }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				allocationResultSink = tc.reference()
				allocationResultSink = tc.current()
			}
			reference := testing.AllocsPerRun(200, func() { allocationResultSink = tc.reference() })
			current := testing.AllocsPerRun(200, func() { allocationResultSink = tc.current() })
			t.Logf("current %.0f, reference %.0f allocs/op, reduction %.0f", current, reference, reference-current)
			if current > reference-tc.reduction {
				t.Errorf("%.0f allocs/op exceeds reference %.0f minus required %.0f", current, reference, tc.reduction)
			}
		})
	}
}

// parseResultWithoutRelease preserves the previous success path specifically
// to verify AST reuse, independently of JSON and statement-slice savings.
func parseResultWithoutRelease(sql string) ParseResult {
	tree, err := parseFor(sql, "")
	if err != nil {
		return ParseResult{Error: err.Error()}
	}
	types := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		if _, ok := stmt.(*ast.BatchSeparator); ok {
			continue
		}
		types = append(types, statementTypeName(stmt))
	}
	return ParseResult{Success: true, StmtCount: len(types), StmtTypes: types}
}

func TestCBindingAllocASTRelease(t *testing.T) {
	sql := benchQueries[1].sql
	for i := 0; i < 20; i++ {
		allocationParseSink = parseResultFor(sql, "")
	}
	withRelease := testing.AllocsPerRun(200, func() { allocationParseSink = parseResultFor(sql, "") })
	withoutRelease := testing.AllocsPerRun(200, func() { allocationParseSink = parseResultWithoutRelease(sql) })
	t.Logf("released %.0f, unreleased %.0f allocs/op", withRelease, withoutRelease)
	if withRelease > withoutRelease-1 {
		t.Errorf("AST release must save at least one allocation: released %.0f, unreleased %.0f", withRelease, withoutRelease)
	}
}

// extractWithoutRelease preserves the success path without releasing the AST.
func extractWithoutRelease(sql, dialect, key string, extract func(*ast.AST) []string) any {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		return extractErrorResult{Error: err.Error(), ErrorCode: errorCodeFor(err)}
	}

	items := extract(tree)
	if items == nil {
		items = []string{}
	}
	switch key {
	case "tables":
		return extractTablesResult{Tables: items}
	case "columns":
		return extractColumnsResult{Columns: items}
	case "functions":
		return extractFunctionsResult{Functions: items}
	default:
		// Unreachable: callers supply one of the three export keys above.
		panic("unknown extract result key: " + key)
	}
}

// metadataWithoutRelease preserves the success path without releasing the AST.
func metadataWithoutRelease(sql, dialect string) MetadataResult {
	tree, err := parseFor(sql, dialect)
	if err != nil {
		return MetadataResult{Error: err.Error(), ErrorCode: errorCodeFor(err)}
	}

	metadata := gosqlx.ExtractMetadata(tree)

	tablesQualified := make([]QualifiedNameJSON, 0, len(metadata.TablesQualified))
	for _, tq := range metadata.TablesQualified {
		tablesQualified = append(tablesQualified, QualifiedNameJSON{
			Schema: tq.Schema,
			Table:  tq.Table,
			Name:   tq.Name,
		})
	}

	columnsQualified := make([]QualifiedNameJSON, 0, len(metadata.ColumnsQualified))
	for _, cq := range metadata.ColumnsQualified {
		columnsQualified = append(columnsQualified, QualifiedNameJSON{
			Schema: cq.Schema,
			Table:  cq.Table,
			Name:   cq.Name,
		})
	}

	// Ensure non-nil slices for consistent JSON output.
	tables := metadata.Tables
	if tables == nil {
		tables = []string{}
	}
	columns := metadata.Columns
	if columns == nil {
		columns = []string{}
	}
	functions := metadata.Functions
	if functions == nil {
		functions = []string{}
	}

	return MetadataResult{
		Tables:           tables,
		TablesQualified:  tablesQualified,
		Columns:          columns,
		ColumnsQualified: columnsQualified,
		Functions:        functions,
	}
}

var allocationMetadataSink MetadataResult
var allocationExtractSink any

func TestCBindingExtractASTRelease(t *testing.T) {
	sql := benchQueries[1].sql
	for _, tc := range []struct {
		name                 string
		released, unreleased func()
	}{
		{"metadata", func() { allocationMetadataSink = metadataFor(sql, "") }, func() { allocationMetadataSink = metadataWithoutRelease(sql, "") }},
		{"tables", func() { allocationExtractSink = extractListFor(sql, "", "tables", gosqlx.ExtractTables) }, func() { allocationExtractSink = extractWithoutRelease(sql, "", "tables", gosqlx.ExtractTables) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				tc.released()
			}
			released := testing.AllocsPerRun(200, tc.released)
			unreleased := testing.AllocsPerRun(200, tc.unreleased)
			t.Logf("released %.0f, unreleased %.0f allocs/op", released, unreleased)
			if released > unreleased-1 {
				t.Errorf("AST release must save at least one allocation: released %.0f, unreleased %.0f", released, unreleased)
			}
		})
	}
}
