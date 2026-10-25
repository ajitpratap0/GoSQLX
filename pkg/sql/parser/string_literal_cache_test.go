// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// Changing options or resetting a reused parser must update how its literals
// render, including the zero/default dialect's strict escaping behavior.
func TestStringLiteralModeAfterParserReuse(t *testing.T) {
	p := GetParser()
	defer PutParser(p)
	for _, tc := range []struct {
		dialect string
		raw     bool
	}{
		{"postgresql", true}, {"mysql", false}, {"oracle", true},
		{"", false}, {"clickhouse", false}, {"generic", true},
	} {
		t.Run(tc.dialect, func(t *testing.T) {
			p.ApplyOptions(WithDialect(tc.dialect))
			checkStringLiteralMode(t, p, tc.raw)
		})
	}
	p.Reset()
	checkStringLiteralMode(t, p, false)
	checkStringLiteralMode(t, &Parser{}, false)
}

func checkStringLiteralMode(t *testing.T, p *Parser, raw bool) {
	t.Helper()
	tree, err := p.ParseFromModelTokens([]models.TokenWithSpan{
		{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
		{Token: models.Token{Type: models.TokenTypeString, Value: `a\b`}},
		{Token: models.Token{Type: models.TokenTypeSemicolon, Value: ";"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("expected SELECT, got %T", tree.Statements[0])
	}
	lit, ok := stmt.Columns[0].(*ast.LiteralValue)
	if !ok {
		t.Fatalf("expected literal, got %T", stmt.Columns[0])
	}
	want := `'a\\b'`
	if raw {
		want = `'a\b'`
	}
	if lit.DialectExtras().RawBackslash != raw || lit.SQL() != want {
		t.Fatalf("literal rendered %s (raw=%v), want %s (raw=%v)", lit.SQL(), lit.DialectExtras().RawBackslash, want, raw)
	}
}
