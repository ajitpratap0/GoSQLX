// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func TestPrimaryFastPath_ModelTokenBinaryPrefix(t *testing.T) {
	for _, typ := range []models.TokenType{
		models.TokenTypeString, models.TokenTypeSingleQuotedString, models.TokenTypeDollarQuotedString,
		models.TokenTypeNumber, models.TokenTypeTrue, models.TokenTypeFalse, models.TokenTypeNull,
		models.TokenTypeAsterisk, models.TokenTypeMul,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			p := NewParser(WithDialect("mysql"))
			tree, err := p.ParseFromModelTokens([]models.TokenWithSpan{
				{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
				{Token: models.Token{Type: models.TokenTypeLParen, Value: "("}},
				{Token: models.Token{Type: typ, Value: "BINARY"}},
				{Token: models.Token{Type: models.TokenTypeIdentifier, Value: "x"}},
				{Token: models.Token{Type: models.TokenTypeRParen, Value: ")"}},
				{Token: models.Token{Type: models.TokenTypeEOF}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			paren, ok := firstColumn(t, tree).(*ast.ParenthesizedExpression)
			if !ok {
				t.Fatalf("want parenthesized expression, got %T", firstColumn(t, tree))
			}
			expr, ok := paren.Expr.(*ast.UnaryExpression)
			if !ok {
				t.Fatalf("want BINARY prefix expression, got %T", firstColumn(t, tree))
			}
			if expr.Operator != ast.MySQLBinary {
				t.Fatalf("operator = %v, want BINARY", expr.Operator)
			}
			ident, ok := expr.Expr.(*ast.Identifier)
			if !ok || ident.Name != "x" {
				t.Fatalf("operand = %#v, want identifier x", expr.Expr)
			}
		})
	}
}

func TestPrimaryFastPath_ModelTokenBinaryLiteral(t *testing.T) {
	for _, quote := range []rune{0, 39} {
		t.Run(string(quote), func(t *testing.T) {
			p := NewParser(WithDialect("mysql"))
			tree, err := p.ParseFromModelTokens([]models.TokenWithSpan{
				{Token: models.Token{Type: models.TokenTypeSelect, Value: "SELECT"}},
				{Token: models.Token{Type: models.TokenTypeString, Value: "BINARY", Quote: quote}},
				{Token: models.Token{Type: models.TokenTypeEOF}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			lit, ok := firstColumn(t, tree).(*ast.LiteralValue)
			if !ok {
				t.Fatalf("want literal, got %T", firstColumn(t, tree))
			}
			if lit.Value != "BINARY" || lit.Type != "string" {
				t.Fatalf("literal = %#v", lit)
			}
		})
	}
}
