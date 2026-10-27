package formatter_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestDialectConstructsSampleFormatterSafety(t *testing.T) {
	evil := "1; DROP TABLE audit; --"
	number := func(v string) ast.Expression { return &ast.LiteralValue{Value: v, Type: "int"} }
	var nilRatio *ast.BinaryExpression
	clauses := []*ast.SampleClause{
		{Size: number(evil)},
		{Size: number("1"), OffsetSize: number(evil)},
		{Size: &ast.BinaryExpression{Left: number(evil), Operator: "/", Right: number("10")}},
		{Size: &ast.BinaryExpression{Left: number("1"), Operator: "/", Right: number(evil)}},
		{Size: number("1"), OffsetSize: &ast.BinaryExpression{Left: number(evil), Operator: "/", Right: number("2")}},
		{Size: number("1"), OffsetSize: &ast.BinaryExpression{Left: number("1"), Operator: "/", Right: number(evil)}},
		{Size: nilRatio},
		{Size: number("1"), OffsetSize: nilRatio},
	}
	for i, clause := range clauses {
		tree := &ast.AST{Statements: []ast.Statement{&ast.SelectStatement{Columns: []ast.Expression{&ast.Identifier{Name: "x"}}, From: []ast.TableReference{{Name: "hits"}}, Sample: clause}}}
		for _, output := range []string{tree.SQL(), formatter.FormatAST(tree, ast.CompactStyle())} {
			if strings.Contains(output, "DROP TABLE") || strings.Contains(output, ";") || strings.Contains(output, "--") {
				t.Errorf("case %d emitted unsafe text: %q", i, output)
			}
		}
	}
}

func TestDialectConstructsSampleCanonicalMutation(t *testing.T) {
	tree, err := gosqlx.ParseWithDialect("SELECT * FROM hits SAMPLE 1/10 OFFSET 1/2", keywords.DialectClickHouse)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatalf("got %T", tree.Statements[0])
	}
	for _, output := range []string{tree.SQL(), formatter.FormatAST(tree, ast.CompactStyle())} {
		if !strings.Contains(output, "SAMPLE 1/10 OFFSET 1/2") {
			t.Fatalf("normal ratio changed: %q", output)
		}
	}
	stmt.Sample.Size = &ast.LiteralValue{Value: "0.25", Type: "float"}
	stmt.Sample.OffsetSize = &ast.LiteralValue{Value: "0.5", Type: "FLOAT"}
	for _, output := range []string{tree.SQL(), formatter.FormatAST(tree, ast.CompactStyle())} {
		if !strings.Contains(output, "SAMPLE 0.25 OFFSET 0.5") {
			t.Fatalf("canonical mutation ignored: %q", output)
		}
		again, err := gosqlx.ParseWithDialect(output, keywords.DialectClickHouse)
		if err != nil {
			t.Fatal(err)
		}
		defer ast.ReleaseAST(again)
	}
}
