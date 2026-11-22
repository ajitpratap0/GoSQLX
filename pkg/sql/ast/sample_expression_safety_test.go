package ast

import (
	"strings"
	"testing"
)

func TestDialectConstructsSampleCanonicalSafety(t *testing.T) {
	evil := "0.1; DROP TABLE audit; --"
	number := func(value string) Expression { return &LiteralValue{Value: value, Type: "INTEGER"} }
	var nilBinary *BinaryExpression
	var nilLiteral *LiteralValue
	cases := []struct {
		name   string
		clause SampleClause
		want   string
	}{
		{"size injection", SampleClause{Size: number(evil)}, ""},
		{"offset injection", SampleClause{Size: number("1"), OffsetSize: number(evil)}, "SAMPLE 1"},
		{"numerator injection", SampleClause{Size: &BinaryExpression{Left: number(evil), Operator: "/", Right: number("10")}}, ""},
		{"denominator injection", SampleClause{Size: &BinaryExpression{Left: number("1"), Operator: "/", Right: number(evil)}}, ""},
		{"offset ratio injection", SampleClause{Size: number("1"), OffsetSize: &BinaryExpression{Left: number("1"), Operator: "/", Right: number(evil)}}, "SAMPLE 1"},
		{"nil size binary", SampleClause{Size: nilBinary}, ""},
		{"nil offset binary", SampleClause{Size: number("1"), OffsetSize: nilBinary}, "SAMPLE 1"},
		{"nil literal", SampleClause{Size: nilLiteral}, ""},
		{"string type", SampleClause{Size: &LiteralValue{Value: "1", Type: "STRING"}}, ""},
		{"unknown type", SampleClause{Size: &LiteralValue{Value: "1", Type: "unknown"}}, ""},
		{"identifier", SampleClause{Size: &Identifier{Name: "ratio"}}, ""},
		{"nested operator", SampleClause{Size: &BinaryExpression{Left: &BinaryExpression{Left: number("1"), Operator: "+", Right: number("2")}, Operator: "/", Right: number("10")}}, ""},
		{"negated division", SampleClause{Size: &BinaryExpression{Left: number("1"), Operator: "/", Right: number("10"), Not: true}}, ""},
		{"normal int", SampleClause{Size: &LiteralValue{Value: 1, Type: "int"}}, "SAMPLE 1"},
		{"normal float", SampleClause{Size: &LiteralValue{Value: "0.1", Type: "FLOAT"}}, "SAMPLE 0.1"},
		{"normal ratio", SampleClause{Size: &BinaryExpression{Left: number("1"), Operator: "/", Right: number("10")}, OffsetSize: &BinaryExpression{Left: number("1"), Operator: "/", Right: number("2")}}, "SAMPLE 1/10 OFFSET 1/2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.clause.SQL()
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "DROP TABLE") {
				t.Fatal("unsafe sample text")
			}
		})
	}
}
