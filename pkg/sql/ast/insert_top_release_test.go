package ast

import "testing"

func TestDialectConstructsInsertTopRelease(t *testing.T) {
	for _, mode := range []releaseMode{releaseAll, releaseDrawn} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			count := GetArrayConstructor()
			count.Elements = append(count.Elements, &LiteralValue{Value: "10", Type: "number"})
			fields := InsertDialectFields{Top: &TopClause{Count: count, Parenthesized: true, IsPercent: true}}
			defer releaseInsertDialectFields(&fields, mode)
			releaseInsertDialectFields(&fields, mode)
			if fields.Top != nil {
				t.Fatal("released INSERT retains TOP")
			}
			if len(count.Elements) != 0 {
				t.Fatal("TOP count was not released")
			}
		})
	}
}
