package ast

import "testing"

// TestFunctionCallPool_ParametersCleared ensures ClickHouse parametric-aggregate
// parameters do not leak into a recycled FunctionCall now that SQL() renders them.
func TestFunctionCallPool_ParametersCleared(t *testing.T) {
	tests := []struct {
		name    string
		release func(*FunctionCall)
	}{
		{"PutFunctionCall", PutFunctionCall},
		{"PutExpression", func(fc *FunctionCall) { PutExpression(fc) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := GetFunctionCall()
			fc.Name = "quantile"
			fc.Parameters = []Expression{&LiteralValue{Value: "0.5", Type: "float"}}
			fc.Arguments = []Expression{&Identifier{Name: "x"}}
			tt.release(fc)
			if len(fc.Parameters) != 0 {
				t.Fatalf("Parameters not cleared on release: len=%d", len(fc.Parameters))
			}

			fc2 := GetFunctionCall()
			defer PutFunctionCall(fc2)
			fc2.Name = "count"
			fc2.Arguments = []Expression{&Identifier{Name: "y"}}
			if got := fc2.SQL(); got != "count(y)" {
				t.Errorf("recycled FunctionCall SQL() = %q, want %q", got, "count(y)")
			}
		})
	}
}
