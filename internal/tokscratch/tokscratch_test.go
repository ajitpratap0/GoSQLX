package tokscratch

import (
	"context"
	"testing"
)

func TestTokenizerNotLinked(t *testing.T) {
	for _, name := range []string{"Bytes", "String", "StringContext"} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				r := recover()
				message, ok := r.(string)
				if !ok || message != "tokscratch: tokenizer not linked" {
					t.Fatalf("panic = %v, want tokscratch: tokenizer not linked", r)
				}
			}()
			switch name {
			case "Bytes":
				_, _ = Bytes(nil, nil)
			case "String":
				_, _ = String(nil, "")
			case "StringContext":
				_, _ = StringContext(context.Background(), nil, "")
			}
		})
	}
}
