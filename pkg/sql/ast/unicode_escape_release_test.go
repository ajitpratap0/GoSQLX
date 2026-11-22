// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import "testing"

func TestUnicodeEscapeReleaseModes(t *testing.T) {
	for _, mode := range []releaseMode{releaseAll, releaseDrawn} {
		expr := &UnicodeEscapeExpression{RawSQL: `U&"d\0061t"`, Identifier: true}
		if children := expr.Children(); len(children) != 0 {
			t.Fatalf("leaf has children: %#v", children)
		}
		releaseExpression(expr, mode)
		if mode == releaseAll {
			if expr.RawSQL != "" || expr.Identifier {
				t.Fatal("releaseAll retained Unicode metadata")
			}
		} else if expr.RawSQL == "" || !expr.Identifier {
			t.Fatal("releaseDrawn cleared an unpooled leaf")
		}
	}
}
