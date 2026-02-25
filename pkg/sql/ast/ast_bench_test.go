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

package ast

import (
	"testing"
)

func BenchmarkASTPool(b *testing.B) {
	b.Run("GetReleaseAST", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ast := NewAST()
			ReleaseAST(ast)
		}
	})
}

func BenchmarkSelectStatementPool(b *testing.B) {
	b.Run("GetPutSelectStatement", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			stmt := GetSelectStatement()
			stmt.Columns = append(stmt.Columns, &Identifier{Name: "id"})
			stmt.Where = &BinaryExpression{
				Left:     &Identifier{Name: "id"},
				Operator: "=",
				Right:    &Identifier{Name: "1"},
			}
			PutSelectStatement(stmt)
		}
	})
}

func BenchmarkIdentifierPool(b *testing.B) {
	b.Run("GetPutIdentifier", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ident := GetIdentifier()
			ident.Name = "test"
			PutIdentifier(ident)
		}
	})
}

func BenchmarkBinaryExpressionPool(b *testing.B) {
	b.Run("GetPutBinaryExpression", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			expr := GetBinaryExpression()
			expr.Left = &Identifier{Name: "id"}
			expr.Operator = "="
			expr.Right = &Identifier{Name: "1"}
			PutBinaryExpression(expr)
		}
	})
}

func BenchmarkExpressionSlicePool(b *testing.B) {
	b.Run("GetPutExpressionSlice", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			slice := GetExpressionSlice()
			*slice = append(*slice, &Identifier{Name: "test"})
			PutExpressionSlice(slice)
		}
	})
}

func BenchmarkPutExpression(b *testing.B) {
	b.Run("PutIdentifier", func(b *testing.B) {
		b.ReportAllocs()
		ident := &Identifier{Name: "test"}
		for i := 0; i < b.N; i++ {
			PutExpression(ident)
		}
	})

	b.Run("PutBinaryExpression", func(b *testing.B) {
		b.ReportAllocs()
		binExpr := &BinaryExpression{
			Left:     &Identifier{Name: "id"},
			Operator: "=",
			Right:    &Identifier{Name: "1"},
		}
		for i := 0; i < b.N; i++ {
			PutExpression(binExpr)
		}
	})
}

func BenchmarkParallel(b *testing.B) {
	b.Run("ParallelSelectStatement", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				stmt := GetSelectStatement()
				stmt.Columns = append(stmt.Columns, &Identifier{Name: "id"})
				stmt.Where = &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Operator: "=",
					Right:    &Identifier{Name: "1"},
				}
				PutSelectStatement(stmt)
			}
		})
	})
}
