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

package ast_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// These benchmarks measure the PutExpression release path in isolation.
// The *AfterBigList variants first release one 20,000-element IN list on the
// same goroutine (so the work queue that grew to hold it lands in this P's
// sync.Pool private slot) and then measure ordinary small releases. Before
// issue #555 every later Put cleared the whole grown queue, making a leaf
// release ~100x slower. They must not use RunParallel: the prelude and the
// loop have to share a P for the measurement to be meaningful.

const bigListLen = 20_000

func releaseBigInList() {
	in := ast.GetInExpression()
	for i := 0; i < bigListLen; i++ {
		in.List = append(in.List, ast.GetLiteralValue())
	}
	ast.PutExpression(in)
}

func putLeafLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ast.PutExpression(ast.GetIdentifier())
	}
}

func putBinaryLoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		be := ast.GetBinaryExpression()
		be.Left = ast.GetIdentifier()
		be.Right = ast.GetIdentifier()
		ast.PutExpression(be)
	}
}

func BenchmarkPutLeaf(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	putLeafLoop(b)
}

func BenchmarkPutLeafAfterBigList(b *testing.B) {
	b.ReportAllocs()
	releaseBigInList()
	b.ResetTimer()
	putLeafLoop(b)
}

func BenchmarkPutBinary(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	putBinaryLoop(b)
}

func BenchmarkPutBinaryAfterBigList(b *testing.B) {
	b.ReportAllocs()
	releaseBigInList()
	b.ResetTimer()
	putBinaryLoop(b)
}
