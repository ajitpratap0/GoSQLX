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

package gosqlx_test

import (
	"context"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

const treeDialectBenchSQL = "SELECT a FROM t WHERE x = 1"

func BenchmarkParseTree_Default(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := gosqlx.ParseTree(ctx, treeDialectBenchSQL); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTree_WithDialect(b *testing.B) {
	ctx := context.Background()
	for _, d := range []string{"postgresql", "mysql"} {
		b.Run(d, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := gosqlx.ParseTree(ctx, treeDialectBenchSQL, gosqlx.WithDialect(d)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
