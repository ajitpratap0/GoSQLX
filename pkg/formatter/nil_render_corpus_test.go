// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestNilRenderNodeCorpusDifferential(t *testing.T) {
	for _, st := range goldens.Corpus(t) {
		tree, err := gosqlx.ParseWithDialect(st.SQL, keywords.SQLDialect(st.Dialect))
		if err != nil {
			continue
		}
		ast.Inspect(tree, func(n ast.Node) bool {
			want := n == nil
			if !want {
				v := reflect.ValueOf(n)
				want = v.Kind() == reflect.Pointer && v.IsNil()
			}
			if got := formatter.NilRenderNodeForTest(n); got != want {
				t.Fatalf("%s#%d %T: got %v, reflect wants %v", st.File, st.Index, n, got, want)
			}
			return !want
		})
		ast.ReleaseAST(tree)
	}
}
