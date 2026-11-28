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

package benchcorpus

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestScaleSQLParsesAndGrows pins what the scale benchmarks rely on: every
// shape at every size parses, is deterministic, and grows with n.
func TestScaleSQLParsesAndGrows(t *testing.T) {
	for _, shape := range ScaleShapes {
		prev := 0
		for _, n := range ScaleSizes {
			sql := ScaleSQL(shape, n)
			if sql != ScaleSQL(shape, n) {
				t.Fatalf("%s/%d: ScaleSQL is not deterministic", shape, n)
			}
			if len(sql) <= prev {
				t.Errorf("%s/%d: length %d did not grow past %d", shape, n, len(sql), prev)
			}
			prev = len(sql)
			tree, err := gosqlx.Parse(sql)
			if err != nil {
				t.Fatalf("%s/%d: parse: %v", shape, n, err)
			}
			if len(tree.Statements) != 1 {
				t.Errorf("%s/%d: %d statements, want 1", shape, n, len(tree.Statements))
			}
			ast.ReleaseAST(tree)
		}
	}
}

func TestScaleSQLShapesAreDistinct(t *testing.T) {
	want := map[string]string{
		ScaleWide:   " AS c9",
		ScaleIn:     " IN (0, 7,",
		ScaleValues: "VALUES (0, 'name_0', 0.5)",
		ScaleAnd:    "x8 = 8 AND x9 = 9",
	}
	for shape, frag := range want {
		if sql := ScaleSQL(shape, 10); !strings.Contains(sql, frag) {
			t.Errorf("%s: %q missing %q", shape, sql, frag)
		}
	}
}

func TestScaleSQLRejectsBadInput(t *testing.T) {
	for name, fn := range map[string]func(){
		"unknown shape": func() { ScaleSQL("nope", 10) },
		"zero n":        func() { ScaleSQL(ScaleIn, 0) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: expected panic", name)
				}
			}()
			fn()
		}()
	}
}
