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

import "testing"

func newReleaseModeTable() *CreateTableStatement {
	return &CreateTableStatement{
		Name: "t",
		Options: []TableOption{{
			Name: "ENGINE", Value: "Distributed(a)", ValueArgs: []Expression{&Identifier{Name: "a"}},
		}},
		CreateTableExtras: CreateTableExtras{
			Clone:          &TableClone{Source: "s", Point: &Identifier{Name: "p"}},
			PartitionBound: &PartitionBound{From: []Expression{&Identifier{Name: "f"}}},
			Engine:         &TableEngineClauses{OrderBy: &Identifier{Name: "o"}},
		},
	}
}

// TestReleaseCreateTableHonoursMode checks that both release modes clear the
// extras of a CREATE TABLE; releaseDrawn must not hand the never-pooled
// statement to its pool (issue #556).
func TestReleaseCreateTableHonoursMode(t *testing.T) {
	for name, mode := range map[string]releaseMode{"all": releaseAll, "drawn": releaseDrawn} {
		t.Run(name, func(t *testing.T) {
			stmt := newReleaseModeTable()
			releaseStatement(stmt, mode)
			if stmt.Name != "" || len(stmt.Options) != 0 || stmt.Engine != nil || stmt.Clone != nil || stmt.PartitionBound != nil {
				t.Errorf("statement not cleared after release: %+v", stmt)
			}
		})
	}
}

func TestChildrenReachCreateTableExtras(t *testing.T) {
	stmt := newReleaseModeTable()
	var names []string
	Inspect(stmt, func(n Node) bool {
		if id, ok := n.(*Identifier); ok {
			names = append(names, id.Name)
		}
		return true
	})
	want := map[string]bool{"a": false, "p": false, "f": false, "o": false}
	for _, n := range names {
		want[n] = true
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("identifier %q not reached by Inspect", n)
		}
	}
}

// TestSQLFallsBackToToSQL covers statements that only implement ToSQL.
func TestSQLFallsBackToToSQL(t *testing.T) {
	a := AST{Statements: []Statement{&UnsupportedStatement{Kind: "X", RawSQL: "RAW STUFF"}}}
	if got := a.SQL(); got == "" {
		t.Errorf("AST.SQL() skipped a ToSQL-only statement")
	}
}
