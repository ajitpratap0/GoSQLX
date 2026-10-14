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

// TestInsertStatementSQL_Forms covers the DEFAULT VALUES and MySQL SET
// forms of InsertStatement.SQL() (#610).
func TestInsertStatementSQL_Forms(t *testing.T) {
	ab := func() []Expression { return []Expression{&Identifier{Name: "a"}, &Identifier{Name: "b"}} }
	one := func() Expression { return &LiteralValue{Value: 1, Type: "INTEGER"} }
	x := func() Expression { return &LiteralValue{Value: "x", Type: "STRING"} }

	tests := []struct {
		name string
		stmt *InsertStatement
		want string
	}{
		{
			name: "default values",
			stmt: &InsertStatement{TableName: "t", DefaultValues: true},
			want: "INSERT INTO t DEFAULT VALUES",
		},
		{
			name: "default values returning",
			stmt: &InsertStatement{TableName: "t", DefaultValues: true, Returning: []Expression{&Identifier{Name: "id"}}},
			want: "INSERT INTO t DEFAULT VALUES RETURNING id",
		},
		{
			name: "set form",
			stmt: &InsertStatement{TableName: "t", SetSyntax: true, Columns: ab(), Values: [][]Expression{{one(), x()}}},
			want: "INSERT INTO t SET a = 1, b = 'x'",
		},
		{
			name: "set syntax with two rows falls back to VALUES",
			stmt: &InsertStatement{TableName: "t", SetSyntax: true, Columns: ab(), Values: [][]Expression{{one(), x()}, {one(), x()}}},
			want: "INSERT INTO t (a, b) VALUES (1, 'x'), (1, 'x')",
		},
		{
			name: "set syntax with cell count mismatch falls back to VALUES",
			stmt: &InsertStatement{TableName: "t", SetSyntax: true, Columns: ab(), Values: [][]Expression{{one()}}},
			want: "INSERT INTO t (a, b) VALUES (1)",
		},
		{
			name: "values win over DefaultValues",
			stmt: &InsertStatement{TableName: "t", DefaultValues: true, Columns: ab(), Values: [][]Expression{{one(), x()}}},
			want: "INSERT INTO t (a, b) VALUES (1, 'x')",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.stmt.SQL(); got != tt.want {
				t.Fatalf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestInsertStatementPool_ResetsFormFlags pins that the #610 form flags do
// not leak through the InsertStatement pool.
func TestInsertStatementPool_ResetsFormFlags(t *testing.T) {
	stmt := GetInsertStatement()
	stmt.DefaultValues = true
	stmt.SetSyntax = true
	PutInsertStatement(stmt)

	// releaseInsertStatement resets fields in place before pooling.
	if stmt.DefaultValues || stmt.SetSyntax {
		t.Fatalf("released InsertStatement kept DefaultValues=%v SetSyntax=%v", stmt.DefaultValues, stmt.SetSyntax)
	}
}
