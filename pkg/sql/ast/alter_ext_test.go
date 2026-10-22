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

// TestPutAlterStatement_ResetsExtendedFields checks that a pooled
// AlterStatement comes back with none of the fields of its previous use.
func TestPutAlterStatement_ResetsExtendedFields(t *testing.T) {
	stmt := GetAlterStatement()
	stmt.Type = AlterTypeTable
	stmt.Name = "s.t"
	stmt.IfExists = true
	stmt.Only = true
	stmt.Modifiers = []string{"ONLINE"}
	stmt.OnCluster = "c"
	op := &AlterTableOperation{Type: AddColumn}
	stmt.Operations = append(stmt.Operations, op, op)
	stmt.Operation = op
	PutAlterStatement(stmt)

	// The pool may hand back a different object; check the one we returned,
	// which is what a later Get could receive.
	if stmt.Name != "" || stmt.IfExists || stmt.Only || stmt.Modifiers != nil || stmt.OnCluster != "" || stmt.Operation != nil {
		t.Errorf("fields not reset: %+v", stmt)
	}
	if len(stmt.Operations) != 0 {
		t.Errorf("Operations has %d elements after Put, want 0", len(stmt.Operations))
	}
	for i, o := range stmt.Operations[:cap(stmt.Operations)] {
		if o != nil {
			t.Errorf("Operations backing array element %d still references an operation", i)
		}
	}

	again := GetAlterStatement()
	defer PutAlterStatement(again)
	if again.Name != "" || again.IfExists || again.Only || again.Modifiers != nil || again.OnCluster != "" || len(again.Operations) != 0 {
		t.Errorf("Get returned a dirty statement: %+v", again)
	}
}

// TestAlterTableOperation_ExtendedChildren checks that the extra column
// definitions and expressions of an operation are visited.
func TestAlterTableOperation_ExtendedChildren(t *testing.T) {
	first := &ColumnDef{Name: "a", Type: "INT"}
	second := &ColumnDef{Name: "b", Type: "INT"}
	op := AlterTableOperation{
		Type:          AddColumn,
		ColumnDef:     first,
		ColumnDefs:    []*ColumnDef{first, second},
		DefaultValue:  &LiteralValue{Value: 1},
		Using:         &LiteralValue{Value: 2},
		Assignments:   []UpdateExpression{{Column: &Identifier{Name: "x"}, Value: &LiteralValue{Value: 3}}},
		PartitionExpr: &LiteralValue{Value: 4},
		Where:         &LiteralValue{Value: 5},
	}
	// first, second, DefaultValue, Using, one assignment, PartitionExpr, Where.
	if got := len(op.Children()); got != 7 {
		t.Errorf("Children() = %d nodes, want 7", got)
	}

	stmt := &AlterStatement{Operation: &op, Operations: []AlterOperation{&op, &op}}
	if got := len(stmt.Children()); got != 2 {
		t.Errorf("AlterStatement.Children() = %d, want 2 (Operations take precedence)", got)
	}
	stmt.Operations = nil
	if got := len(stmt.Children()); got != 1 {
		t.Errorf("AlterStatement.Children() = %d, want 1 (legacy Operation)", got)
	}
}

func TestAlterColumnOperation_ExtendedLiterals(t *testing.T) {
	tests := []struct {
		op   AlterColumnOperation
		want string
	}{
		{AlterColumnSetDataType, "SET DATA TYPE"},
		{AlterColumnOther, "ALTER COLUMN"},
	}
	for _, tc := range tests {
		op := tc.op
		if got := op.TokenLiteral(); got != tc.want {
			t.Errorf("TokenLiteral(%d) = %q, want %q", int(tc.op), got, tc.want)
		}
	}
}
