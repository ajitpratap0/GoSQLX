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
	"fmt"
	"reflect"
	"testing"
)

// Tests for #617: CreateTable, FunctionDesc, TriggerReferencing and
// TriggerExecBody return pointer-typed children that alias the stored fields,
// so type switches on *T and edits made through Walk/Inspect reach the AST.

func typeNames(nodes []Node) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = fmt.Sprintf("%T", n)
	}
	return out
}

func TestIssue617_CreateTableBuilderInspectRenames(t *testing.T) {
	stmt := NewCreateTableBuilder(ObjectName{Name: "t"}).
		SetColumns([]ColumnDef{{Name: "a", Type: "INT"}}).
		SetConstraints([]TableConstraint{{Type: "PRIMARY KEY", Columns: []string{"a"}}}).
		Build()
	ct, ok := stmt.Variant.(*CreateTable)
	if !ok {
		t.Fatalf("expected *CreateTable, got %T", stmt.Variant)
	}

	want := []string{"*ast.ObjectName", "*ast.ColumnDef", "*ast.TableConstraint"}
	if got := typeNames(ct.Children()); !reflect.DeepEqual(got, want) {
		t.Fatalf("Children() types = %v, want %v", got, want)
	}

	Inspect(ct, func(n Node) bool {
		switch v := n.(type) {
		case *ObjectName:
			v.Name = "renamed"
		case *ColumnDef:
			v.Type = "BIGINT"
		case *TableConstraint:
			v.Name = "pk"
		}
		return true
	})
	if ct.Name.Name != "renamed" {
		t.Errorf("ct.Name.Name = %q, want renamed", ct.Name.Name)
	}
	if ct.Columns[0].Type != "BIGINT" {
		t.Errorf("ct.Columns[0].Type = %q, want BIGINT", ct.Columns[0].Type)
	}
	if ct.Constraints[0].Name != "pk" {
		t.Errorf("ct.Constraints[0].Name = %q, want pk", ct.Constraints[0].Name)
	}
}

func TestIssue617_TriggerAndFunctionDescChildrenArePointers(t *testing.T) {
	tests := []struct {
		name     string
		node     Node
		wantType string
		wantName string
	}{
		{"FunctionDesc", FunctionDesc{Name: ObjectName{Name: "f"}}, "*ast.ObjectName", "f"},
		{"TriggerReferencing", TriggerReferencing{TransitionRelationName: ObjectName{Name: "old_rows"}}, "*ast.ObjectName", "old_rows"},
		{"TriggerExecBody", TriggerExecBody{FuncDesc: FunctionDesc{Name: ObjectName{Name: "g"}}}, "*ast.FunctionDesc", "g"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			children := tt.node.Children()
			if len(children) != 1 {
				t.Fatalf("got %d children, want 1", len(children))
			}
			if got := fmt.Sprintf("%T", children[0]); got != tt.wantType {
				t.Fatalf("child type = %s, want %s", got, tt.wantType)
			}
			switch c := children[0].(type) {
			case *ObjectName:
				if c.Name != tt.wantName {
					t.Errorf("name = %q, want %q", c.Name, tt.wantName)
				}
			case *FunctionDesc:
				if c.Name.Name != tt.wantName {
					t.Errorf("name = %q, want %q", c.Name.Name, tt.wantName)
				}
			}
		})
	}
}

func TestIssue617_InspectMutates(t *testing.T) {
	fd := &FunctionDesc{Name: ObjectName{Name: "f"}}
	tr := &TriggerReferencing{TransitionRelationName: ObjectName{Name: "old_rows"}}
	te := &TriggerExecBody{FuncDesc: FunctionDesc{Name: ObjectName{Name: "g"}}}

	tests := []struct {
		name  string
		node  Node
		wantF int
		got   func() string
	}{
		{"FunctionDesc", fd, 0, func() string { return fd.Name.Name }},
		{"TriggerReferencing", tr, 0, func() string { return tr.TransitionRelationName.Name }},
		{"TriggerExecBody", te, 1, func() string { return te.FuncDesc.Name.Name }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var names, funcs int
			Inspect(tt.node, func(n Node) bool {
				switch v := n.(type) {
				case *ObjectName:
					names++
					v.Name = "renamed"
				case *FunctionDesc:
					funcs++
				}
				return true
			})
			if names != 1 {
				t.Errorf("visited %d *ObjectName, want 1", names)
			}
			wantFuncs := tt.wantF
			if _, isFD := tt.node.(*FunctionDesc); isFD {
				wantFuncs = 1
			}
			if funcs != wantFuncs {
				t.Errorf("visited %d *FunctionDesc, want %d", funcs, wantFuncs)
			}
			if got := tt.got(); got != "renamed" {
				t.Errorf("stored name = %q, want renamed", got)
			}
		})
	}
}

func TestIssue617_ChildrenAliasStoredFields(t *testing.T) {
	ct := &CreateTable{
		Name:        ObjectName{Name: "t"},
		Columns:     []ColumnDef{{Name: "a"}, {Name: "b"}},
		Constraints: []TableConstraint{{Type: "UNIQUE"}},
	}
	wantCT := []Node{&ct.Name, &ct.Columns[0], &ct.Columns[1], &ct.Constraints[0]}
	assertAliases(t, ct.Children, wantCT)
	assertAliases(t, func() []Node { return childrenOf(ct) }, wantCT)

	fd := &FunctionDesc{Name: ObjectName{Name: "f"}}
	tr := &TriggerReferencing{TransitionRelationName: ObjectName{Name: "old_rows"}}
	te := &TriggerExecBody{FuncDesc: FunctionDesc{Name: ObjectName{Name: "g"}}}

	cases := []struct {
		name string
		node Node
		want Node
	}{
		{"FunctionDesc", fd, &fd.Name},
		{"TriggerReferencing", tr, &tr.TransitionRelationName},
		{"TriggerExecBody", te, &te.FuncDesc},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := childrenOf(c.node)
			if len(got) != 1 || got[0] != c.want {
				t.Fatalf("childrenOf returned %v, want exactly the stored field %p", got, c.want)
			}
			if a, b := fmt.Sprint(nodeSignature(got)), fmt.Sprint(nodeSignature(c.node.Children())); a != b {
				t.Errorf("childrenOf signature %s != Children() signature %s", a, b)
			}
		})
	}
}

func TestIssue617_TriggerExecBodyVisitOrder(t *testing.T) {
	te := &TriggerExecBody{FuncDesc: FunctionDesc{Name: ObjectName{Name: "g"}}}
	var order []string
	Inspect(te, func(n Node) bool {
		if n == nil {
			return false
		}
		order = append(order, fmt.Sprintf("%T", n))
		if on, ok := n.(*ObjectName); ok && on != &te.FuncDesc.Name {
			t.Errorf("visited *ObjectName %p is not &te.FuncDesc.Name", on)
		}
		return true
	})
	want := []string{"*ast.TriggerExecBody", "*ast.FunctionDesc", "*ast.ObjectName"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("visit order = %v, want %v", order, want)
	}
}
