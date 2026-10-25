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
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestDMLDialectFields_ResetOnPut fills the UPDATE / DELETE / INSERT dialect
// fields, releases the statement and checks that the object the pool hands
// out again carries none of them.
func TestDMLDialectFields_ResetOnPut(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cases := []struct {
		name  string
		fill  func() any
		reget func() any
		check func(v any) bool
	}{
		{"Update", func() any {
			s := GetUpdateStatement()
			fillNonZero(reflect.ValueOf(&s.DMLTargetFields).Elem())
			PutUpdateStatement(s)
			return s
		}, func() any { return GetUpdateStatement() }, func(v any) bool {
			s, ok := v.(*UpdateStatement)
			return ok && reflect.ValueOf(s.DMLTargetFields).IsZero()
		}},
		{"Delete", func() any {
			s := GetDeleteStatement()
			fillNonZero(reflect.ValueOf(&s.DMLTargetFields).Elem())
			s.From = []TableReference{{Name: "x"}}
			PutDeleteStatement(s)
			return s
		}, func() any { return GetDeleteStatement() }, func(v any) bool {
			s, ok := v.(*DeleteStatement)
			return ok && reflect.ValueOf(s.DMLTargetFields).IsZero() && len(s.From) == 0
		}},
		{"Insert", func() any {
			s := GetInsertStatement()
			fillNonZero(reflect.ValueOf(s.EnsureExtras()).Elem())
			s.OnConflict = &OnConflict{TargetWhere: &Identifier{Name: "x"}}
			PutInsertStatement(s)
			return s
		}, func() any { return GetInsertStatement() }, func(v any) bool {
			s, ok := v.(*InsertStatement)
			return ok && reflect.ValueOf(s.Extras).IsZero() && s.OnConflict == nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for try := 0; try < maxReuseTries; try++ {
				put := tc.fill()
				got := tc.reget()
				if got != put {
					continue
				}
				if !tc.check(got) {
					t.Fatalf("%s: dialect fields not reset after Put", tc.name)
				}
				return
			}
			t.Skipf("pool never returned the just-released %s", tc.name)
		})
	}
}

// TestDMLRender_UnknownKeywordTextDropped checks that keyword fields set by
// hand to arbitrary text are not written into the SQL.
func TestDMLRender_UnknownKeywordTextDropped(t *testing.T) {
	u := &UpdateStatement{
		TableName:       "t",
		Assignments:     []UpdateExpression{{Column: &Identifier{Name: "a"}, Value: &LiteralValue{Value: "1", Type: "int"}}},
		DMLTargetFields: DMLTargetFields{Modifiers: []string{"IGNORE", "; DROP TABLE x; --"}},
	}
	if got, want := u.SQL(), "UPDATE IGNORE t SET a = 1"; got != want {
		t.Errorf("UPDATE SQL() = %q, want %q", got, want)
	}
	i := &InsertStatement{
		TableName: "t",
		Values:    [][]Expression{{&LiteralValue{Value: "1", Type: "int"}}},

		Extras: &InsertDialectFields{Modifiers: []string{"OR REPLACE", "evil"}, Overriding: "evil"}}
	if got, want := i.SQL(), "INSERT OR REPLACE INTO t VALUES (1)"; got != want {
		t.Errorf("INSERT SQL() = %q, want %q", got, want)
	}
	i.EnsureExtras().DataFormat = "x; DROP"
	if got := i.SQL(); !strings.HasSuffix(got, ` FORMAT "x; DROP"`) {
		t.Errorf("FORMAT name not quoted: %q", got)
	}
}

// TestDMLChildren_IncludeDialectFields checks that visitors reach the
// expressions stored in the new DML fields.
func TestDMLChildren_IncludeDialectFields(t *testing.T) {
	limit := &LiteralValue{Value: "5", Type: "int"}
	into := &Identifier{Name: "v"}
	u := &UpdateStatement{
		TableName:       "t",
		DMLTargetFields: DMLTargetFields{Limit: limit, ReturningInto: []Expression{into}},
	}
	children := u.Children()
	found := 0
	for _, c := range children {
		if c == Node(limit) || c == Node(into) {
			found++
		}
	}
	if found != 2 {
		t.Errorf("UpdateStatement.Children reached %d of 2 dialect-field expressions", found)
	}

	where := &Identifier{Name: "w"}
	m := &MergeAction{ActionType: "UPDATE", Where: where}
	if kids := m.Children(); len(kids) != 1 || kids[0] != Node(where) {
		t.Errorf("MergeAction.Children = %v, want the WHERE predicate", kids)
	}
}
