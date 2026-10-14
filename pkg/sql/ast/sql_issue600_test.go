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

// TestSQL_Issue600 covers rendering of constructs that SQL() used to drop
// (#600): named arguments, IGNORE/RESPECT NULLS, INSERT ... OUTPUT,
// ON DUPLICATE KEY UPDATE and ClickHouse SELECT ... SETTINGS.
func TestSQL_Issue600(t *testing.T) {
	lit := func(v interface{}) *ast.LiteralValue { return &ast.LiteralValue{Value: v, Type: "INTEGER"} }
	id := func(name string) *ast.Identifier { return &ast.Identifier{Name: name} }

	t.Run("named_argument", func(t *testing.T) {
		if got := (&ast.NamedArgument{Name: "x", Value: lit(1)}).SQL(); got != "x => 1" {
			t.Errorf("got %q", got)
		}
		if got := (&ast.NamedArgument{Name: "my arg", Value: lit(1)}).SQL(); got != `"my arg" => 1` {
			t.Errorf("got %q", got)
		}
		var nilArg *ast.NamedArgument
		if got := nilArg.SQL(); got != "" {
			t.Errorf("nil NamedArgument SQL() = %q", got)
		}
		fc := &ast.FunctionCall{Name: "f", Arguments: []ast.Expression{&ast.NamedArgument{Name: "x", Value: lit(1)}}}
		if got := fc.SQL(); got != "f(x => 1)" {
			t.Errorf("function with named arg = %q", got)
		}
	})

	t.Run("null_treatment", func(t *testing.T) {
		fc := &ast.FunctionCall{
			Name:          "LAG",
			Arguments:     []ast.Expression{id("x")},
			NullTreatment: "RESPECT NULLS",
			Over:          &ast.WindowSpec{},
		}
		if got, want := fc.SQL(), "LAG(x) RESPECT NULLS OVER ()"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("insert_output_on_duplicate_key", func(t *testing.T) {
		ins := &ast.InsertStatement{
			TableName:      "t",
			Columns:        []ast.Expression{id("a")},
			Output:         []ast.Expression{&ast.Identifier{Table: "INSERTED", Name: "id"}},
			Values:         [][]ast.Expression{{lit(1)}},
			OnDuplicateKey: &ast.UpsertClause{Updates: []ast.UpdateExpression{{Column: id("a"), Value: lit(2)}}},
		}
		if got, want := ins.SQL(), "INSERT INTO t (a) OUTPUT INSERTED.id VALUES (1) ON DUPLICATE KEY UPDATE a = 2"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		ins.Output = nil
		ins.OnDuplicateKey = &ast.UpsertClause{}
		if got, want := ins.SQL(), "INSERT INTO t (a) VALUES (1)"; got != want {
			t.Errorf("empty ON DUPLICATE KEY: got %q, want %q", got, want)
		}
	})

	t.Run("select_settings", func(t *testing.T) {
		v1, v2 := lit(4), lit(10)
		sel := &ast.SelectStatement{
			Columns: []ast.Expression{id("a")},
			From:    []ast.TableReference{{Name: "t"}},
			Settings: []ast.QuerySetting{
				{Name: "max_threads", Value: v1},
				{Name: "limit", Value: v2},
			},
		}
		if got, want := sel.SQL(), "SELECT a FROM t SETTINGS max_threads = 4, limit = 10"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
		if got := (&ast.QuerySetting{Name: "max_threads", Value: v1}).SQL(); got != "max_threads = 4" {
			t.Errorf("QuerySetting.SQL() = %q", got)
		}
		var nilSetting *ast.QuerySetting
		if got := nilSetting.SQL(); got != "" {
			t.Errorf("nil QuerySetting SQL() = %q", got)
		}

		children := sel.Children()
		var seen1, seen2 bool
		for _, c := range children {
			if c == ast.Node(v1) {
				seen1 = true
			}
			if c == ast.Node(v2) {
				seen2 = true
			}
			if ident, ok := c.(*ast.Identifier); ok && ident.Name == "max_threads" {
				t.Errorf("setting name exposed as identifier child")
			}
		}
		if !seen1 || !seen2 {
			t.Errorf("Children() missing settings values (seen %v, %v)", seen1, seen2)
		}
	})
}
