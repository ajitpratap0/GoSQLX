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

package mcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestHandleParseSQL_Dialect(t *testing.T) {
	for _, dialect := range sqlkeywords.DialectNames() {
		t.Run(dialect, func(t *testing.T) {
			res, err := handleParseSQL(context.Background(), makeReq(map[string]any{"sql": "SELECT 1", "dialect": dialect}))
			if err != nil || res == nil || res.IsError {
				t.Fatalf("parse failed: result=%+v, error=%v", res, err)
			}
			data := unmarshalResult(t, res)
			if data["statement_count"] != float64(1) {
				t.Fatalf("statement_count = %v, want 1", data["statement_count"])
			}
		})
	}
	for _, tc := range []struct {
		name    string
		dialect any
		want    string
	}{
		{"unknown", "not-a-dialect", "unsupported dialect"},
		{"wrong type", 5.0, "parameter 'dialect' must be a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := handleParseSQL(context.Background(), makeReq(map[string]any{"sql": "SELECT 1", "dialect": tc.dialect}))
			requireToolError(t, res, err, tc.want)
		})
	}
}

func TestHandleParseSQL_SQLServerBatchCount(t *testing.T) {
	res, err := handleParseSQL(context.Background(), makeReq(map[string]any{"sql": "SELECT 1\nGO 3\nSELECT 2\nGO\n", "dialect": "sqlserver"}))
	if err != nil || res == nil || res.IsError {
		t.Fatalf("parse failed: result=%+v, error=%v", res, err)
	}
	data := unmarshalResult(t, res)
	if data["statement_count"] != float64(2) {
		t.Fatalf("statement_count = %v, want 2", data["statement_count"])
	}
	got, ok := data["statement_types"].([]any)
	if !ok {
		t.Fatalf("statement_types has type %T", data["statement_types"])
	}
	if !reflect.DeepEqual(got, []any{"*ast.SelectStatement", "*ast.SelectStatement"}) {
		t.Errorf("statement_types = %v", got)
	}
}

func TestParseSQL_DialectSchema(t *testing.T) {
	tool := New(DefaultConfig()).mcpSrv.GetTool("parse_sql")
	if tool == nil {
		t.Fatal("parse_sql tool not registered")
	}
	prop, ok := tool.Tool.InputSchema.Properties["dialect"].(map[string]any)
	if !ok {
		t.Fatalf("dialect property has type %T", tool.Tool.InputSchema.Properties["dialect"])
	}
	got, ok := prop["enum"].([]string)
	if !ok {
		t.Fatalf("dialect enum has type %T", prop["enum"])
	}
	if !reflect.DeepEqual(got, sqlkeywords.DialectNames()) {
		t.Errorf("dialect enum = %v", got)
	}
	for _, required := range tool.Tool.InputSchema.Required {
		if required == "dialect" {
			t.Error("dialect must remain optional")
		}
	}
}

func TestFormatSQL_CommentDescription(t *testing.T) {
	tool := New(DefaultConfig()).mcpSrv.GetTool("format_sql")
	if tool == nil {
		t.Fatal("format_sql tool not registered")
	}
	for _, want := range []string{"Comments are preserved", "unplaceable optimizer hints"} {
		if !strings.Contains(tool.Tool.Description, want) {
			t.Errorf("description %q missing %q", tool.Tool.Description, want)
		}
	}
}
