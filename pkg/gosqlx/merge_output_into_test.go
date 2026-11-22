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

package gosqlx

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// The formatter keeps the INTO target of a SQL Server MERGE ... OUTPUT.
func TestFormatMergeOutputInto(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{"table variable",
			"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE OUTPUT deleted.id INTO @t",
			"INTO @t"},
		{"column list",
			"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE OUTPUT deleted.id INTO dbo.log (id)",
			"INTO dbo.log (id)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := ParseWithDialect(tc.sql, keywords.DialectSQLServer)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			out := FormatAST(tree)
			if !strings.Contains(out, tc.want) {
				t.Errorf("formatted output %q does not contain %q", out, tc.want)
			}
			tree2, err := ParseWithDialect(out, keywords.DialectSQLServer)
			if err != nil {
				t.Fatalf("reparse %q: %v", out, err)
			}
			if out2 := FormatAST(tree2); out2 != out {
				t.Errorf("not idempotent:\n%q\n%q", out, out2)
			}
		})
	}
}
