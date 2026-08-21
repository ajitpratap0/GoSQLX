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

package parser_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Regression: ClickHouse array/tuple element access via dot-notation (d.1, t.2)
// must parse. Previously a numeric component after '.' raised E2004.
func TestClickHouseArrayElementAccess(t *testing.T) {
	tests := []string{
		`SELECT d.1 FROM t ARRAY JOIN arr AS d`,
		`SELECT a.x FROM t ARRAY JOIN a`,
		`SELECT arr[1] FROM t`,
	}
	for _, sql := range tests {
		tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectClickHouse)
		if err != nil {
			t.Fatalf("parse %q failed: %v", sql, err)
		}
		if got := tree.SQL(); got != sql {
			t.Errorf("SQL() = %q, want %q", got, sql)
		}
	}
}
