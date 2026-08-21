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

// Regression for #519: parenthesized expressions must round-trip unchanged.
// Previously the `ParenthesizedExpression` node did not exist, so parentheses
// were dropped during parsing and AND/OR precedence silently changed on render:
//   (a OR b) AND c  →  a OR b AND c
func TestParenthesizedExpressionRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"or group and",
			`SELECT * FROM t WHERE (category = 'si' OR category = 'eev') AND snapshot_date = today()`},
		{"and group",
			`SELECT * FROM t WHERE a AND (b OR c)`},
		{"nested parens",
			`SELECT * FROM t WHERE ((a AND b) OR c) AND d`},
		{"join condition parens",
			`SELECT * FROM t WHERE name = 'Vasya' AND (user_id = account.id) GROUP BY position`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.ParseWithDialect(tt.sql, keywords.DialectClickHouse)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if got := tree.SQL(); got != tt.sql {
				t.Errorf("SQL() = %q, want %q", got, tt.sql)
			}
		})
	}
}
