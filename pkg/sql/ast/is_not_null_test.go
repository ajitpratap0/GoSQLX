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

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// Regression: rendering `a IS NOT NULL` used to drop the NOT qualifier,
// producing `a IS NULL` and silently inverting the intended predicate.
// See BinaryExpression.SQL() — the parser stores operator "IS NULL" with
// Not=true for `IS NOT NULL`, but the renderer ignored the Not flag.
func TestRenderIsNotNullPreservesNot(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want string
	}{
		{"is null", "SELECT * FROM users WHERE email IS NULL", "SELECT * FROM users WHERE email IS NULL"},
		{"is not null", "SELECT * FROM users WHERE email IS NOT NULL", "SELECT * FROM users WHERE email IS NOT NULL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := gosqlx.Parse(tt.sql)
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", tt.sql, err)
			}
			if got := tree.SQL(); got != tt.want {
				t.Errorf("SQL() = %q, want %q", got, tt.want)
			}
		})
	}
}
