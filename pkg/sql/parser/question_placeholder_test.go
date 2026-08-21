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

// Regression: `?` positional placeholders (JDBC) must parse and round-trip.
// Previously `WHERE a = ?` failed with "unexpected token: QUESTION".
// Postgres JSON existence `data ? 'key'` is untouched (binary-operator path).
func TestQuestionPlaceholder(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"single", `SELECT * FROM omi_reporting WHERE category = ?`},
		{"multiple", `SELECT * FROM omi_reporting WHERE a > ? AND b < ? AND category IN (?, ?)`},
		{"in having group", `SELECT category, count() FROM omi_reporting WHERE next_verification_date >= ? GROUP BY category`},
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

// TestQuestionJSONOperator guards against breaking Postgres JSON existence
// operator `?` when treating `?` as a placeholder.
func TestQuestionJSONOperatorStillWorks(t *testing.T) {
	sql := `SELECT * FROM users WHERE data ? 'key'`
	// PostgreSQL dialect.
	tree, err := gosqlx.ParseWithDialect(sql, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("parse json operator: %v", err)
	}
	if got := tree.SQL(); got != sql {
		t.Errorf("SQL() = %q, want %q", got, sql)
	}
}
