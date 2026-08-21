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

// Regression: ClickHouse SAMPLE and ORDER BY ... WITH FILL must round-trip.
// They were dropped on render (SAMPLE lost; WITH FILL skipped by the parser).
func TestClickHouseSampleAndWithFillRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{"sample_ratio", `SELECT category, count() FROM omi_reporting SAMPLE 0.1 GROUP BY category`},
		{"sample_frac", `SELECT a FROM t SAMPLE 1/10`},
		{"sample_offset", `SELECT a FROM t SAMPLE 1/10 OFFSET 2/10`},
		{"with_fill_step", `SELECT id FROM t ORDER BY id WITH FILL STEP 1`},
		{"with_fill_full", `SELECT day, count() FROM events GROUP BY day ORDER BY day WITH FILL FROM '2024-01-01' TO '2024-12-31' STEP 1`},
		{"with_fill_desc", `SELECT id FROM t ORDER BY id DESC WITH FILL STEP 1`},
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
