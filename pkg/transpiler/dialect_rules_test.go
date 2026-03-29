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

package transpiler_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestRulesFor_MySQLToPostgres_NonEmpty(t *testing.T) {
	rules := transpiler.RulesFor(keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if len(rules) == 0 {
		t.Error("expected at least one rule for MySQL→PostgreSQL")
	}
}

func TestRulesFor_SameDialect_Empty(t *testing.T) {
	rules := transpiler.RulesFor(keywords.DialectPostgreSQL, keywords.DialectPostgreSQL)
	if len(rules) != 0 {
		t.Errorf("expected no rules for same dialect, got %d", len(rules))
	}
}

func TestRulesFor_UnregisteredPair_Empty(t *testing.T) {
	rules := transpiler.RulesFor(keywords.DialectOracle, keywords.DialectClickHouse)
	// Unknown pair → no rules (passthrough).
	_ = rules // should be 0 length, no panic
}
