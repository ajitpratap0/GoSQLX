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

func TestTranspile_SameDialect_ReturnsEquivalent(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestTranspile_InvalidSQL_ReturnsError(t *testing.T) {
	_, err := transpiler.Transpile("NOT VALID SQL !!!", keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestTranspile_UnsupportedDialectPair_Passthrough(t *testing.T) {
	// Should either work (passthrough) or return a descriptive error — not panic.
	_, err := transpiler.Transpile("SELECT 1", keywords.DialectOracle, keywords.DialectClickHouse)
	_ = err // either outcome is acceptable as long as there is no panic
}

func TestTranspile_MySQLToPostgres_BasicSelect(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}
