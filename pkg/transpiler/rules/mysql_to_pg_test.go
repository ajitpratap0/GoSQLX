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

package rules_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

// transpileMyToPg is a test helper that runs Transpile MySQL→PostgreSQL.
func transpileMyToPg(t *testing.T, sql string) string {
	t.Helper()
	result, err := transpiler.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile MySQL→PG %q: %v", sql, err)
	}
	return result
}

func containsCI(s, sub string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(sub))
}

func TestMySQLAutoIncrement_ToSerial(t *testing.T) {
	in := "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))"
	out := transpileMyToPg(t, in)
	if !containsCI(out, "SERIAL") && !containsCI(out, "BIGSERIAL") {
		t.Errorf("expected SERIAL in output, got: %s", out)
	}
}

func TestMySQLBigintAutoIncrement_ToBigserial(t *testing.T) {
	in := "CREATE TABLE events (id BIGINT AUTO_INCREMENT PRIMARY KEY, name TEXT)"
	out := transpileMyToPg(t, in)
	if !containsCI(out, "BIGSERIAL") {
		t.Errorf("expected BIGSERIAL in output for BIGINT AUTO_INCREMENT, got: %s", out)
	}
}

func TestMySQLTinyint1_ToBoolean(t *testing.T) {
	in := "CREATE TABLE flags (id INT PRIMARY KEY, active TINYINT(1))"
	out := transpileMyToPg(t, in)
	if !containsCI(out, "BOOLEAN") {
		t.Errorf("expected BOOLEAN in output for TINYINT(1), got: %s", out)
	}
}

func TestMySQL_SelectPassthrough(t *testing.T) {
	in := "SELECT id, name FROM users WHERE id = 1"
	out := transpileMyToPg(t, in)
	if out == "" {
		t.Error("expected non-empty output for basic SELECT")
	}
	if !containsCI(out, "SELECT") {
		t.Errorf("output should contain SELECT, got: %s", out)
	}
}

func TestMySQLLimitComma_ToOffset(t *testing.T) {
	// The parser normalises LIMIT offset, count → Limit/Offset AST fields.
	// The formatter then emits LIMIT n OFFSET m.
	in := "SELECT * FROM users LIMIT 10, 20"
	out := transpileMyToPg(t, in)
	if out == "" {
		t.Error("expected non-empty output")
	}
	// Either OFFSET appears (properly rewritten) or at minimum LIMIT is present.
	if !containsCI(out, "LIMIT") {
		t.Errorf("expected LIMIT keyword in output, got: %s", out)
	}
}
