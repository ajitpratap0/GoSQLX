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

func TestPgSerial_ToAutoIncrement(t *testing.T) {
	in := "CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT)"
	out, err := transpiler.Transpile(in, keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if !strings.Contains(strings.ToUpper(out), "AUTO_INCREMENT") {
		t.Errorf("expected AUTO_INCREMENT in output, got: %s", out)
	}
}

func TestPgBigserial_ToAutoIncrement(t *testing.T) {
	in := "CREATE TABLE events (id BIGSERIAL PRIMARY KEY, name TEXT)"
	out, err := transpiler.Transpile(in, keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if !strings.Contains(strings.ToUpper(out), "AUTO_INCREMENT") {
		t.Errorf("expected AUTO_INCREMENT in output, got: %s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "BIGINT") {
		t.Errorf("expected BIGINT in output for BIGSERIAL, got: %s", out)
	}
}

func TestPgILike_ToLower(t *testing.T) {
	in := "SELECT * FROM users WHERE name ILIKE '%alice%'"
	out, err := transpiler.Transpile(in, keywords.DialectPostgreSQL, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if strings.Contains(strings.ToUpper(out), "ILIKE") {
		t.Errorf("expected ILIKE to be rewritten in MySQL output, got: %s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "LOWER") {
		t.Errorf("expected LOWER() wrapper in MySQL output, got: %s", out)
	}
}
