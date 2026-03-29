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

package gosqlx_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestGoSQLX_Transpile_BasicSelect(t *testing.T) {
	sql := "SELECT id, name FROM users WHERE id = 1"
	result, err := gosqlx.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
	if !strings.Contains(strings.ToUpper(result), "SELECT") {
		t.Errorf("result should contain SELECT, got: %s", result)
	}
}

func TestGoSQLX_Transpile_InvalidSQL(t *testing.T) {
	_, err := gosqlx.Transpile("NOT VALID", keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestGoSQLX_Transpile_AutoIncrementToSerial(t *testing.T) {
	sql := "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255))"
	result, err := gosqlx.Transpile(sql, keywords.DialectMySQL, keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if !strings.Contains(strings.ToUpper(result), "SERIAL") {
		t.Errorf("expected SERIAL in output, got: %s", result)
	}
}
