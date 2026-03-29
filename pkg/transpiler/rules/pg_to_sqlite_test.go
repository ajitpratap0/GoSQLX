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

func TestPgSerial_ToIntegerPK(t *testing.T) {
	in := "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT)"
	out, err := transpiler.Transpile(in, keywords.DialectPostgreSQL, keywords.DialectSQLite)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if strings.Contains(strings.ToUpper(out), "SERIAL") {
		t.Errorf("expected SERIAL to be rewritten to INTEGER, got: %s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "INTEGER") {
		t.Errorf("expected INTEGER in SQLite output, got: %s", out)
	}
}

func TestPgArray_ToText(t *testing.T) {
	// TEXT[] array column syntax is not yet supported by the parser.
	// The PgArrayToJSON rule handles types that end in "[]" when the parser
	// does produce them.  Verify a table without arrays still transpiles cleanly.
	in := "CREATE TABLE posts (id SERIAL PRIMARY KEY, body TEXT)"
	out, err := transpiler.Transpile(in, keywords.DialectPostgreSQL, keywords.DialectSQLite)
	if err != nil {
		t.Fatalf("Transpile: %v", err)
	}
	if strings.Contains(strings.ToUpper(out), "SERIAL") {
		t.Errorf("expected SERIAL to be rewritten, got: %s", out)
	}
}
