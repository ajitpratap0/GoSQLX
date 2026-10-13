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

package formatter

import (
	"strings"
	"testing"
)

func TestFormat_BasicStatements(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple select", "SELECT id, name FROM users", false},
		{"select with where", "SELECT * FROM users WHERE id = 1", false},
		{"insert", "INSERT INTO users (id, name) VALUES (1, 'test')", false},
		{"update", "UPDATE users SET name = 'new' WHERE id = 1", false},
		{"delete", "DELETE FROM users WHERE id = 1", false},
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"invalid SQL", "SELEC BOGUS FROM", true},
	}

	f := New(Options{IndentSize: 2})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := f.Format(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Format() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.input != "" && tt.input != "   " && result == "" {
				t.Error("Format() returned empty string for valid non-empty SQL")
			}
		})
	}
}

func TestFormatString(t *testing.T) {
	result, err := FormatString("SELECT 1")
	if err != nil {
		t.Fatalf("FormatString() error = %v", err)
	}
	if result == "" {
		t.Error("FormatString() returned empty")
	}
}

func TestNew_DefaultIndent(t *testing.T) {
	f := New(Options{})
	if f.opts.IndentSize != 2 {
		t.Errorf("default IndentSize = %d, want 2", f.opts.IndentSize)
	}
}

func TestFormat_UppercaseOutput(t *testing.T) {
	f := New(Options{Uppercase: true})
	result, err := f.Format("select id from users")
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if !strings.Contains(result, "SELECT") {
		t.Errorf("Expected uppercase SELECT in output, got: %s", result)
	}
	if !strings.Contains(result, "FROM") {
		t.Errorf("Expected uppercase FROM in output, got: %s", result)
	}
}

func TestFormat_CompactOutput(t *testing.T) {
	f := New(Options{Compact: true})
	result, err := f.Format("SELECT id, name FROM users WHERE id = 1")
	if err != nil {
		t.Fatalf("Format() error = %v", err)
	}
	if strings.Contains(result, "\n") {
		t.Errorf("Compact mode should not contain newlines, got: %s", result)
	}
}

// TestFormat_InsertWithCTE_Issue537 checks that the compact formatter keeps
// the WITH clause of INSERT ... SELECT in both positions and is idempotent.
func TestFormat_InsertWithCTE_Issue537(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "inner WITH after column list",
			input: "INSERT INTO test(a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
			want:  "INSERT INTO test (a, b) WITH main AS (SELECT a, b FROM src) SELECT a, b FROM main",
		},
		{
			name:  "leading WITH before INSERT",
			input: "WITH main AS (SELECT a, b FROM src) INSERT INTO test(a, b) SELECT a, b FROM main",
			want:  "WITH main AS (SELECT a, b FROM src) INSERT INTO test (a, b) SELECT a, b FROM main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(Options{Compact: true})
			out, err := f.Format(tt.input)
			if err != nil {
				t.Fatalf("Format(%q): %v", tt.input, err)
			}
			if out != tt.want {
				t.Fatalf("Format(%q):\n got: %s\nwant: %s", tt.input, out, tt.want)
			}
			again, err := f.Format(out)
			if err != nil {
				t.Fatalf("Format(%q) second pass: %v", out, err)
			}
			if again != out {
				t.Errorf("Format not idempotent:\n first: %s\nsecond: %s", out, again)
			}
		})
	}
}

// TestFormat_WithCTEChainedSetOperations checks that the compact formatter
// keeps the WITH clause (exactly once) for CTE queries with chained set
// operators, at top level and under INSERT, and is idempotent.
func TestFormat_WithCTEChainedSetOperations(t *testing.T) {
	inputs := []string{
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION SELECT 2 UNION SELECT 3",
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION ALL SELECT 2 UNION ALL SELECT 3",
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c INTERSECT SELECT 2 INTERSECT SELECT 3",
		"WITH c AS (SELECT 1 AS a) SELECT a FROM c EXCEPT SELECT 2 EXCEPT SELECT 3",
		"INSERT INTO t (a) WITH c AS (SELECT 1 AS a) SELECT a FROM c UNION SELECT 2 UNION SELECT 3",
		"INSERT INTO t (a) WITH c AS (SELECT 1 AS a) SELECT a FROM c EXCEPT SELECT 2 EXCEPT SELECT 3",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			f := New(Options{Compact: true})
			out, err := f.Format(in)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if n := strings.Count(out, "WITH "); n != 1 {
				t.Fatalf("output has %d WITH clauses, want 1: %s", n, out)
			}
			if !strings.Contains(out, "WITH c AS (SELECT 1 AS a)") {
				t.Errorf("output lost the CTE: %s", out)
			}
			again, err := f.Format(out)
			if err != nil {
				t.Fatalf("second pass: %v", err)
			}
			if again != out {
				t.Errorf("not idempotent:\n first: %s\nsecond: %s", out, again)
			}
		})
	}
}
