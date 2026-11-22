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

package gosqlx

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

func TestLint_SelectStar(t *testing.T) {
	result, err := Lint("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Lint returned nil result")
	}

	// Should find at least L016 (SELECT *)
	found := false
	for _, v := range result.Violations {
		if v.Rule == "L016" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected L016 (SELECT *) violation, but none found")
	}
}

func TestLint_CleanSQL(t *testing.T) {
	// A well-formed query should still lint without error
	result, err := Lint("SELECT id, name FROM users WHERE active = TRUE")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("Lint returned nil result")
	}
}

func TestLint_DeleteWithoutWhere(t *testing.T) {
	result, err := Lint("DELETE FROM users")
	if err != nil {
		t.Fatalf("Lint returned unexpected error: %v", err)
	}

	found := false
	for _, v := range result.Violations {
		if v.Rule == "L011" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected L011 (DELETE without WHERE) violation, but none found")
	}
}

func TestLint_AllRulesCreated(t *testing.T) {
	rules := allRules()
	if len(rules) != 30 {
		t.Errorf("expected 30 rules, got %d", len(rules))
	}
}

func TestLint_DefaultLinterShared(t *testing.T) {
	a, b := defaultLinter(), defaultLinter()
	if a != b {
		t.Fatal("defaultLinter() returned different instances")
	}
	if got := len(a.Rules()); got != 30 {
		t.Errorf("expected 30 rules on shared linter, got %d", got)
	}
}

func TestLint_ConcurrentMatchesSerial(t *testing.T) {
	inputs := []string{
		"SELECT * FROM users",
		"DELETE FROM users",
		"select * from t into outfile '/tmp/x'",
		"select id,name from users where id in (1,2) or id = 3",
		"SELECT " + strings.Repeat("column_name, ", 11) + "last_col FROM some_table WHERE x = 1",
		"SELECT id FROM t  \n\n\n\tWHERE x = 1",
		"SELECT FROM WHERE (",
		"UPDATE t SET a = 1",
	}
	want := make([][]linter.Violation, len(inputs))
	for i, in := range inputs {
		res, err := lintTolerant(in)
		if err != nil {
			t.Fatalf("serial Lint(%q): %v", in, err)
		}
		want[i] = res.Violations
	}

	const goroutines, iterations = 32, 50
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []string
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				idx := (g + i) % len(inputs)
				res, err := lintTolerant(inputs[idx])
				if err != nil {
					mu.Lock()
					errs = append(errs, fmt.Sprintf("Lint(%q): %v", inputs[idx], err))
					mu.Unlock()
					continue
				}
				if !reflect.DeepEqual(res.Violations, want[idx]) {
					mu.Lock()
					errs = append(errs, fmt.Sprintf("Lint(%q): concurrent result differs from serial", inputs[idx]))
					mu.Unlock()
				}
			}
		}(g)
	}
	wg.Wait()
	for _, e := range errs {
		t.Error(e)
	}
}

func BenchmarkLint(b *testing.B) {
	cases := []struct {
		name string
		sql  string
	}{
		{"Tiny", "SELECT a FROM t"},
		{"Realistic", "select u.id, u.name, count(o.id) as order_count\n" +
			"from users u\n" +
			"join orders o on o.user_id = u.id\n" +
			"where u.active = true\n" +
			"  and o.created_at > '2024-01-01'\n" +
			"group by u.id, u.name\n" +
			"having count(o.id) > 5\n" +
			"order by order_count desc\n" +
			"limit 100"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Lint(tc.sql); err != nil {
					b.Fatalf("Lint: %v", err)
				}
			}
		})
	}
}

// TestLint_DeterministicL006L009 verifies L006 tie-breaking and text-fallback
// L009 ordering are stable across calls (issue #618).
func TestLint_DeterministicL006L009(t *testing.T) {
	type key struct {
		rule      string
		line, col int
	}
	tests := []struct {
		name string
		sql  string
		want []key
	}{
		{"L006 tie", "SELECT a,\n  b,\n    c\nFROM t", []key{{"L006", 3, 5}}},
		{"L009 text fallback", "SELECT users.id, orders.total\nFROM users u\nJOIN orders ON users.id = orders.uid\nWHERE (", []key{{"L009", 2, 1}, {"L009", 3, 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				res, err := lintTolerant(tt.sql)
				if err != nil {
					t.Fatalf("iteration %d: Lint: %v", i, err)
				}
				var got []key
				for _, v := range res.Violations {
					if v.Rule == "L006" || v.Rule == "L009" {
						got = append(got, key{v.Rule, v.Location.Line, v.Location.Column})
					}
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("iteration %d: got %v, want %v", i, got, tt.want)
				}
			}
		})
	}
}
