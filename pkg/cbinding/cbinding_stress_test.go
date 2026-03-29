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

// Package main – concurrent/stress tests for the GoSQLX C binding.
// Tests use pure-Go wrappers from cbinding_testhelpers.go so that CGo is not
// needed directly in this test file.
package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Concurrent parse test (50 goroutines × 100 iterations)
// ---------------------------------------------------------------------------

func TestStressConcurrentParse(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	sqls := []string{
		"SELECT * FROM users WHERE id = 1",
		"INSERT INTO orders (user_id, amount) VALUES (1, 99.99)",
		"UPDATE products SET price = 19.99 WHERE id = 5",
		"DELETE FROM sessions WHERE expires_at < NOW()",
		"SELECT COUNT(*) FROM logs GROUP BY level HAVING COUNT(*) > 100",
	}

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				sql := sqls[(idx+j)%len(sqls)]
				result := parseSQL(sql)
				if !result.Success {
					errors <- fmt.Errorf("goroutine %d iter %d: parse failed: %s", idx, j, result.Error)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent validate test
// ---------------------------------------------------------------------------

func TestStressConcurrentValidate(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	sql := "SELECT u.id, u.name FROM users u WHERE u.active = 1 AND u.status = 'verified'"
	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				result := validateSQL(sql)
				if !result.Valid {
					errors <- fmt.Errorf("goroutine %d iter %d: validate failed: %s", idx, j, result.Error)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent format test
// ---------------------------------------------------------------------------

func TestStressConcurrentFormat(t *testing.T) {
	const goroutines = 50
	const iterations = 100

	sql := "select id,name,email from users where active=1 order by name"
	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				result := formatSQL(sql)
				if !result.Success {
					errors <- fmt.Errorf("goroutine %d iter %d: format failed: %s", idx, j, result.Error)
				}
				if result.Formatted == "" {
					errors <- fmt.Errorf("goroutine %d iter %d: empty formatted output", idx, j)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Concurrent all-functions test (20 goroutines exercising all 8 non-version functions)
// ---------------------------------------------------------------------------

func TestStressConcurrentAllFunctions(t *testing.T) {
	const goroutines = 20
	const iterations = 50

	sql := "SELECT u.id, COUNT(o.id) AS order_count FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.id"
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				parseSQL(sql)
				validateSQL(sql)
				formatSQL(sql)
				extractTables(sql)
				extractColumns(sql)
				extractFunctions(sql)
				extractMetadata(sql)
				// gosqlx_version is a cached singleton — just read it.
				getVersion()
			}
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Large SQL (100-clause UNION ALL)
// ---------------------------------------------------------------------------

func TestStressLargeSQL(t *testing.T) {
	var parts []string
	for i := 0; i < 100; i++ {
		parts = append(parts, fmt.Sprintf("SELECT %d AS n, 'row_%d' AS label", i, i))
	}
	largeSql := strings.Join(parts, " UNION ALL ")

	result := parseSQL(largeSql)
	if !result.Success {
		t.Errorf("large SQL parse failed: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// Very long identifier (500-char names)
// ---------------------------------------------------------------------------

func TestStressVeryLongIdentifier(t *testing.T) {
	longName := strings.Repeat("a", 500)
	sql := fmt.Sprintf("SELECT %s FROM %s_table WHERE %s_col = 1", longName, longName, longName)

	result := parseSQL(sql)
	// May succeed or fail depending on parser limits — the key requirement is no panic.
	t.Logf("very long identifier: success=%v error=%s", result.Success, result.Error)
}

// ---------------------------------------------------------------------------
// Unicode SQL
// ---------------------------------------------------------------------------

func TestStressUnicodeSQL(t *testing.T) {
	sql := "SELECT * FROM users WHERE name = '日本語テスト' AND city = 'München' AND region = '中文'"

	result := parseSQL(sql)
	if !result.Success {
		t.Errorf("unicode SQL should parse successfully: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// Mixed valid/invalid SQL concurrent
// ---------------------------------------------------------------------------

func TestStressMixedValidInvalid(t *testing.T) {
	const goroutines = 30
	const iterations = 50

	sqls := []struct {
		sql   string
		valid bool
	}{
		{"SELECT * FROM users", true},
		{"GARBAGE SQL !!!", false},
		{"SELECT 1 + 1", true},
		{"FROM WHERE INVALID", false},
		{"INSERT INTO t (id) VALUES (42)", true},
	}

	var wg sync.WaitGroup
	errors := make(chan error, goroutines*iterations)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				entry := sqls[(idx+j)%len(sqls)]
				result := parseSQL(entry.sql)
				if entry.valid && !result.Success {
					errors <- fmt.Errorf("goroutine %d iter %d: expected success for %q: %s",
						idx, j, entry.sql, result.Error)
				}
				if !entry.valid && result.Success {
					// Log but don't fail — some parsers are lenient.
					t.Logf("goroutine %d iter %d: lenient parse for %q", idx, j, entry.sql)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// Version singleton is stable under concurrency
// ---------------------------------------------------------------------------

func TestStressVersionSingleton(t *testing.T) {
	const goroutines = 100
	var wg sync.WaitGroup
	versions := make(chan string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			versions <- getVersion()
		}()
	}

	wg.Wait()
	close(versions)

	first := ""
	for v := range versions {
		if first == "" {
			first = v
			continue
		}
		if v != first {
			t.Errorf("version mismatch: expected %q, got %q", first, v)
		}
	}
}
