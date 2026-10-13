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

package parser

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// dialectSamples maps each supported dialect to a statement that parses in
// that dialect. Where possible the statement is rejected by the default
// (PostgreSQL) pooled path, so a leaked or missing dialect is observable.
var dialectSamples = []struct {
	dialect keywords.SQLDialect
	sql     string
	// defaultRejects is true when ParseBytes (default dialect) must reject sql.
	defaultRejects bool
}{
	{keywords.DialectPostgreSQL, "SELECT a FROM t WHERE b ILIKE 'x%'", false},
	{keywords.DialectMySQL, "SELECT `a` FROM `t` LIMIT 5, 10", true},
	{keywords.DialectMariaDB, "SELECT `a` FROM `t` LIMIT 5, 10", true},
	{keywords.DialectSQLServer, "SELECT TOP 10 [a] FROM [t]", true},
	{keywords.DialectOracle, "SELECT a FROM t WHERE b = :1", true},
	{keywords.DialectSQLite, "SELECT a FROM t LIMIT 1", false},
	{keywords.DialectSnowflake, "SELECT a FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY a) = 1", true},
	{keywords.DialectClickHouse, "SELECT a FROM t PREWHERE b = 1", true},
}

// defaultParserCapabilities is what Reset leaves behind (zero value).
var defaultParserCapabilities = (&Parser{}).Capabilities()

// checkPoolsDefault fetches a tokenizer and a parser from the pools and
// reports any non-default dialect state. sync.Pool may hand back a different
// instance than the one just returned; any instance must be default.
func checkPoolsDefault() error {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if got := tkz.Dialect(); got != keywords.DialectPostgreSQL {
		return fmt.Errorf("pooled tokenizer dialect = %q, want %q", got, keywords.DialectPostgreSQL)
	}

	p := GetParser()
	defer PutParser(p)
	if got := p.Dialect(); got != "postgresql" {
		return fmt.Errorf("pooled parser Dialect() = %q, want %q", got, "postgresql")
	}
	if got := p.DialectTyped(); got != dialect.Unknown {
		return fmt.Errorf("pooled parser DialectTyped() = %v, want Unknown", got)
	}
	if got := p.Capabilities(); got != defaultParserCapabilities {
		return fmt.Errorf("pooled parser Capabilities() = %+v, want zero value", got)
	}
	if p.strict {
		return fmt.Errorf("pooled parser strict = true, want false")
	}
	return nil
}

// TestDialectEntryPoints_PoolHygiene verifies that ParseBytesWithDialect and
// ValidateBytesWithDialect return their pooled tokenizer and parser in the
// default state for every dialect (#550).
func TestDialectEntryPoints_PoolHygiene(t *testing.T) {
	for _, s := range dialectSamples {
		t.Run(string(s.dialect), func(t *testing.T) {
			tree, err := ParseBytesWithDialect([]byte(s.sql), s.dialect)
			if err != nil {
				t.Fatalf("ParseBytesWithDialect(%q) error = %v", s.sql, err)
			}
			ast.ReleaseAST(tree)
			if err := checkPoolsDefault(); err != nil {
				t.Fatalf("after ParseBytesWithDialect: %v", err)
			}

			if err := ValidateBytesWithDialect([]byte(s.sql), s.dialect); err != nil {
				t.Fatalf("ValidateBytesWithDialect(%q) error = %v", s.sql, err)
			}
			if err := checkPoolsDefault(); err != nil {
				t.Fatalf("after ValidateBytesWithDialect: %v", err)
			}

			// Error paths must restore the pools too.
			_, _ = ParseBytesWithDialect([]byte("SELECT FROM WHERE ("), s.dialect)
			if err := checkPoolsDefault(); err != nil {
				t.Fatalf("after failed ParseBytesWithDialect: %v", err)
			}
			_ = ValidateBytesWithDialect([]byte("SELECT 'unterminated"), s.dialect)
			if err := checkPoolsDefault(); err != nil {
				t.Fatalf("after failed ValidateBytesWithDialect: %v", err)
			}

			if s.defaultRejects {
				if tree, err := ParseBytes([]byte(s.sql)); err == nil {
					ast.ReleaseAST(tree)
					t.Fatalf("default ParseBytes(%q) succeeded after a %s parse; dialect leaked", s.sql, s.dialect)
				}
			}
		})
	}
}

// TestDialectEntryPoints_ConcurrentMixed interleaves default and
// dialect-aware parses and validations across goroutines. Run under -race it
// checks that pooling the dialect entry points introduces no data races and
// no dialect leakage between concurrent callers (#550).
func TestDialectEntryPoints_ConcurrentMixed(t *testing.T) {
	const (
		goroutines = 32
		iterations = 50
	)
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s := dialectSamples[(g+i)%len(dialectSamples)]

				tree, err := ParseBytesWithDialect([]byte(s.sql), s.dialect)
				if err != nil {
					errCh <- fmt.Errorf("ParseBytesWithDialect(%s, %q): %w", s.dialect, s.sql, err)
					return
				}
				if len(tree.Statements) != 1 {
					errCh <- fmt.Errorf("ParseBytesWithDialect(%s, %q): %d statements, want 1", s.dialect, s.sql, len(tree.Statements))
					return
				}
				ast.ReleaseAST(tree)

				if err := ValidateBytesWithDialect([]byte(s.sql), s.dialect); err != nil {
					errCh <- fmt.Errorf("ValidateBytesWithDialect(%s, %q): %w", s.dialect, s.sql, err)
					return
				}

				// A default-path caller must never observe another
				// goroutine's dialect.
				if s.defaultRejects {
					if tree, err := ParseBytes([]byte(s.sql)); err == nil {
						ast.ReleaseAST(tree)
						errCh <- fmt.Errorf("default ParseBytes(%q) succeeded; dialect leaked", s.sql)
						return
					}
				}
				if err := checkPoolsDefault(); err != nil {
					errCh <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestParseBytesWithDialect_AllocParity pins that the pooled dialect-aware
// entry points allocate no more than the default pooled ParseBytes for the
// same input (#550). Before #550 each call rebuilt a keyword table and
// allocated a fresh tokenizer and parser (~40 extra allocations).
func TestParseBytesWithDialect_AllocParity(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	input := []byte("SELECT u.id, u.name FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 100 ORDER BY u.id LIMIT 50")

	parseDefault := func() {
		tree, err := ParseBytes(input)
		if err != nil {
			t.Fatal(err)
		}
		ast.ReleaseAST(tree)
	}
	// Warm the pools.
	parseDefault()
	want := testing.AllocsPerRun(200, parseDefault)

	for _, d := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectMySQL} {
		parse := func() {
			tree, err := ParseBytesWithDialect(input, d)
			if err != nil {
				t.Fatal(err)
			}
			ast.ReleaseAST(tree)
		}
		parse()
		if got := testing.AllocsPerRun(200, parse); got != want {
			t.Errorf("ParseBytesWithDialect(%s) allocs = %v, ParseBytes allocs = %v; want equal", d, got, want)
		}

		validate := func() {
			if err := ValidateBytesWithDialect(input, d); err != nil {
				t.Fatal(err)
			}
		}
		validate()
		if got := testing.AllocsPerRun(200, validate); got > want {
			t.Errorf("ValidateBytesWithDialect(%s) allocs = %v, want <= ParseBytes allocs %v", d, got, want)
		}
	}
}
