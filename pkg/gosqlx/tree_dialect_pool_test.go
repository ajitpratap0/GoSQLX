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
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// gosqlxDialectSamples are statements accepted by the named dialect and
// rejected by the default dialect.
var gosqlxDialectSamples = []struct {
	dialect keywords.SQLDialect
	sql     string
}{
	{keywords.DialectMySQL, "SELECT `a` FROM `t` LIMIT 5, 10"},
	{keywords.DialectSQLServer, "SELECT TOP 10 [a] FROM [t]"},
	{keywords.DialectSnowflake, "SELECT a FROM t QUALIFY ROW_NUMBER() OVER (ORDER BY a) = 1"},
	{keywords.DialectClickHouse, "SELECT a FROM t PREWHERE b = 1"},
}

func checkGosqlxPoolsDefault() error {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if got := tkz.Dialect(); got != keywords.DialectPostgreSQL {
		return fmt.Errorf("pooled tokenizer dialect = %q, want %q", got, keywords.DialectPostgreSQL)
	}
	p := parser.GetParser()
	defer parser.PutParser(p)
	if got := p.Dialect(); got != "postgresql" {
		return fmt.Errorf("pooled parser Dialect() = %q, want postgresql", got)
	}
	if got := p.DialectTyped(); got != dialect.Unknown {
		return fmt.Errorf("pooled parser DialectTyped() = %v, want Unknown", got)
	}
	return nil
}

// TestParseTreeWithDialect_PoolHygiene verifies that ParseTree(WithDialect)
// and ParseWithDialect leave the shared pools in the default state (#550).
func TestParseTreeWithDialect_PoolHygiene(t *testing.T) {
	ctx := context.Background()
	for _, s := range gosqlxDialectSamples {
		t.Run(string(s.dialect), func(t *testing.T) {
			if _, err := gosqlx.ParseTree(ctx, s.sql, gosqlx.WithDialect(string(s.dialect))); err != nil {
				t.Fatalf("ParseTree(WithDialect(%s), %q) error = %v", s.dialect, s.sql, err)
			}
			if err := checkGosqlxPoolsDefault(); err != nil {
				t.Fatalf("after ParseTree(WithDialect): %v", err)
			}
			if _, err := gosqlx.ParseWithDialect(s.sql, s.dialect); err != nil {
				t.Fatalf("ParseWithDialect(%s, %q) error = %v", s.dialect, s.sql, err)
			}
			if err := checkGosqlxPoolsDefault(); err != nil {
				t.Fatalf("after ParseWithDialect: %v", err)
			}
			if _, err := gosqlx.ParseTree(ctx, s.sql); err == nil {
				t.Fatalf("default ParseTree(%q) succeeded; dialect leaked", s.sql)
			}
		})
	}
}

// TestParseTreeWithDialect_ConcurrentMixed interleaves default and
// dialect-aware gosqlx parses across goroutines; run under -race (#550).
func TestParseTreeWithDialect_ConcurrentMixed(t *testing.T) {
	const (
		goroutines = 16
		iterations = 40
	)
	ctx := context.Background()
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s := gosqlxDialectSamples[(g+i)%len(gosqlxDialectSamples)]
				if _, err := gosqlx.ParseTree(ctx, s.sql, gosqlx.WithDialect(string(s.dialect))); err != nil {
					errCh <- fmt.Errorf("ParseTree(WithDialect(%s), %q): %w", s.dialect, s.sql, err)
					return
				}
				if _, err := gosqlx.ParseWithDialect(s.sql, s.dialect); err != nil {
					errCh <- fmt.Errorf("ParseWithDialect(%s, %q): %w", s.dialect, s.sql, err)
					return
				}
				if _, err := gosqlx.ParseTree(ctx, s.sql); err == nil {
					errCh <- fmt.Errorf("default ParseTree(%q) succeeded; dialect leaked", s.sql)
					return
				}
				if _, err := gosqlx.ParseTree(ctx, "SELECT a FROM t WHERE x = 1"); err != nil {
					errCh <- fmt.Errorf("default ParseTree: %w", err)
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
