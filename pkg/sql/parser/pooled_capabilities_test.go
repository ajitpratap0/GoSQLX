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
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// pooledCaps fetches a pooled parser, reads its capabilities and typed
// dialect, and returns the parser to the pool.
func pooledCaps() (dialect.Capabilities, dialect.Dialect) {
	p := GetParser()
	defer PutParser(p)
	return p.Capabilities(), p.dialectTyped
}

// TestPooledParserCapabilities_MatchNewParser is the regression test for
// issue #590: a pooled default parser must be state-identical to NewParser().
func TestPooledParserCapabilities_MatchNewParser(t *testing.T) {
	fresh := NewParser()
	want := fresh.Capabilities()

	for i := 0; i < 3; i++ {
		got, typed := pooledCaps()
		if got != want {
			t.Fatalf("iteration %d: pooled Capabilities() = %+v, want %+v", i, got, want)
		}
		if typed != fresh.dialectTyped {
			t.Fatalf("iteration %d: pooled dialectTyped = %v, want %v", i, typed, fresh.dialectTyped)
		}
	}
	if want != dialect.Unknown.Capabilities() {
		t.Fatalf("default parser capabilities differ from dialect.Unknown.Capabilities()")
	}
}

// TestPooledParserCapabilities_RestoredAfterWithDialect verifies pool reuse
// after a dialect-specific parse restores the defaults.
func TestPooledParserCapabilities_RestoredAfterWithDialect(t *testing.T) {
	want := NewParser().Capabilities()

	dialects := []keywords.SQLDialect{
		keywords.DialectPostgreSQL,
		keywords.DialectMySQL,
		keywords.DialectSnowflake,
		keywords.DialectClickHouse,
	}
	for _, d := range dialects {
		p := GetParser()
		p.ApplyOptions(WithDialect(string(d)))
		if p.dialectTyped == dialect.Unknown {
			t.Fatalf("WithDialect(%s) did not change typed dialect", d)
		}
		PutParser(p)

		got, typed := pooledCaps()
		if got != want {
			t.Fatalf("after %s: pooled Capabilities() = %+v, want %+v", d, got, want)
		}
		if typed != dialect.Unknown {
			t.Fatalf("after %s: dialectTyped = %v, want Unknown", d, typed)
		}
	}
}

// TestPooledParserCapabilities_Concurrent hammers GetParser/PutParser with
// alternating dialects; every parser obtained must start in default state.
// Meaningful under -race.
func TestPooledParserCapabilities_Concurrent(t *testing.T) {
	want := NewParser().Capabilities()
	dialects := []string{"postgresql", "mysql", "snowflake", "clickhouse", "sqlite", ""}

	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				p := GetParser()
				if p.Capabilities() != want || p.dialectTyped != dialect.Unknown {
					select {
					case errs <- "pooled parser not in default state":
					default:
					}
					PutParser(p)
					return
				}
				if d := dialects[(g+i)%len(dialects)]; d != "" {
					p.ApplyOptions(WithDialect(d))
				}
				PutParser(p)
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
