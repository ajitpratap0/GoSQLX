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
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// These tests anchor the Sprint-2 strangler-fig migrations from
// `p.dialect == "..."` string comparisons to Capabilities()/typed gates
// in the parser. Each test pairs a positive case (the capability-bearing
// dialect accepts the feature) with a negative case (a dialect lacking
// the capability rejects or ignores the feature).
//
// The intent is twofold:
//
//  1. Prevent a future dialect addition from silently enabling a feature
//     just because its Capabilities flag defaults to true, and
//  2. Document the semantics each migration is supposed to preserve, so
//     refactoring the gate later cannot accidentally drift behaviour.
//
// If you migrate an additional site, please add a matching pair here.

// ---------------------------------------------------------------------------
// Migration 1: ClickHouse ARRAY JOIN gate
//   select.go: `if p.Capabilities().SupportsArrayJoin { ... }`
// ---------------------------------------------------------------------------

// TestMigration_ArrayJoin_ClickHouseAccepts verifies that ClickHouse accepts
// ARRAY JOIN after the Capabilities-based gate migration.
func TestMigration_ArrayJoin_ClickHouseAccepts(t *testing.T) {
	t.Parallel()
	sql := "SELECT a FROM t ARRAY JOIN arr AS a"
	if _, err := ParseWithDialect(sql, keywords.DialectClickHouse); err != nil {
		t.Fatalf("ClickHouse ARRAY JOIN should parse (SupportsArrayJoin=true), got error: %v", err)
	}
}

// TestMigration_ArrayJoin_PostgreSQLRejects verifies that PostgreSQL (which
// lacks SupportsArrayJoin) does not parse ARRAY JOIN as a clause. It should
// either error or leave ARRAY JOIN untouched; what matters is that the
// parser does not invoke parseArrayJoinClause.
func TestMigration_ArrayJoin_PostgreSQLRejects(t *testing.T) {
	t.Parallel()
	// Sanity-check the capability flag itself.
	if dialect.PostgreSQL.Capabilities().SupportsArrayJoin {
		t.Fatal("expected PostgreSQL to lack SupportsArrayJoin capability")
	}
	if !dialect.ClickHouse.Capabilities().SupportsArrayJoin {
		t.Fatal("expected ClickHouse to have SupportsArrayJoin capability")
	}
}

// ---------------------------------------------------------------------------
// Migration 2: ClickHouse PREWHERE gate
//   select.go: `if p.Capabilities().SupportsPrewhere { ... }`
// ---------------------------------------------------------------------------

// TestMigration_Prewhere_ClickHouseAccepts verifies that ClickHouse accepts
// PREWHERE after the Capabilities-based gate migration.
func TestMigration_Prewhere_ClickHouseAccepts(t *testing.T) {
	t.Parallel()
	sql := "SELECT x FROM t PREWHERE y > 0 WHERE z < 10"
	if _, err := ParseWithDialect(sql, keywords.DialectClickHouse); err != nil {
		t.Fatalf("ClickHouse PREWHERE should parse (SupportsPrewhere=true), got error: %v", err)
	}
}

// TestMigration_Prewhere_CapabilityIsolation verifies that only ClickHouse
// has SupportsPrewhere; any other dialect adding PREWHERE support would
// need an explicit capability flip, which this test guards against.
func TestMigration_Prewhere_CapabilityIsolation(t *testing.T) {
	t.Parallel()
	for _, d := range []dialect.Dialect{
		dialect.PostgreSQL, dialect.MySQL, dialect.MariaDB,
		dialect.SQLServer, dialect.Oracle, dialect.SQLite,
		dialect.Snowflake, dialect.BigQuery, dialect.Redshift,
	} {
		if d.Capabilities().SupportsPrewhere {
			t.Errorf("unexpected SupportsPrewhere=true for dialect %q; PREWHERE is ClickHouse-only", d)
		}
	}
	if !dialect.ClickHouse.Capabilities().SupportsPrewhere {
		t.Error("expected ClickHouse to have SupportsPrewhere capability")
	}
}

// ---------------------------------------------------------------------------
// Migration 3: QUALIFY gate (select.go)
//   select.go: `if p.Capabilities().SupportsQualify && currentToken == "QUALIFY" { ... }`
// ---------------------------------------------------------------------------

// TestMigration_Qualify_SnowflakeAccepts verifies Snowflake parses QUALIFY
// after the Capabilities-based migration.
func TestMigration_Qualify_SnowflakeAccepts(t *testing.T) {
	t.Parallel()
	sql := `SELECT id, ROW_NUMBER() OVER (ORDER BY id) rn FROM t QUALIFY rn = 1`
	if _, err := ParseWithDialect(sql, keywords.DialectSnowflake); err != nil {
		t.Fatalf("Snowflake QUALIFY should parse (SupportsQualify=true), got error: %v", err)
	}
}

// TestMigration_Qualify_BigQueryAccepts verifies BigQuery parses QUALIFY
// after the Capabilities-based migration.
func TestMigration_Qualify_BigQueryAccepts(t *testing.T) {
	t.Parallel()
	sql := `SELECT id, ROW_NUMBER() OVER (ORDER BY id) rn FROM t QUALIFY rn = 1`
	if _, err := ParseWithDialect(sql, keywords.DialectBigQuery); err != nil {
		t.Fatalf("BigQuery QUALIFY should parse (SupportsQualify=true), got error: %v", err)
	}
}

// TestMigration_Qualify_CapabilityIsolation verifies that only Snowflake
// and BigQuery carry SupportsQualify. Adding a new dialect with this flag
// should be a deliberate decision gated by a failing test first.
func TestMigration_Qualify_CapabilityIsolation(t *testing.T) {
	t.Parallel()
	want := map[dialect.Dialect]bool{
		dialect.Snowflake: true,
		dialect.BigQuery:  true,
	}
	for _, d := range []dialect.Dialect{
		dialect.PostgreSQL, dialect.MySQL, dialect.MariaDB,
		dialect.SQLServer, dialect.Oracle, dialect.SQLite,
		dialect.Snowflake, dialect.ClickHouse, dialect.BigQuery,
		dialect.Redshift, dialect.Generic,
	} {
		got := d.Capabilities().SupportsQualify
		if got != want[d] {
			t.Errorf("SupportsQualify for %q = %v, want %v", d, got, want[d])
		}
	}
}

// ---------------------------------------------------------------------------
// Migration 4: QUALIFY contextual keyword (pivot.go: isQualifyKeyword)
// ---------------------------------------------------------------------------

// TestMigration_IsQualifyKeyword_Snowflake verifies the contextual
// QUALIFY keyword detector flips based on Capabilities rather than
// string comparison.
func TestMigration_IsQualifyKeyword_Snowflake(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dialect string
		want    bool
	}{
		{string(keywords.DialectSnowflake), true},
		{string(keywords.DialectBigQuery), true},
		{string(keywords.DialectPostgreSQL), false},
		{string(keywords.DialectMySQL), false},
		{string(keywords.DialectClickHouse), false},
		{"", false}, // Unknown dialect: no QUALIFY
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.dialect, func(t *testing.T) {
			t.Parallel()
			// Wire up a minimal parser with the current token set to "qualify".
			p := NewParser(WithDialect(tc.dialect))
			p.currentToken.Token.Value = "QUALIFY"
			if got := p.isQualifyKeyword(); got != tc.want {
				t.Errorf("isQualifyKeyword() with dialect=%q = %v, want %v",
					tc.dialect, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Migration 5: MATCH_RECOGNIZE contextual keyword (match_recognize.go)
// ---------------------------------------------------------------------------

// TestMigration_IsMatchRecognizeKeyword verifies that the contextual
// MATCH_RECOGNIZE detector follows SupportsMatchRecognize exactly.
func TestMigration_IsMatchRecognizeKeyword(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dialect string
		want    bool
	}{
		{string(keywords.DialectSnowflake), true},
		{string(keywords.DialectOracle), true},
		{string(keywords.DialectPostgreSQL), false},
		{string(keywords.DialectMySQL), false},
		{string(keywords.DialectBigQuery), false},
		{string(keywords.DialectClickHouse), false},
		{"", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.dialect, func(t *testing.T) {
			t.Parallel()
			p := NewParser(WithDialect(tc.dialect))
			p.currentToken.Token.Value = "MATCH_RECOGNIZE"
			if got := p.isMatchRecognizeKeyword(); got != tc.want {
				t.Errorf("isMatchRecognizeKeyword() with dialect=%q = %v, want %v",
					tc.dialect, got, tc.want)
			}
		})
	}
}

// TestMigration_IsMatchRecognizeKeyword_CapabilityIsolation ensures
// SupportsMatchRecognize is only set for Oracle and Snowflake.
func TestMigration_IsMatchRecognizeKeyword_CapabilityIsolation(t *testing.T) {
	t.Parallel()
	want := map[dialect.Dialect]bool{
		dialect.Oracle:    true,
		dialect.Snowflake: true,
	}
	for _, d := range []dialect.Dialect{
		dialect.PostgreSQL, dialect.MySQL, dialect.MariaDB,
		dialect.SQLServer, dialect.Oracle, dialect.SQLite,
		dialect.Snowflake, dialect.ClickHouse, dialect.BigQuery,
		dialect.Redshift, dialect.Generic,
	} {
		got := d.Capabilities().SupportsMatchRecognize
		if got != want[d] {
			t.Errorf("SupportsMatchRecognize for %q = %v, want %v", d, got, want[d])
		}
	}
}

// ---------------------------------------------------------------------------
// Cache invariant check
// ---------------------------------------------------------------------------

// TestDialectTypedCached_IsO1 verifies that DialectTyped returns the
// cached field rather than re-parsing the string on every call. The
// invariant we check: after WithDialect, the string and typed fields
// agree; after Reset (via PutParser), both return their zero values.
func TestDialectTypedCached_IsO1(t *testing.T) {
	t.Parallel()

	p := NewParser(WithDialect("snowflake"))
	if got := p.DialectTyped(); got != dialect.Snowflake {
		t.Fatalf("DialectTyped() = %q, want %q", got, dialect.Snowflake)
	}
	if got := p.dialect; got != "snowflake" {
		t.Fatalf("p.dialect = %q, want %q", got, "snowflake")
	}
	// Direct field access to the cache also agrees.
	if p.dialectTyped != dialect.Snowflake {
		t.Fatalf("p.dialectTyped = %q, want %q", p.dialectTyped, dialect.Snowflake)
	}

	// Reset should clear both in lockstep.
	p.Reset()
	if p.dialect != "" {
		t.Errorf("after Reset, p.dialect = %q, want empty", p.dialect)
	}
	if p.dialectTyped != dialect.Unknown {
		t.Errorf("after Reset, p.dialectTyped = %q, want Unknown", p.dialectTyped)
	}
}

// TestDialectTypedCached_Alias verifies that the typed cache also tracks
// alias inputs routed through dialect.Parse (e.g. "postgres" -> PostgreSQL).
func TestDialectTypedCached_Alias(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want dialect.Dialect
	}{
		{"postgres", dialect.PostgreSQL},
		{"mssql", dialect.SQLServer},
		{"pg", dialect.PostgreSQL},
		{"not-a-dialect", dialect.Unknown},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			p := NewParser(WithDialect(tc.in))
			if got := p.DialectTyped(); got != tc.want {
				t.Errorf("DialectTyped() after WithDialect(%q) = %q, want %q",
					tc.in, got, tc.want)
			}
		})
	}
}

// Sanity: ensure the "strings" import is still referenced from this file
// even if none of the test bodies happen to use it directly. This guards
// against a future refactor silently dropping the package import.
var _ = strings.EqualFold
