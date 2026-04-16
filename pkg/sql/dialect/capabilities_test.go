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

package dialect

import (
	"reflect"
	"testing"
)

// TestParse covers canonical names, case-insensitivity, aliases, and
// unknown strings.
func TestParse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want Dialect
	}{
		// Canonical
		{"postgresql", PostgreSQL},
		{"mysql", MySQL},
		{"mariadb", MariaDB},
		{"sqlserver", SQLServer},
		{"oracle", Oracle},
		{"sqlite", SQLite},
		{"snowflake", Snowflake},
		{"clickhouse", ClickHouse},
		{"bigquery", BigQuery},
		{"redshift", Redshift},
		{"generic", Generic},

		// Case-insensitive
		{"PostgreSQL", PostgreSQL},
		{"MYSQL", MySQL},
		{"SqlServer", SQLServer},

		// Whitespace trimmed
		{"  mysql  ", MySQL},

		// Aliases
		{"postgres", PostgreSQL},
		{"pg", PostgreSQL},
		{"mssql", SQLServer},
		{"tsql", SQLServer},
		{"sqlite3", SQLite},
		{"ch", ClickHouse},
		{"bq", BigQuery},
		{"ansi", Generic},
		{"standard", Generic},

		// Empty / unknown
		{"", Unknown},
		{"fakesql", Unknown},
		{"cassandra", Unknown},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := Parse(tc.in)
			if got != tc.want {
				t.Fatalf("Parse(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDialect_String covers fmt.Stringer compliance.
func TestDialect_String(t *testing.T) {
	t.Parallel()

	if got := PostgreSQL.String(); got != "postgresql" {
		t.Errorf("PostgreSQL.String() = %q, want %q", got, "postgresql")
	}
	if got := Unknown.String(); got != "" {
		t.Errorf("Unknown.String() = %q, want empty string", got)
	}
	if got := Snowflake.String(); got != "snowflake" {
		t.Errorf("Snowflake.String() = %q, want %q", got, "snowflake")
	}
}

// TestDialect_IsValid covers the IsValid predicate.
func TestDialect_IsValid(t *testing.T) {
	t.Parallel()

	valid := []Dialect{
		PostgreSQL, MySQL, MariaDB, SQLServer, Oracle, SQLite,
		Snowflake, ClickHouse, BigQuery, Redshift, Generic,
	}
	for _, d := range valid {
		if !d.IsValid() {
			t.Errorf("%q.IsValid() = false, want true", d)
		}
	}

	invalid := []Dialect{Unknown, Dialect("fakesql"), Dialect("postgres")}
	for _, d := range invalid {
		if d.IsValid() {
			t.Errorf("%q.IsValid() = true, want false", d)
		}
	}
}

// TestCapabilities_PerDialect verifies that every known dialect sets at
// least one flag that the permissive default does NOT set. This guards
// against the matrix drifting back to "everything returns the default".
//
// It is a weak property (it proves the matrix is populated, not that any
// individual flag is correct) but makes accidental regressions loud.
func TestCapabilities_PerDialectDiffersFromUnknown(t *testing.T) {
	t.Parallel()

	def := Unknown.Capabilities()
	known := []Dialect{
		PostgreSQL, MySQL, MariaDB, SQLServer, Oracle, SQLite,
		Snowflake, ClickHouse, BigQuery, Redshift, Generic,
	}

	for _, d := range known {
		got := d.Capabilities()
		if reflect.DeepEqual(got, def) {
			t.Errorf("%q.Capabilities() is identical to the permissive default; "+
				"expected at least one dialect-specific flag to differ", d)
		}
	}
}

// TestCapabilities_KnownFlags spot-checks specific cells in the matrix.
// These are not exhaustive, but lock down the facts the parser most often
// relies on when feature-gating.
func TestCapabilities_KnownFlags(t *testing.T) {
	t.Parallel()

	type flag struct {
		name string
		get  func(Capabilities) bool
		want bool
	}

	type matrixRow struct {
		dialect Dialect
		flags   []flag
	}

	rows := []matrixRow{
		{
			dialect: PostgreSQL,
			flags: []flag{
				{"DistinctOn", func(c Capabilities) bool { return c.SupportsDistinctOn }, true},
				{"ILike", func(c Capabilities) bool { return c.SupportsILike }, true},
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, true},
				{"Top", func(c Capabilities) bool { return c.SupportsTop }, false},
				{"ArrayJoin", func(c Capabilities) bool { return c.SupportsArrayJoin }, false},
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, false},
			},
		},
		{
			dialect: Snowflake,
			flags: []flag{
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, true},
				{"TimeTravel", func(c Capabilities) bool { return c.SupportsTimeTravel }, true},
				{"MatchRecognize", func(c Capabilities) bool { return c.SupportsMatchRecognize }, true},
				{"Top", func(c Capabilities) bool { return c.SupportsTop }, true},
				{"ILike", func(c Capabilities) bool { return c.SupportsILike }, true},
				{"ArrayJoin", func(c Capabilities) bool { return c.SupportsArrayJoin }, false},
			},
		},
		{
			dialect: ClickHouse,
			flags: []flag{
				{"ArrayJoin", func(c Capabilities) bool { return c.SupportsArrayJoin }, true},
				{"Prewhere", func(c Capabilities) bool { return c.SupportsPrewhere }, true},
				{"Sample", func(c Capabilities) bool { return c.SupportsSample }, true},
				{"Backtick", func(c Capabilities) bool { return c.SupportsBacktickQuoting }, true},
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, false},
			},
		},
		{
			dialect: SQLServer,
			flags: []flag{
				{"Top", func(c Capabilities) bool { return c.SupportsTop }, true},
				{"BracketQuoting", func(c Capabilities) bool { return c.SupportsBracketQuoting }, true},
				{"Merge", func(c Capabilities) bool { return c.SupportsMerge }, true},
				{"CompoundReturning", func(c Capabilities) bool { return c.SupportsCompoundReturning }, true},
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, false},
				{"ILike", func(c Capabilities) bool { return c.SupportsILike }, false},
			},
		},
		{
			dialect: Oracle,
			flags: []flag{
				{"ConnectBy", func(c Capabilities) bool { return c.SupportsConnectBy }, true},
				{"MatchRecognize", func(c Capabilities) bool { return c.SupportsMatchRecognize }, true},
				{"FetchFirst", func(c Capabilities) bool { return c.SupportsFetchFirst }, true},
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, false},
				{"Top", func(c Capabilities) bool { return c.SupportsTop }, false},
			},
		},
		{
			dialect: MySQL,
			flags: []flag{
				{"IndexHints", func(c Capabilities) bool { return c.SupportsIndexHints }, true},
				{"Backtick", func(c Capabilities) bool { return c.SupportsBacktickQuoting }, true},
				{"Merge", func(c Capabilities) bool { return c.SupportsMerge }, false},
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, false},
				{"ILike", func(c Capabilities) bool { return c.SupportsILike }, false},
			},
		},
		{
			dialect: MariaDB,
			flags: []flag{
				{"IndexHints", func(c Capabilities) bool { return c.SupportsIndexHints }, true},
				{"ConnectBy", func(c Capabilities) bool { return c.SupportsConnectBy }, true},
				{"Returning", func(c Capabilities) bool { return c.SupportsReturning }, true},
			},
		},
		{
			dialect: SQLite,
			flags: []flag{
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, true},
				{"Returning", func(c Capabilities) bool { return c.SupportsReturning }, true},
				{"Merge", func(c Capabilities) bool { return c.SupportsMerge }, false},
			},
		},
		{
			dialect: BigQuery,
			flags: []flag{
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, true},
				{"Pivot", func(c Capabilities) bool { return c.SupportsPivotUnpivot }, true},
				{"Backtick", func(c Capabilities) bool { return c.SupportsBacktickQuoting }, true},
			},
		},
		{
			dialect: Redshift,
			flags: []flag{
				{"ILike", func(c Capabilities) bool { return c.SupportsILike }, true},
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, true},
			},
		},
		{
			dialect: Generic,
			flags: []flag{
				{"FetchFirst", func(c Capabilities) bool { return c.SupportsFetchFirst }, true},
				{"LimitOffset", func(c Capabilities) bool { return c.SupportsLimitOffset }, false},
				{"Qualify", func(c Capabilities) bool { return c.SupportsQualify }, false},
			},
		},
	}

	for _, row := range rows {
		row := row
		t.Run(string(row.dialect), func(t *testing.T) {
			t.Parallel()
			caps := row.dialect.Capabilities()
			for _, f := range row.flags {
				if got := f.get(caps); got != f.want {
					t.Errorf("%q.Capabilities().%s = %v, want %v",
						row.dialect, f.name, got, f.want)
				}
			}
		})
	}
}

// TestCapabilities_UnknownIsPermissive verifies the Unknown dialect returns
// the permissive default that enables common standard features. Callers
// that never pass WithDialect rely on this.
func TestCapabilities_UnknownIsPermissive(t *testing.T) {
	t.Parallel()

	caps := Unknown.Capabilities()

	// Features that should be on by default so that the pre-typed-dialect
	// behaviour is preserved for callers who never set a dialect.
	if !caps.SupportsLimitOffset {
		t.Error("Unknown should allow LIMIT/OFFSET in permissive mode")
	}
	if !caps.SupportsMerge {
		t.Error("Unknown should allow MERGE in permissive mode")
	}
	if !caps.SupportsReturning {
		t.Error("Unknown should allow RETURNING in permissive mode")
	}
	if !caps.SupportsILike {
		t.Error("Unknown should allow ILIKE in permissive mode (back-compat)")
	}

	// Features that should be off by default because they are dialect-
	// specific extensions; leaving them on would defeat feature-gating.
	if caps.SupportsArrayJoin {
		t.Error("Unknown should NOT enable ARRAY JOIN (ClickHouse-only)")
	}
	if caps.SupportsPrewhere {
		t.Error("Unknown should NOT enable PREWHERE (ClickHouse-only)")
	}
	if caps.SupportsQualify {
		t.Error("Unknown should NOT enable QUALIFY (Snowflake/BigQuery-only)")
	}
	if caps.SupportsTop {
		t.Error("Unknown should NOT enable TOP (SQL Server/Snowflake-only)")
	}
	if caps.SupportsDistinctOn {
		t.Error("Unknown should NOT enable DISTINCT ON (PostgreSQL-only)")
	}
	if caps.SupportsConnectBy {
		t.Error("Unknown should NOT enable CONNECT BY (Oracle/MariaDB)")
	}
}

// TestCapabilities_ZeroValueIsUnknown verifies the Go zero-value Dialect{}
// round-trips through Capabilities() as Unknown.
func TestCapabilities_ZeroValueIsUnknown(t *testing.T) {
	t.Parallel()

	var zero Dialect
	if zero != Unknown {
		t.Fatalf("zero Dialect = %q, want Unknown (empty string)", zero)
	}
	if !reflect.DeepEqual(zero.Capabilities(), Unknown.Capabilities()) {
		t.Fatal("zero Dialect's Capabilities differ from Unknown's")
	}
}
