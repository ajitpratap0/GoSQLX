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
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestDialectTyped_RoundTrip verifies that WithDialect's string input
// round-trips through DialectTyped as the matching typed constant.
func TestDialectTyped_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		opt  string
		want dialect.Dialect
	}{
		{"postgresql", dialect.PostgreSQL},
		{"mysql", dialect.MySQL},
		{"mariadb", dialect.MariaDB},
		{"sqlserver", dialect.SQLServer},
		{"oracle", dialect.Oracle},
		{"sqlite", dialect.SQLite},
		{"snowflake", dialect.Snowflake},
		{"clickhouse", dialect.ClickHouse},
		{"bigquery", dialect.BigQuery},
		{"redshift", dialect.Redshift},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.opt, func(t *testing.T) {
			t.Parallel()
			p := NewParser(WithDialect(tc.opt))
			if got := p.DialectTyped(); got != tc.want {
				t.Errorf("DialectTyped() after WithDialect(%q) = %q, want %q",
					tc.opt, got, tc.want)
			}
		})
	}
}

// TestDialectTyped_UnsetReturnsUnknown verifies that a parser with no
// explicit dialect reports Unknown (not PostgreSQL). This is different
// from the string-returning Dialect() method, which defaults to
// "postgresql" for backward compatibility.
func TestDialectTyped_UnsetReturnsUnknown(t *testing.T) {
	t.Parallel()
	p := NewParser()
	if got := p.DialectTyped(); got != dialect.Unknown {
		t.Fatalf("DialectTyped() with no option = %q, want Unknown", got)
	}
	// The string-returning accessor must remain unchanged for v1.x
	// back-compat: returns "postgresql" for unset.
	if got := p.Dialect(); got != "postgresql" {
		t.Fatalf("Dialect() (string) with no option = %q, want %q (back-compat)",
			got, "postgresql")
	}
}

// TestCapabilities_FromParser spot-checks that the parser's Capabilities
// helper delegates to the typed dialect and returns the expected matrix.
func TestCapabilities_FromParser(t *testing.T) {
	t.Parallel()

	type check struct {
		opt  string
		gate func(dialect.Capabilities) bool
		name string
		want bool
	}
	cases := []check{
		{"snowflake", func(c dialect.Capabilities) bool { return c.SupportsQualify }, "SupportsQualify", true},
		{"bigquery", func(c dialect.Capabilities) bool { return c.SupportsQualify }, "SupportsQualify", true},
		{"clickhouse", func(c dialect.Capabilities) bool { return c.SupportsArrayJoin }, "SupportsArrayJoin", true},
		{"clickhouse", func(c dialect.Capabilities) bool { return c.SupportsPrewhere }, "SupportsPrewhere", true},
		{"postgresql", func(c dialect.Capabilities) bool { return c.SupportsDistinctOn }, "SupportsDistinctOn", true},
		{"postgresql", func(c dialect.Capabilities) bool { return c.SupportsILike }, "SupportsILike", true},
		{"sqlserver", func(c dialect.Capabilities) bool { return c.SupportsTop }, "SupportsTop", true},
		{"sqlserver", func(c dialect.Capabilities) bool { return c.SupportsBracketQuoting }, "SupportsBracketQuoting", true},
		{"mysql", func(c dialect.Capabilities) bool { return c.SupportsIndexHints }, "SupportsIndexHints", true},
		{"mysql", func(c dialect.Capabilities) bool { return c.SupportsBacktickQuoting }, "SupportsBacktickQuoting", true},
		{"oracle", func(c dialect.Capabilities) bool { return c.SupportsConnectBy }, "SupportsConnectBy", true},
		{"oracle", func(c dialect.Capabilities) bool { return c.SupportsMatchRecognize }, "SupportsMatchRecognize", true},
		{"sqlite", func(c dialect.Capabilities) bool { return c.SupportsMerge }, "SupportsMerge", false},

		// Unknown / empty should be permissive on common features but
		// disable dialect-specific extensions.
		{"", func(c dialect.Capabilities) bool { return c.SupportsLimitOffset }, "SupportsLimitOffset", true},
		{"", func(c dialect.Capabilities) bool { return c.SupportsQualify }, "SupportsQualify", false},
		{"", func(c dialect.Capabilities) bool { return c.SupportsArrayJoin }, "SupportsArrayJoin", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.opt+"_"+tc.name, func(t *testing.T) {
			t.Parallel()
			var p *Parser
			if tc.opt == "" {
				p = NewParser()
			} else {
				p = NewParser(WithDialect(tc.opt))
			}
			caps := p.Capabilities()
			if got := tc.gate(caps); got != tc.want {
				t.Errorf("NewParser(WithDialect(%q)).Capabilities().%s = %v, want %v",
					tc.opt, tc.name, got, tc.want)
			}
		})
	}
}

// TestDialectPredicates verifies the Is<Dialect>() convenience predicates.
func TestDialectPredicates(t *testing.T) {
	t.Parallel()

	p := NewParser(WithDialect("snowflake"))
	if !p.IsSnowflake() {
		t.Error("IsSnowflake() = false for WithDialect(\"snowflake\")")
	}
	if p.IsPostgreSQL() || p.IsMySQL() || p.IsSQLServer() ||
		p.IsOracle() || p.IsSQLite() || p.IsClickHouse() ||
		p.IsBigQuery() || p.IsRedshift() || p.IsMariaDB() {
		t.Error("exactly one predicate should return true for a given dialect")
	}

	// Unset dialect: every predicate should be false (Unknown matches
	// none of the typed constants).
	unset := NewParser()
	if unset.IsPostgreSQL() || unset.IsMySQL() || unset.IsSQLServer() ||
		unset.IsOracle() || unset.IsSQLite() || unset.IsSnowflake() ||
		unset.IsClickHouse() || unset.IsBigQuery() || unset.IsRedshift() ||
		unset.IsMariaDB() {
		t.Error("all Is<Dialect> predicates should be false for unset dialect")
	}
}

// TestDialectTyped_ParseSanity verifies that a parser configured with a
// typed dialect still parses basic SQL. This guards against the new
// helpers accidentally interfering with parser initialisation.
func TestDialectTyped_ParseSanity(t *testing.T) {
	t.Parallel()

	ast, err := ParseWithDialect("SELECT 1", keywords.DialectSnowflake)
	if err != nil {
		t.Fatalf("ParseWithDialect(snowflake) failed: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil AST")
	}
}
