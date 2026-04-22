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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
)

// DialectTyped returns the parser's active dialect as a typed
// dialect.Dialect value.
//
// This is the preferred accessor for new parser code and should be used in
// place of reading the p.dialect string field directly or calling the
// string-returning Dialect() method. The typed form enables compile-time
// typo detection and is the long-term replacement for scattered
// `p.dialect == "..."` comparisons scheduled for v2.0.
//
// The existing string-returning Dialect() method is retained for v1.x
// backward compatibility and continues to return "postgresql" for the
// unset default. DialectTyped, by contrast, returns dialect.Unknown when
// no dialect has been set, which is the correct signal for feature-gated
// parser logic: Unknown selects the permissive default capability set
// from dialect.Capabilities.
//
// Callers that need the string form should continue to use Dialect(); new
// feature-gated parser logic should use Capabilities() below.
//
// Performance: O(1). The typed dialect is cached on the Parser struct at
// WithDialect-time, so this accessor is a direct field read with no
// dialect.Parse call per invocation. See the dialectTyped field comment
// and the INVARIANT on Parser.
//
// Strangler-fig migration: the long-term plan is to replace scattered
// `p.dialect == "snowflake"` string comparisons with Capabilities() gates
// and typed Is*() predicates. Migration happens incrementally (a handful
// of sites per release) rather than in a single bulk commit, so the
// string field remains the source of truth for v1.x back-compat while
// dialectTyped acts as the typed cache.
func (p *Parser) DialectTyped() dialect.Dialect {
	return p.dialectTyped
}

// Capabilities returns the capability matrix for the parser's active
// dialect. Use this for feature-gated parser logic:
//
//	if p.Capabilities().SupportsQualify {
//	    // parse QUALIFY clause
//	}
//
// in place of the older, typo-prone form:
//
//	if p.dialect == "snowflake" || p.dialect == "bigquery" {
//	    // parse QUALIFY clause
//	}
//
// For the Unknown dialect (no WithDialect), Capabilities returns a
// permissive default suitable for "parse anything widely supported" use
// cases. See dialect.Capabilities for the full flag set.
func (p *Parser) Capabilities() dialect.Capabilities {
	return p.DialectTyped().Capabilities()
}

// --- Convenience predicates ---
//
// These are thin wrappers over DialectTyped() comparisons, useful for the
// subset of call sites that genuinely need to match a specific dialect
// (as opposed to feature-gating via Capabilities). They exist to make
// migration off raw `p.dialect == "..."` comparisons possible without
// forcing every call site to import the dialect package.
//
// Prefer Capabilities() when the check is really about a feature
// ("does this dialect support QUALIFY?") rather than an identity
// ("is this Snowflake?").

// IsPostgreSQL reports whether the parser's active dialect is PostgreSQL.
func (p *Parser) IsPostgreSQL() bool { return p.DialectTyped() == dialect.PostgreSQL }

// IsMySQL reports whether the parser's active dialect is MySQL.
func (p *Parser) IsMySQL() bool { return p.DialectTyped() == dialect.MySQL }

// IsMariaDB reports whether the parser's active dialect is MariaDB.
func (p *Parser) IsMariaDB() bool { return p.DialectTyped() == dialect.MariaDB }

// IsSQLServer reports whether the parser's active dialect is SQL Server.
func (p *Parser) IsSQLServer() bool { return p.DialectTyped() == dialect.SQLServer }

// IsOracle reports whether the parser's active dialect is Oracle.
func (p *Parser) IsOracle() bool { return p.DialectTyped() == dialect.Oracle }

// IsSQLite reports whether the parser's active dialect is SQLite.
func (p *Parser) IsSQLite() bool { return p.DialectTyped() == dialect.SQLite }

// IsSnowflake reports whether the parser's active dialect is Snowflake.
func (p *Parser) IsSnowflake() bool { return p.DialectTyped() == dialect.Snowflake }

// IsClickHouse reports whether the parser's active dialect is ClickHouse.
func (p *Parser) IsClickHouse() bool { return p.DialectTyped() == dialect.ClickHouse }

// IsBigQuery reports whether the parser's active dialect is BigQuery.
func (p *Parser) IsBigQuery() bool { return p.DialectTyped() == dialect.BigQuery }

// IsRedshift reports whether the parser's active dialect is Redshift.
func (p *Parser) IsRedshift() bool { return p.DialectTyped() == dialect.Redshift }
