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

import "time"

// Option configures parse behavior for ParseTree, ParseReader, and future
// parsing entry points that follow the functional-options pattern.
//
// Options are applied in the order they are passed. Later options override
// earlier ones when they touch the same field. Passing zero options selects
// sensible defaults (generic dialect, no timeout, non-strict parsing).
//
// Options are the recommended configuration surface for new code. The older
// ParseWithContext / ParseWithDialect / ParseWithTimeout / ParseWithRecovery
// entry points remain fully supported for backward compatibility but are
// combinatorial; Option avoids that combinatorial explosion.
//
// Example:
//
//	tree, err := gosqlx.ParseTree(
//	    ctx, sql,
//	    gosqlx.WithDialect("postgresql"),
//	    gosqlx.WithTimeout(3*time.Second),
//	)
type Option func(*parseOptions)

// parseOptions is the internal, mutable bag that Option functions write into.
// It is intentionally unexported: callers compose behavior through With* helpers.
type parseOptions struct {
	// dialect selects SQL dialect keyword recognition and grammar rules.
	// Empty string means generic SQL (library default).
	dialect string

	// strict enables strict parsing (e.g., reject empty statements between
	// semicolons). When false, the parser is lenient for backward compat.
	strict bool

	// timeout applies a parse-time deadline to contexts passed without one.
	// Zero means no deadline applied by the options layer.
	timeout time.Duration

	// recover enables error-recovery parsing — returns partial results and all
	// collected diagnostics rather than stopping at the first error.
	recover bool
}

// defaultParseOptions returns the baseline configuration used when no options
// are supplied. It is safe to mutate the returned value.
func defaultParseOptions() parseOptions {
	return parseOptions{
		dialect: "",
		strict:  false,
		timeout: 0,
		recover: false,
	}
}

// applyOptions folds the provided options over the default configuration.
func applyOptions(opts []Option) parseOptions {
	o := defaultParseOptions()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&o)
	}
	return o
}

// WithDialect selects the SQL dialect for keyword recognition and
// dialect-specific grammar rules.
//
// Supported values include (see pkg/sql/keywords for the canonical list):
//   - "generic"    — generic SQL (default when empty)
//   - "mysql"      — MySQL
//   - "mariadb"    — MariaDB
//   - "postgresql" — PostgreSQL
//   - "sqlite"     — SQLite
//   - "sqlserver"  — Microsoft SQL Server (T-SQL)
//   - "oracle"     — Oracle (PL/SQL)
//   - "snowflake"  — Snowflake
//   - "clickhouse" — ClickHouse
//
// Unknown dialect strings are passed through to the parser, which returns an
// ErrUnsupportedDialect-wrapped error if it cannot resolve the name.
//
// Example:
//
//	tree, err := gosqlx.ParseTree(ctx, sql, gosqlx.WithDialect("mysql"))
func WithDialect(dialect string) Option {
	return func(o *parseOptions) {
		o.dialect = dialect
	}
}

// WithStrict enables strict parsing mode. In strict mode the parser rejects
// constructs it would otherwise silently tolerate (for example, lone
// semicolons producing empty statements).
//
// Default is lenient (non-strict) for backward compatibility.
func WithStrict() Option {
	return func(o *parseOptions) {
		o.strict = true
	}
}

// WithTimeout applies a parse-time deadline. If the caller already passes a
// context with an earlier deadline, the caller's deadline wins; this option
// only tightens contexts that have no deadline of their own.
//
// A non-positive duration disables the timeout.
//
// Example:
//
//	tree, err := gosqlx.ParseTree(ctx, sql, gosqlx.WithTimeout(2*time.Second))
func WithTimeout(d time.Duration) Option {
	return func(o *parseOptions) {
		o.timeout = d
	}
}

// WithRecovery enables error-recovery parsing. When set, the parser
// synchronizes after errors and continues, returning partial statements and
// the full list of diagnostics rather than failing at the first error.
//
// Consumers that need diagnostics (IDEs, LSP servers, linters) should prefer
// this mode. When WithRecovery is set, ParseTree returns a *Tree whose
// Statements may include nil entries for unparseable segments; inspect the
// returned error via errors.Is(err, ErrSyntax) / ErrTokenize to identify the
// kinds of problems collected.
func WithRecovery() Option {
	return func(o *parseOptions) {
		o.recover = true
	}
}
