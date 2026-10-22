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

// StringEscape describes how a dialect treats the backslash inside a
// single-quoted string literal. The tokenizer uses it to decode literals and
// the parser records it on each string literal so the formatter can write the
// literal back with the same rules (re-escaping with the wrong rules doubles
// backslashes on every format pass).
type StringEscape uint8

const (
	// StringEscapeLenient is the default for an unspecified dialect and for
	// ClickHouse, Snowflake, BigQuery and Redshift: C-style
	// backslash escapes are decoded and an unrecognised sequence keeps its
	// backslash, so the literal never fails to tokenize.
	StringEscapeLenient StringEscape = iota
	// StringEscapeNone means a backslash is an ordinary character
	// (PostgreSQL standard strings, Oracle, SQLite, SQL Server and the
	// standard-SQL "generic" dialect). Only a doubled quote escapes the quote.
	StringEscapeNone
	// StringEscapeMySQL is MySQL and MariaDB: backslash escapes are decoded,
	// \% and \_ keep their backslash (so LIKE patterns survive) and any other
	// escaped character stands for itself.
	StringEscapeMySQL
)

// StringEscape returns how the dialect treats a backslash in a string literal.
func (d Dialect) StringEscape() StringEscape {
	switch d {
	case PostgreSQL, Oracle, SQLite, SQLServer, Generic:
		return StringEscapeNone
	case MySQL, MariaDB:
		return StringEscapeMySQL
	default:
		return StringEscapeLenient
	}
}
