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
	// StringEscapeStrict is the zero value and the mode of a tokenizer that
	// has no dialect configured. Only the escapes every backslash-escaping
	// dialect agrees on are decoded (\\ \' \" \` \n \r \t); any other
	// sequence is an error, because its meaning depends on the dialect (in
	// PostgreSQL 'x\.y' is four characters, in MySQL three). Refusing the
	// literal is better than silently changing its value on a format pass.
	StringEscapeStrict StringEscape = iota
	// StringEscapeLenient is ClickHouse and BigQuery: C-style backslash
	// escapes (\b \f \n \r \t \0 \a \v \xHH) are decoded and an
	// unrecognised sequence keeps its backslash, as ClickHouse does so that
	// LIKE patterns and regular expressions survive.
	StringEscapeLenient
	// StringEscapeNone means a backslash is an ordinary character
	// (PostgreSQL standard strings, Oracle, SQLite, SQL Server and the
	// standard-SQL "generic" dialect). Only a doubled quote escapes the quote.
	StringEscapeNone
	// StringEscapeMySQL is MySQL and MariaDB: backslash escapes are decoded,
	// \% and \_ keep their backslash (so LIKE patterns survive) and any other
	// escaped character stands for itself.
	StringEscapeMySQL
	// StringEscapeDropUnknown is Snowflake and Amazon Redshift: backslash
	// escapes are decoded (\b \f \n \r \t, three-digit octal, \xhh and
	// \uhhhh) and before any other character the backslash is ignored, so
	// 'x\.y' is x.y and '50\%' is 50%. Snowflake documents this rule
	// ("the backslash is ignored"); Redshift reads plain literals with
	// PostgreSQL's pre-9.1 escape rules (its documented default LIKE escape
	// is written as two backslashes in a literal).
	StringEscapeDropUnknown
)

// StringEscape returns how the dialect treats a backslash in a string
// literal. An unknown dialect reports StringEscapeStrict, the rules of a
// tokenizer with no dialect configured.
func (d Dialect) StringEscape() StringEscape {
	switch d {
	case PostgreSQL, Oracle, SQLite, SQLServer, Generic:
		return StringEscapeNone
	case MySQL, MariaDB:
		return StringEscapeMySQL
	case Snowflake, Redshift:
		return StringEscapeDropUnknown
	case ClickHouse, BigQuery:
		return StringEscapeLenient
	default:
		return StringEscapeStrict
	}
}
