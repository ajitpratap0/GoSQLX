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

import "testing"

func TestStringEscape(t *testing.T) {
	tests := []struct {
		d    Dialect
		want StringEscape
	}{
		{Unknown, StringEscapeLenient},
		{Generic, StringEscapeNone},
		{PostgreSQL, StringEscapeNone},
		{Oracle, StringEscapeNone},
		{SQLite, StringEscapeNone},
		{SQLServer, StringEscapeNone},
		{MySQL, StringEscapeMySQL},
		{MariaDB, StringEscapeMySQL},
		{ClickHouse, StringEscapeLenient},
		{Snowflake, StringEscapeLenient},
		{BigQuery, StringEscapeLenient},
		{Redshift, StringEscapeLenient},
		{Parse("postgres"), StringEscapeNone},
		{Parse("mssql"), StringEscapeNone},
	}
	for _, tt := range tests {
		if got := tt.d.StringEscape(); got != tt.want {
			t.Errorf("%q.StringEscape() = %d, want %d", tt.d, got, tt.want)
		}
	}
}
