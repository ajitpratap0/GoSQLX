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

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
)

// TestFormatter_Format_UsesDialect checks that Formatter.Format tokenizes and
// parses with Options.Dialect, not only renders with it: strings and syntax
// that are valid in the dialect must not fail in the no-dialect front end.
func TestFormatter_Format_UsesDialect(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		in      string
		want    string
	}{
		{"postgres backslash literal", "postgresql", `SELECT 'C:\dir'`, `SELECT 'C:\dir'`},
		{"mysql escaped quote", "mysql", `SELECT 'it\'s'`, `SELECT 'it''s'`},
		{"mysql dialect name case", "MySQL", `SELECT 'it\'s'`, `SELECT 'it''s'`},
		{"clickhouse engine", "clickhouse", `CREATE TABLE t (a Int32) ENGINE = MergeTree ORDER BY a`, `CREATE TABLE t (a Int32) ENGINE=MergeTree ORDER BY a`},
		{"unknown dialect ignored", "nosuchdb", `SELECT a FROM t`, `SELECT a FROM t`},
		{"no dialect", "", `SELECT a FROM t`, `SELECT a FROM t`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatter.New(formatter.Options{Compact: true, Dialect: tc.dialect}).Format(tc.in)
			if err != nil {
				t.Fatalf("Format(%q) with dialect %q: %v", tc.in, tc.dialect, err)
			}
			if got != tc.want {
				t.Errorf("Format(%q) with dialect %q\n got: %s\nwant: %s", tc.in, tc.dialect, got, tc.want)
			}
		})
	}
}
