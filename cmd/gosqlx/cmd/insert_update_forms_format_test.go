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

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatCommand_InsertUpdateForms is a regression test for the #610
// grammar additions: the `gosqlx format` renderer dropped UPDATE ... FROM
// sources and rendered INSERT ... DEFAULT VALUES as a bare INSERT INTO t, so
// `format -i` rewrote files with SQL of different meaning or invalid SQL.
func TestFormatCommand_InsertUpdateForms(t *testing.T) {
	cases := []struct {
		name, dialect, in, want string
	}{
		{"update from", "postgresql",
			"UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			"UPDATE t SET a = s.b FROM s WHERE t.id = s.id"},
		{"update from list", "postgresql",
			"UPDATE t SET a = s.b FROM s, u AS v WHERE t.id = s.id",
			// pkg/formatter writes table aliases without AS (#599).
			"UPDATE t SET a = s.b FROM s, u v WHERE t.id = s.id"},
		{"update from", "sqlserver",
			"UPDATE t SET a = s.b FROM s WHERE t.id = s.id",
			"UPDATE t SET a = s.b FROM s WHERE t.id = s.id"},
		{"update from no where", "postgresql",
			"UPDATE t SET a = s.b FROM s",
			"UPDATE t SET a = s.b FROM s"},
		{"default values", "postgresql",
			"INSERT INTO t DEFAULT VALUES",
			"INSERT INTO t DEFAULT VALUES"},
		{"default values", "sqlserver",
			"INSERT INTO t DEFAULT VALUES",
			"INSERT INTO t DEFAULT VALUES"},
		{"default values", "sqlite",
			"INSERT INTO t DEFAULT VALUES",
			"INSERT INTO t DEFAULT VALUES"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name+"/"+tc.dialect, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			f := NewFormatter(&out, &errBuf, CLIFormatterOptions{Compact: true, Uppercase: true, Dialect: tc.dialect})
			got, err := f.formatSQL(tc.in)
			if err != nil {
				t.Fatalf("formatSQL(%q) failed: %v", tc.in, err)
			}
			got = strings.TrimSpace(got)
			if got != tc.want {
				t.Fatalf("formatSQL mismatch\n got: %q\nwant: %q", got, tc.want)
			}

			// The output must mean the same thing: re-parse it and compare
			// the canonical SQL() of both trees.
			d := keywords.SQLDialect(tc.dialect)
			inTree, err := gosqlx.ParseWithDialect(tc.in, d)
			if err != nil {
				t.Fatalf("parse(%q) failed: %v", tc.in, err)
			}
			outTree, err := gosqlx.ParseWithDialect(got, d)
			if err != nil {
				t.Fatalf("re-parse of %q failed: %v", got, err)
			}
			if inTree.SQL() != outTree.SQL() {
				t.Fatalf("formatted SQL changed meaning\n in:  %q\n out: %q", inTree.SQL(), outTree.SQL())
			}
		})
	}

	t.Run("readable update from", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		f := NewFormatter(&out, &errBuf, CLIFormatterOptions{IndentSize: 2, Uppercase: true, Dialect: "postgresql"})
		got, err := f.formatSQL("UPDATE t SET a = s.b FROM s WHERE t.id = s.id")
		if err != nil {
			t.Fatalf("formatSQL failed: %v", err)
		}
		want := "UPDATE t\nSET a = s.b\nFROM s\nWHERE t.id = s.id"
		if strings.TrimSpace(got) != want {
			t.Fatalf("readable output mismatch\n got: %q\nwant: %q", strings.TrimSpace(got), want)
		}
	})
}
