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

package security

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestHasEqualIdentPairCaptureBoundary pins the 51-byte capture bound of
// [a-z_][a-z0-9_.]{0,50}. A border-free identifier ("a" followed by 50 "b")
// equal on both sides of '=' can only be matched by the full 51-byte comparison.
func TestHasEqualIdentPairCaptureBoundary(t *testing.T) {
	id51 := "a" + strings.Repeat("b", 50)
	id52 := "a" + strings.Repeat("b", 51)
	scanner := NewScanner()
	cases := []struct {
		name, sql string
		want      bool
	}{
		{"51 plain", id51 + "=" + id51, true},
		{"51 spaced", id51 + " = " + id51, true},
		{"51 case-folded", strings.ToUpper(id51) + "=" + id51, true},
		{"51 left only prefix", "x " + id51 + "=" + id51 + " y", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasEqualIdentPair(tc.sql); got != tc.want {
				t.Fatalf("hasEqualIdentPair(%q) = %v, want %v", tc.sql, got, tc.want)
			}
			if r := scanner.ScanSQL(tc.sql); r.TotalCount == 0 {
				t.Fatalf("ScanSQL(%q) reported no finding", tc.sql)
			}
		})
	}
	// 52 bytes exceeds the regex capture bound; the guard must agree with the
	// regex-only path whatever it decides.
	for _, sql := range []string{id52 + "=" + id52, id52 + " = " + id52} {
		got, want := scanner.ScanSQL(sql), scanSQLRegexOnly(scanner, sql)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("52-byte case %q: guarded %+v, regex-only %+v", sql, got, want)
		}
	}
}

// TestTableFnGuardCoversEveryRegexName extracts the names from the ClickHouse
// table-function alternation in scanner.go and requires the guard's name set to
// match it exactly, and every name (mixed case, tab/VT whitespace) to be both a
// guard candidate and a ScanSQL finding.
func TestTableFnGuardCoversEveryRegexName(t *testing.T) {
	src, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`\(\?:FROM\|JOIN\)\[\\s\\v\]\+\(\?:([A-Za-z0-9_|]+)\)\[\\s\\v\]\*\\\(`).FindSubmatch(src)
	if m == nil {
		t.Fatal("ClickHouse table-function alternation not found in scanner.go")
	}
	names := strings.Split(string(m[1]), "|")
	if len(names) != len(chNames) {
		t.Fatalf("regex has %d names, guard has %d", len(names), len(chNames))
	}
	scanner := NewScanner()
	for _, name := range names {
		if !chNames[strings.ToLower(name)] {
			t.Errorf("guard is missing %q", name)
		}
		mixed := mixCase(name)
		for _, sql := range []string{
			"SELECT * FROM " + mixed + " ('x')",
			"SELECT * FROM t JOIN " + mixed + "\v('x')",
			"select * from\t" + strings.ToUpper(name) + "(1)",
		} {
			if !hasTableFnCandidate(sql) {
				t.Errorf("hasTableFnCandidate(%q) = false", sql)
			}
			found := false
			for _, f := range scanner.ScanSQL(sql).Findings {
				if f.Pattern == PatternOutOfBand {
					found = true
				}
			}
			if !found {
				t.Errorf("ScanSQL(%q) did not report an out-of-band finding", sql)
			}
		}
	}
}

func mixCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 1 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
