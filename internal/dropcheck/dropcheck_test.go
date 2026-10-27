// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package dropcheck

import (
	"reflect"
	"strings"
	"testing"
)

func TestDroppedWordsCanonicalSynonyms(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
		want []string
	}{
		{"select all", "SELECT ALL name FROM users", "SELECT name FROM users", nil},
		{"select unique", "SELECT UNIQUE name FROM users", "SELECT DISTINCT name FROM users", nil},
		{"distinctrow", "SELECT DISTINCTROW name FROM users", "SELECT DISTINCT name FROM users", nil},
		{"postfix isnull", "SELECT x ISNULL FROM users", "SELECT x IS NULL FROM users", nil},
		{"postfix notnull", "SELECT x NOTNULL FROM users", "SELECT x IS NOT NULL FROM users", nil},
		{"isnull function preserved", "SELECT ISNULL(x, y) FROM users", "SELECT x FROM users", []string{"ISNULL", "Y"}},
		{"union all retained", "SELECT x FROM a UNION ALL SELECT x FROM b", "SELECT x FROM a UNION SELECT x FROM b", []string{"ALL"}},
		{"one repeated AND dropped", "SELECT x FROM t WHERE a AND b AND c", "SELECT x FROM t WHERE a AND b c", []string{"AND"}},
		{"two repeated words dropped", "SELECT x, x, x FROM t", "SELECT x FROM t", []string{"X", "X"}},
		{"dropped clause words", "SELECT x FROM users WHERE enabled = true", "SELECT x FROM users", []string{"WHERE", "ENABLED", "TRUE"}},
		{"dollar-quoted literal contents ignored", "SELECT $body$WHERE missing$body$ FROM users", "SELECT 'rewritten' FROM users", nil},
		{"quoted and commented words ignored", "SELECT x, 'missing string' FROM users -- missing comment", "SELECT x FROM users", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DroppedWords(tt.in, tt.out); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DroppedWords(%q, %q) = %v, want %v", tt.in, tt.out, got, tt.want)
			}
		})
	}
}

func TestWordsDialectBackslash(t *testing.T) {
	for _, dialect := range []string{"generic", "postgresql", "sqlite", "sqlserver", "oracle", "mysql", "mariadb", "clickhouse", "snowflake", "bigquery", "redshift"} {
		t.Run(dialect, func(t *testing.T) {
			want := []string{"SELECT", "AND", "B"}
			switch dialect {
			case "mysql", "mariadb", "clickhouse", "snowflake", "bigquery", "redshift":
				want = []string{"SELECT"}
			}
			if got := Words(`SELECT 'a\' AND b`, dialect); !reflect.DeepEqual(got, want) {
				t.Fatalf("Words = %v, want %v", got, want)
			}
		})
	}
	if got := Words(`SELECT E'a\'; b' AND x`, "postgresql"); !reflect.DeepEqual(got, []string{"SELECT", "AND", "X"}) {
		t.Fatalf("E string words = %v", got)
	}
}

func TestSQLWordsSkipsDollarQuotedLiteral(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{"untagged", "SELECT $$WHERE missing$$ FROM users", []string{"SELECT", "FROM", "USERS"}},
		{"tagged", "SELECT $body$WHERE missing$body$ FROM users", []string{"SELECT", "FROM", "USERS"}},
		{"regular identifier", "SELECT $1, my$column FROM users", []string{"SELECT", "MY$COLUMN", "FROM", "USERS"}},
		{"quoted identifier retained", "SELECT \"WHERE\" FROM users", []string{"SELECT", "WHERE", "FROM", "USERS"}},
		{"ordinary string and comments", "SELECT 'WHERE' FROM users /* missing */ -- other\nWHERE live", []string{"SELECT", "FROM", "USERS", "WHERE", "LIVE"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Words(tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Words(%q) = %v, want %v", tt.sql, got, tt.want)
			}
		})
	}
}

// TestDroppedWordsCorpusCases pins what the corpus drop detector accepts as a
// canonical spelling and what it still reports.
func TestDroppedWordsCorpusCases(t *testing.T) {
	tests := []struct {
		name, in, out string
		lost          string // space-separated, "" when nothing is lost
	}{
		{"select all", "SELECT ALL a FROM t", "SELECT a FROM t", ""},
		{"union all is not a synonym", "SELECT a FROM t UNION ALL SELECT a FROM u", "SELECT a FROM t UNION SELECT a FROM u", "ALL"},
		{"oracle select unique", "SELECT UNIQUE a FROM t", "SELECT DISTINCT a FROM t", ""},
		{"distinctrow", "SELECT DISTINCTROW a FROM t", "SELECT DISTINCT a FROM t", ""},
		{"postfix isnull", "SELECT a FROM t WHERE a ISNULL", "SELECT a FROM t WHERE a IS NULL", ""},
		{"postfix notnull", "SELECT a FROM t WHERE a NOTNULL", "SELECT a FROM t WHERE a IS NOT NULL", ""},
		{"isnull function is not a synonym", "SELECT ISNULL(a, 0) FROM t", "SELECT a FROM t", "ISNULL"},
		{"dollar quoted strings", "SELECT $$dollar quoted$$, $tag$ body 'with' quotes $tag$", "SELECT 'dollar quoted', ' body ''with'' quotes '", ""},
		{"dropped clause", "SELECT a FROM t WHERE b = 1", "SELECT a FROM t", "WHERE B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(DroppedWords(tc.in, tc.out), " ")
			if got != tc.lost {
				t.Errorf("lost words = %q, want %q", got, tc.lost)
			}
		})
	}
}
