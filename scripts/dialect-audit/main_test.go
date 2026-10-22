package main

import (
	"reflect"
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
		{"dropped clause words", "SELECT x FROM users WHERE enabled = true", "SELECT x FROM users", []string{"WHERE", "ENABLED", "TRUE"}},
		{"dollar-quoted literal contents ignored", "SELECT $body$WHERE missing$body$ FROM users", "SELECT 'rewritten' FROM users", nil},
		{"quoted and commented words ignored", "SELECT x, 'missing string' FROM users -- missing comment", "SELECT x FROM users", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := droppedWords(tt.in, tt.out); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("droppedWords(%q, %q) = %v, want %v", tt.in, tt.out, got, tt.want)
			}
		})
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
			if got := sqlWords(tt.sql); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sqlWords(%q) = %v, want %v", tt.sql, got, tt.want)
			}
		})
	}
}
