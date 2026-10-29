// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package tokenizer

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestNumericDialectLiterals(t *testing.T) {
	for _, tc := range []struct {
		dialect        keywords.SQLDialect
		valid, invalid []string
	}{
		{keywords.DialectPostgreSQL, []string{"1_000", "0x1F", "0o17", "0b101", "0x_FF", "0o_17", "0b_101", "1_000.000_1", "1e1_0"}, []string{"1x", "0x", "1__0", "1_", "0b102", "0x__FF", "0x_"}},
		{keywords.DialectSQLite, []string{"0x1F", "1_000"}, []string{"1x", "0b101", "1__0"}},
		{keywords.DialectClickHouse, []string{"0x1F", "1_000", "0b101"}, []string{"1x", "1_"}},
		{keywords.DialectSQLServer, []string{"0x1F"}, []string{"1x", "1_000", "0b101"}},
		// 0x hex stays accepted in every dialect, as before per-dialect lexing.
		{keywords.DialectOracle, []string{"1000", "0x1F", "1d", "1f", "1.5f", "1e5d", "1.5D", "1.e5F"}, []string{"1x", "1_000", "0b101", "1dx", "1.5fa"}},
		{keywords.DialectSnowflake, []string{"1000", "0xFF"}, []string{"1x", "1_000", "0b101", "1d"}},
		{keywords.DialectBigQuery, []string{"1000", "0x1F"}, []string{"1x", "1_000", "0b101"}},
		{keywords.DialectRedshift, []string{"1000", "0x1F"}, []string{"1x", "1_000", "0b101"}},
		{keywords.DialectGeneric, []string{"1000", "0x1F"}, []string{"1x", "1_000", "0b101", "1d", "1.5f"}},
	} {
		t.Run(string(tc.dialect), func(t *testing.T) {
			tk, err := NewWithDialect(tc.dialect)
			if err != nil {
				t.Fatal(err)
			}
			for _, sql := range tc.valid {
				tokens, err := tk.TokenizeString(sql)
				if err != nil {
					t.Errorf("%s: %v", sql, err)
					continue
				}
				if len(tokens) != 2 || tokens[0].Token.Type != models.TokenTypeNumber || tokens[0].Token.Value != sql {
					t.Errorf("%s: %v", sql, tokens)
				}
			}
			for _, sql := range tc.invalid {
				if _, err := tk.TokenizeString(sql); err == nil {
					t.Errorf("%s: expected error", sql)
				}
			}
		})
	}
	for _, dialect := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, sql := range []string{"1x", "1_000", "0x"} {
			got := lexAll(t, dialect, sql)
			if len(got) != 1 || got[0].typ != models.TokenTypeIdentifier || got[0].val != sql {
				t.Errorf("%s %s: %v", dialect, sql, got)
			}
		}
		for _, sql := range []string{"0x1F", "0b101"} {
			got := lexAll(t, dialect, sql)
			if len(got) != 1 || got[0].typ != models.TokenTypeNumber {
				t.Errorf("%s %s: %v", dialect, sql, got)
			}
		}
	}
}

func TestStorageSizeUnits(t *testing.T) {
	// Oracle storage sizes (and the generic dialect, which accepted them
	// before per-dialect lexing) keep the established number/unit token pair
	// wherever they appear, not only after SIZE.
	for _, dialect := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectGeneric} {
		for _, prefix := range []string{"SIZE ", "QUOTA ", "NEXT ", "MAXSIZE ", "RESIZE ", "BLOCKSIZE ", "PRIVATE_SGA ", "sga_target="} {
			for _, unit := range []string{"K", "M", "G", "T", "P", "E", "k", "m"} {
				got := lexAll(t, dialect, prefix+"500"+unit)
				n := len(got)
				if n < 3 || got[n-2].typ != models.TokenTypeNumber || got[n-2].val != "500" || got[n-1].val != unit {
					t.Errorf("%s %s: %v", dialect, prefix+"500"+unit, got)
				}
			}
		}
		tk, err := NewWithDialect(dialect)
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"SIZE 1x", "SIZE 1MB", "SIZE 1.5G", "SIZE 1_0M"} {
			if _, err := tk.TokenizeString(sql); err == nil {
				t.Errorf("%s %s: expected error", dialect, sql)
			}
		}
		// 1e+5 and 1E5 stay exponents, not an exabyte unit.
		for _, sql := range []string{"1e+5", "1E5", "1e-5"} {
			got := lexAll(t, dialect, sql)
			if len(got) != 1 || got[0].typ != models.TokenTypeNumber || got[0].val != sql {
				t.Errorf("%s %s: %v", dialect, sql, got)
			}
		}
	}
	// Other dialects do not take storage units.
	for _, dialect := range []keywords.SQLDialect{keywords.DialectPostgreSQL, keywords.DialectSQLite, keywords.DialectClickHouse} {
		tk, err := NewWithDialect(dialect)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tk.TokenizeString("SIZE 10M"); err == nil {
			t.Errorf("%s: expected error", dialect)
		}
	}
}

func TestNumberBeforeKeyword(t *testing.T) {
	// Oracle, SQL Server and the generic dialect end a number at a keyword
	// written against it; other names still make the number invalid.
	for _, dialect := range []keywords.SQLDialect{keywords.DialectOracle, keywords.DialectSQLServer, keywords.DialectGeneric} {
		for _, tc := range []struct{ sql, num, word string }{
			{"1FROM", "1", "FROM"}, {"5ROWS", "5", "ROWS"}, {"1as", "1", "as"}, {"1UNION", "1", "UNION"},
		} {
			got := lexAll(t, dialect, tc.sql)
			if len(got) != 2 || got[0].typ != models.TokenTypeNumber || got[0].val != tc.num || got[1].val != tc.word {
				t.Errorf("%s %s: %v", dialect, tc.sql, got)
			}
		}
		tk, err := NewWithDialect(dialect)
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{"1fromx", "1from$x", "1x"} {
			if _, err := tk.TokenizeString(sql); err == nil {
				t.Errorf("%s %s: expected error", dialect, sql)
			}
		}
	}
	tk, err := NewWithDialect(keywords.DialectPostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tk.TokenizeString("1FROM"); err == nil {
		t.Error("postgresql 1FROM: expected trailing junk error")
	}
}

func TestMySQLNumberThenName(t *testing.T) {
	// A MySQL number with a fraction or signed exponent ends before a name,
	// which is then an alias (1.5a is 1.5 AS a); 1x and 1e5x stay names.
	for _, dialect := range []keywords.SQLDialect{keywords.DialectMySQL, keywords.DialectMariaDB} {
		for _, tc := range []struct {
			sql  string
			want []lexTok
		}{
			{"1.5a", []lexTok{{models.TokenTypeNumber, "1.5"}, {models.TokenTypeIdentifier, "a"}}},
			{"1.0d", []lexTok{{models.TokenTypeNumber, "1.0"}, {models.TokenTypeIdentifier, "d"}}},
			{".5x", []lexTok{{models.TokenTypeNumber, ".5"}, {models.TokenTypeIdentifier, "x"}}},
			{"1e+5x", []lexTok{{models.TokenTypeNumber, "1e+5"}, {models.TokenTypeIdentifier, "x"}}},
			{"1e5x", []lexTok{{models.TokenTypeIdentifier, "1e5x"}}},
		} {
			got := lexAll(t, dialect, tc.sql)
			if len(got) != len(tc.want) {
				t.Errorf("%s %s: %v", dialect, tc.sql, got)
				continue
			}
			for i := range got {
				if got[i].typ != tc.want[i].typ || got[i].val != tc.want[i].val {
					t.Errorf("%s %s: %v", dialect, tc.sql, got)
				}
			}
		}
	}
}
