// Copyright 2026 GoSQLX Authors
// Licensed under the Apache License, Version 2.0.
package ast

import (
	"strings"
	"testing"
	"unicode"
)

func identifierNeedsQuotingRef(name string) bool {
	if name == "" {
		return true
	}
	digitLed, partStart := false, true
	for _, r := range name {
		switch {
		case r == '.':
			digitLed, partStart = false, true
			continue
		case r == '$' && !partStart && !digitLed:
			// A later character of a name (Oracle v$session, Snowflake
			// SYSTEM$TYPEOF); never the first.
			continue
		case r != '_' && r != '*' && !unicode.IsLetter(r) && !unicode.IsDigit(r):
			return true
		case partStart:
			digitLed = unicode.IsDigit(r)
		case digitLed && !unicode.IsDigit(r):
			return true
		}
		partStart = false
	}
	return false
}

func isReservedNameRef(name string, table bool) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '_') {
			return false
		}
	}
	inAll, ok := reservedNameWords[strings.ToUpper(name)]
	return ok && (inAll || !table)
}

var quoteHandCases = []string{"", "d.1", "1abc", "t.1x", "v$session", "$x", "a.$b", "SYSTEM$TYPEOF", "1$", "*", "t.*", "é", "naïve", "x١", "١x", "a..b", ".a", "a.", "Ā"}

func TestIdentifierNeedsQuoting_MatchesReference(t *testing.T) {
	t.Parallel()
	check := func(s string) {
		want := identifierNeedsQuotingRef(s)
		if got := identifierNeedsQuoting(s); got != want {
			t.Fatalf("identifierNeedsQuoting(%q) = %v, want %v", s, got, want)
		}
		if got := identifierNeedsQuotingRunes(s); got != want {
			t.Fatalf("identifierNeedsQuotingRunes(%q) = %v, want %v", s, got, want)
		}
	}
	for _, s := range quoteHandCases {
		check(s)
	}
	check("")
	for a := 0; a < 256; a++ {
		check(string([]byte{byte(a)}))
		for b := 0; b < 256; b++ {
			check(string([]byte{byte(a), byte(b)}))
		}
	}
	pieces := []string{"a", "Z", "_", "*", ".", "$", "0", "9", "-", " ", "\"", "`", "@", "#", "\x00", "\x7f", "\x80", "\xff", "é", "١", "\u0301", "\ufffd", "ǅ"}
	var walk func(string, int)
	walk = func(s string, n int) {
		if n == 0 {
			check(s)
			return
		}
		for _, p := range pieces {
			walk(s+p, n-1)
		}
	}
	walk("", 3)
	walk("", 4)
}

func TestIsReservedName_MatchesReference(t *testing.T) {
	t.Parallel()
	check := func(s string) {
		for _, table := range []bool{false, true} {
			if got, want := isReservedName(s, table), isReservedNameRef(s, table); got != want {
				t.Fatalf("isReservedName(%q,%v) = %v, want %v", s, table, got, want)
			}
		}
	}
	for w := range reservedNameWords {
		alt := []byte(strings.ToLower(w))
		for i := 0; i < len(alt); i += 2 {
			if alt[i] >= 'a' && alt[i] <= 'z' {
				alt[i] -= 'a' - 'A'
			}
		}
		title := strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		for _, s := range []string{w, strings.ToLower(w), title, string(alt)} {
			for _, variant := range []string{s, s + "X", s + "_", s + "1", "_" + s, s[:len(s)-1], s[:len(s)-1] + string(s[len(s)-1]+1)} {
				check(variant)
			}
		}
	}
	check("")
	for a := 0; a < 256; a++ {
		check(string([]byte{byte(a)}))
		for b := 0; b < 256; b++ {
			check(string([]byte{byte(a), byte(b)}))
		}
	}
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_0123456789$"
	for i := range alpha {
		for j := range alpha {
			for k := range alpha {
				check(string([]byte{alpha[i], alpha[j], alpha[k]}))
			}
		}
	}
	for _, n := range []int{15, 16, 17} {
		check(strings.Repeat("A", n))
		check(strings.Repeat("a", n))
		check(strings.Repeat("_", n))
	}
}

func FuzzQuoteFastPath(f *testing.F) {
	for _, s := range quoteHandCases {
		f.Add(s)
	}
	for w := range reservedNameWords {
		f.Add(w)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := identifierNeedsQuoting(s), identifierNeedsQuotingRef(s); got != want {
			t.Fatalf("identifier %q: got %v want %v", s, got, want)
		}
		for _, table := range []bool{false, true} {
			if got, want := isReservedName(s, table), isReservedNameRef(s, table); got != want {
				t.Fatalf("reserved %q table=%v: got %v want %v", s, table, got, want)
			}
		}
	})
}

var quoteBenchNames = []string{"id", "name", "users", "orders", "o", "u", "created_at", "status", "amount", "customer_id", "total", "email", "price", "quantity", "p", "c", "order_date", "product_id", "department", "salary", "employees", "t1", "x", "region", "revenue", "event_time", "user_id", "count", "a", "b", "select", "from", "Order", "key", "table", "db.users", "s.t"}
var quoteBenchSink bool

func BenchmarkIdentifierNeedsQuoting(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, s := range quoteBenchNames {
			quoteBenchSink = identifierNeedsQuoting(s)
		}
	}
}
func BenchmarkIsReservedName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, s := range quoteBenchNames {
			quoteBenchSink = isReservedName(s, true)
		}
	}
}

func TestReservedNameIndex_Invariants(t *testing.T) {
	t.Parallel()
	if len(reservedNameEntries) != len(reservedNameWords) {
		t.Fatalf("entry count %d, want %d", len(reservedNameEntries), len(reservedNameWords))
	}
	seen := make(map[string]int)
	for c := range reservedNameIndex {
		for n, bucket := range reservedNameIndex[c] {
			end := int(bucket.start) + int(bucket.n)
			if end > len(reservedNameEntries) {
				t.Fatalf("bucket %d/%d out of bounds", c, n)
			}
			for _, entry := range reservedNameEntries[int(bucket.start):end] {
				word := strings.TrimRight(string(entry.word[:]), "\x00")
				if len(word) != n || len(word) < 2 || word[0] != byte(c)+'A' {
					t.Fatalf("invalid bucket %d/%d entry %q", c, n, word)
				}
				for i := range word {
					if !(word[i] >= 'A' && word[i] <= 'Z' || word[i] == '_') {
						t.Fatalf("invalid word %q", word)
					}
				}
				all, ok := reservedNameWords[word]
				if !ok || all != entry.everyPosition {
					t.Fatalf("entry mismatch %q", word)
				}
				seen[word]++
			}
		}
	}
	for w := range reservedNameWords {
		if len(w) < 2 || len(w) > maxReservedNameLen || w[0] < 'A' || w[0] > 'Z' {
			t.Fatalf("invalid key %q", w)
		}
		for i := range w {
			if !(w[i] >= 'A' && w[i] <= 'Z' || w[i] == '_') {
				t.Fatalf("invalid key %q", w)
			}
		}
		if seen[w] != 1 {
			t.Fatalf("key %q occurs %d times", w, seen[w])
		}
	}
}

func TestIdentifierByteClass_NonASCII(t *testing.T) {
	t.Parallel()
	for i := 0x80; i < 256; i++ {
		if identifierByteClass[i] != identifierByteNonASCII {
			t.Fatalf("byte %#x is not classified as non-ASCII", i)
		}
	}
}
