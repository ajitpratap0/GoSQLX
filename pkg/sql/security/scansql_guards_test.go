// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These are the verifier's mutation vocabulary, plus boundary and Unicode
// folding cases for the necessary-condition guards. Share them with fuzzing.
var scanSQLGuardSeeds = []string{
	" OR 1=1", " or a = A", " x=x ", "'a'='a'", " FROM url('http://x') ",
	" JOIN  s3 (", "from\tFile (", " $$ x $$ ", " $1 ", "$tag$ y $tag$", " WHERE id=id",
	"ſ=s", "k = K", ";DROP TABLE x", " -- ", " UNION SELECT NULL,NULL ", "$", "$$",
	"a.b=a.b", " from remote\v(", " FROM mysql (", "from redis(", " FROM s3Cluster (",
	"FROM poſtgresql(", "JOIN ſqlite(", "FROM executable(K)", "s=ſ", "K=k",
	"a$$ OR 1=1 $$", "$1 OR 1=1", "$tag$ OR 1=1 $tag$", "\xffa=a",
}

func loadScanSQLFiles(t testing.TB, root string) []string {
	t.Helper()
	var inputs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- repository test corpus
		if err != nil {
			return err
		}
		inputs = append(inputs, string(data))
		return nil
	})
	if err != nil {
		t.Fatalf("load SQL corpus %s: %v", root, err)
	}
	if len(inputs) == 0 {
		t.Fatalf("no SQL files in %s", root)
	}
	return inputs
}

func scanSQLStatements(files []string) []string {
	var statements []string
	for _, file := range files {
		for _, statement := range strings.Split(file, ";\n") {
			if statement = strings.TrimSpace(statement); statement != "" {
				statements = append(statements, statement)
			}
		}
	}
	return statements
}

// scanSQLRegexOnly keeps the pre-guard orchestration and dollar-quote handling
// independent of all three guards under test. A nil folded slice runs every
// regex, retaining the production regexes and finding construction verbatim.
func scanSQLRegexOnly(s *Scanner, sql string) *ScanResult {
	result := &ScanResult{Findings: make([]Finding, 0)}
	sql = stripDollarQuotedStringsReference(sql)
	s.detectCommentPatterns(sql, nil, result)
	views := append([]string{sql}, commentViews(sql)...)
	s.detectRegexPatterns(views, nil, PatternTautology, result)
	s.detectTautologyInSQL(views, nil, result)
	for _, pattern := range []PatternType{PatternTimeBased, PatternOutOfBand, PatternDangerousFunc, PatternUnionInjection, PatternUnionGeneric, PatternStackedQuery} {
		s.detectRegexPatterns(views, nil, pattern, result)
	}
	s.updateCounts(result)
	return result
}

// TestScanSQLGuardsEquivalence ports the verifier's seeded differential harness.
// Compare entire results (including every finding field and order), rather than
// only detection counts. Race/short runs retain every corpus and Unicode case,
// plus the first 20k random cases; ordinary runs cover the full 200k set.
func TestScanSQLGuardsEquivalence(t *testing.T) {
	scanner := NewScanner()
	check := func(sql string) {
		t.Helper()
		got, want := scanner.ScanSQL(sql), scanSQLRegexOnly(scanner, sql)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ScanSQL guard mismatch for %q:\n got: %+v\nwant: %+v", sql, got, want)
		}
	}
	rng := rand.New(rand.NewSource(7))
	mutate := func(sql string) string {
		for n := 1 + rng.Intn(3); n > 0; n-- {
			at := rng.Intn(len(sql) + 1)
			sql = sql[:at] + scanSQLGuardSeeds[rng.Intn(len(scanSQLGuardSeeds))] + sql[at:]
		}
		return sql
	}
	root := filepath.Join("..", "..", "..", "testdata")
	for _, name := range []string{"realworld", "corpus"} {
		files := loadScanSQLFiles(t, filepath.Join(root, name))
		for _, file := range files {
			check(file)
			check(mutate(file))
		}
		for i, statement := range scanSQLStatements(files) {
			check(statement)
			if i%3 == 0 {
				for n := 0; n < 4; n++ {
					check(mutate(statement))
				}
			}
		}
	}
	for _, sql := range scanSQLGuardSeeds {
		check(sql)
	}
	alphabet := []string{"a", "B", "x", "1", "=", " ", "\t", "$", "(", ")", "'", "url", "FROM ", "s3", " JOIN ", "$$", "_", ".", "ſ", "K", "--", ";"}
	randomCases := 200000
	if testing.Short() || raceEnabled {
		randomCases = 20000
	}
	t.Logf("checking %d seeded random/mutated inputs plus all corpus and seed cases", randomCases)
	for i := 0; i < randomCases; i++ {
		var sql strings.Builder
		for n := rng.Intn(14); n > 0; n-- {
			sql.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		input := sql.String()
		// Include both random inputs and mutations throughout the seeded sample.
		if i%4 == 0 {
			input = mutate(input)
		}
		check(input)
	}
}

// The unequal suffix forces every candidate comparison to fail at its last
// byte. Quadrupling input size must not quadruple both candidate count and
// comparison length. Minima reduce scheduler noise; the generous ratio permits
// linear scanning overhead without imposing an absolute timing threshold.
func TestHasEqualIdentPairLinear(t *testing.T) {
	measure := func(size int) time.Duration {
		t.Helper()
		n := (size - 2) / 2
		sql := strings.Repeat("a", n) + "b=" + strings.Repeat("a", size-n-2)
		var best time.Duration
		for sample := 0; sample < 3; sample++ {
			start := time.Now()
			for repeat := 0; repeat < 4; repeat++ {
				if hasEqualIdentPair(sql) {
					t.Fatal("unequal identifier suffix unexpectedly passed guard")
				}
			}
			elapsed := time.Since(start)
			if sample == 0 || elapsed < best {
				best = elapsed
			}
		}
		return best
	}
	small, large := measure(16*1024), measure(64*1024)
	t.Logf("16 KiB: %v; 64 KiB: %v; ratio %.2f", small, large, float64(large)/float64(small))
	if large > 10*small {
		t.Fatalf("identifier guard scaling exceeds linear allowance: 16 KiB=%v, 64 KiB=%v", small, large)
	}
}

// stripDollarQuotedStringsReference is the pre-guard implementation.
func stripDollarQuotedStringsReference(sql string) string {
	if strings.IndexByte(sql, '$') < 0 {
		return sql
	}
	// Cross product of escapes, nesting, bracket identifiers, hash comments and
	// PostgreSQL E-string-only escapes.
	var states [32]sqlLexState
	resetDollarStates(&states)
	var out strings.Builder
	start := 0
	for i := 0; i < len(sql); i++ {
		code := true
		for j := range states {
			code = code && states[j].code()
		}
		if code && sql[i] == '$' && (i == 0 || !identifierByte(sql[i-1])) {
			if end := dollarTagEnd(sql, i); end != 0 {
				tag := sql[i:end]
				closeAt := strings.Index(sql[end:], tag)
				if closeAt < 0 {
					break
				}
				if start == 0 {
					out.Grow(len(sql))
				}
				out.WriteString(sql[start:end])
				out.WriteString(tag)
				i = end + closeAt + len(tag) - 1
				start = i + 1
				resetDollarStates(&states)
				continue
			}
		}
		for j := range states {
			states[j].step(sql, i, j&1 != 0, j&2 != 0, j&8 != 0, j&4 != 0)
		}
	}
	if start == 0 {
		return sql
	}
	out.WriteString(sql[start:])
	return out.String()
}
