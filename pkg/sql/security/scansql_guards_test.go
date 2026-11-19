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
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
	s.detectCommentPatterns(sql, scanPrefilter{}, result)
	views := append([]string{sql}, commentViews(sql)...)
	s.detectRegexPatterns(views, scanPrefilter{}, PatternTautology, result)
	s.detectTautologyInSQL(views, scanPrefilter{}, result)
	for _, pattern := range []PatternType{PatternTimeBased, PatternOutOfBand, PatternDangerousFunc, PatternUnionInjection, PatternUnionGeneric} {
		s.detectRegexPatterns(views, scanPrefilter{}, pattern, result)
	}
	stackedReference(s, views, result)
	s.updateCounts(result)
	return result
}

// TestScanSQLGuardsEquivalence ports the verifier's seeded differential harness.
// Compare entire results (including every finding field and order), rather than
// only detection counts. Race/short runs retain every corpus and Unicode case,
// plus the first 20k random cases; ordinary runs cover the full 200k set.
func TestScanSQLGuardsEquivalence(t *testing.T) {
	// Shared by the parallel subtests below; ScanSQL is safe for concurrent use.
	scanner := NewScanner()
	check := func(t *testing.T, sql string) {
		t.Helper()
		got, want := scanner.ScanSQL(sql), scanSQLRegexOnly(scanner, sql)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ScanSQL guard mismatch for %q:\n got: %+v\nwant: %+v", sql, got, want)
		}
	}
	// Each subtest owns a fixed-seed rng, so every input stays deterministic
	// while the subtests run in parallel (this sweep dominates the package's
	// race-test time).
	mutator := func(rng *rand.Rand) func(string) string {
		return func(sql string) string {
			for n := 1 + rng.Intn(3); n > 0; n-- {
				at := rng.Intn(len(sql) + 1)
				sql = sql[:at] + scanSQLGuardSeeds[rng.Intn(len(scanSQLGuardSeeds))] + sql[at:]
			}
			return sql
		}
	}
	const shards = 4
	root := filepath.Join("..", "..", "..", "testdata")
	for seed, name := range []string{"realworld", "corpus"} {
		files := loadScanSQLFiles(t, filepath.Join(root, name))
		statements := scanSQLStatements(files)
		for shard := 0; shard < shards; shard++ {
			t.Run(name+"/"+strconv.Itoa(shard), func(t *testing.T) {
				t.Parallel()
				mutate := mutator(rand.New(rand.NewSource(int64(7 + seed*shards + shard))))
				for i := shard; i < len(files); i += shards {
					check(t, files[i])
					check(t, mutate(files[i]))
				}
				for i := shard; i < len(statements); i += shards {
					check(t, statements[i])
					if i%3 == 0 {
						for n := 0; n < 4; n++ {
							check(t, mutate(statements[i]))
						}
					}
				}
			})
		}
	}
	t.Run("seeds", func(t *testing.T) {
		t.Parallel()
		for _, sql := range scanSQLGuardSeeds {
			check(t, sql)
		}
	})
	alphabet := []string{"a", "B", "x", "1", "=", " ", "\t", "$", "(", ")", "'", "url", "FROM ", "s3", " JOIN ", "$$", "_", ".", "ſ", "K", "--", ";"}
	randomCases := 200000
	if testing.Short() || raceEnabled {
		randomCases = 20000
	}
	t.Logf("checking %d seeded random/mutated inputs plus all corpus and seed cases", randomCases)
	for shard := 0; shard < shards; shard++ {
		t.Run("random/"+strconv.Itoa(shard), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewSource(int64(100 + shard)))
			mutate := mutator(rng)
			for i := shard; i < randomCases; i += shards {
				var sql strings.Builder
				for n := rng.Intn(14); n > 0; n-- {
					sql.WriteString(alphabet[rng.Intn(len(alphabet))])
				}
				input := sql.String()
				// Include both random inputs and mutations throughout the seeded sample.
				if i%4 == 0 {
					input = mutate(input)
				}
				check(t, input)
			}
		})
	}
}

// The unequal suffix forces every candidate comparison to fail at its last
// byte. Quadrupling input size must not quadruple both candidate count and
// comparison length. Minima reduce scheduler noise; the generous ratio permits
// linear scanning overhead without imposing an absolute timing threshold.
func TestHasEqualIdentPairLinear(t *testing.T) {
	input := func(size int) string {
		n := (size - 2) / 2
		return strings.Repeat("a", n) + "b=" + strings.Repeat("a", size-n-2)
	}
	sample := func(sql string) time.Duration {
		t.Helper()
		start := time.Now()
		for repeat := 0; repeat < 4; repeat++ {
			if hasEqualIdentPair(sql) {
				t.Fatal("unequal identifier suffix unexpectedly passed guard")
			}
		}
		return time.Since(start)
	}
	// Interleave the two sizes and keep each one's fastest round, so CPU
	// contention from tests running in parallel (other packages, parallel
	// subtests) hits both sizes alike instead of skewing the ratio.
	smallSQL, largeSQL := input(16*1024), input(64*1024)
	var small, large time.Duration
	for round := 0; round < 9; round++ {
		if s := sample(smallSQL); round == 0 || s < small {
			small = s
		}
		if l := sample(largeSQL); round == 0 || l < large {
			large = l
		}
	}
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
