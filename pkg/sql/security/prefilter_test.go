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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
)

// equivalenceCorpus returns a deterministic set of ScanSQL inputs used to check
// that the literal prefilters never change findings. It combines the repository
// SQL corpus, the fuzz seeds, case/whitespace obfuscations, Unicode case-fold
// tricks, near-misses, structural edge cases and payloads beyond the former 10,000-byte cap.
func equivalenceCorpus(t testing.TB) []string {
	t.Helper()

	var corpus []string

	// (a) Every *.sql file under the repository testdata directory.
	root := filepath.Join("..", "..", "..", "testdata")
	if info, err := os.Stat(root); err == nil && info.IsDir() {
		var paths []string
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".sql") {
				paths = append(paths, path)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", root, walkErr)
		}
		sort.Strings(paths)
		for _, p := range paths {
			data, err := os.ReadFile(p) // #nosec G304 -- test corpus under testdata
			if err != nil {
				t.Fatalf("reading %s: %v", p, err)
			}
			corpus = append(corpus, string(data))
		}
	}

	// (b) Fuzz seeds (kept in sync with FuzzScanSQL).
	corpus = append(corpus,
		"SELECT 1",
		"SELECT * FROM users WHERE id = 1",
		"INSERT INTO users (name, email) VALUES ('Alice', 'a@b.com')",
		"UPDATE users SET name = 'Bob' WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
		"CREATE TABLE t (id INT PRIMARY KEY)",
		"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"SELECT COUNT(*) FROM t GROUP BY a HAVING COUNT(*) > 1",
		"SELECT CAST(price AS INTEGER) FROM products",
		"SELECT * FROM users WHERE 1=1",
		"SELECT * FROM users WHERE 'a'='a'",
		"SELECT * FROM users WHERE id=1 OR 1=1",
		"SELECT * FROM users WHERE id=1--",
		"SELECT * FROM users WHERE id=1/**/",
		"SELECT * FROM users WHERE id=1#",
		"admin'--",
		"SELECT * FROM users UNION SELECT username, password FROM admin",
		"' UNION SELECT 1,2,3--",
		"1 UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
		"SELECT 1; DROP TABLE users",
		"SELECT 1; DELETE FROM users",
		"'; DROP TABLE users--",
		"SELECT SLEEP(5)",
		"SELECT * FROM users WHERE id=1 AND SLEEP(5)",
		"SELECT pg_sleep(5)",
		"'; WAITFOR DELAY '0:0:5'--",
		"SELECT LOAD_FILE('/etc/passwd')",
		"EXEC xp_cmdshell('dir')",
		"SELECT UTL_HTTP.REQUEST('http://evil.com')",
		"EXEC sp_executesql N'SELECT 1'",
		"PREPARE stmt FROM 'SELECT 1'",
		"SELECT * FROM users WHERE id=1 AND 1=1",
		"SELECT * FROM users WHERE id=1 AND 1=2",
		"SELECT * FROM users WHERE id=1 AND SUBSTRING(username,1,1)='a'",
		"",
		";;;",
		"SELECT",
		"' OR ''='",
		"1' AND '1'='1",
		"admin' OR '1'='1' /*",
		string(make([]byte, 10000)),
		"ſleep(1)",
		"BENCHMARK(1,1)",
	)

	// (c) Case and whitespace obfuscation.
	corpus = append(corpus,
		"sElEcT 1 wHeRe 1=1 oR tRuE",
		"x UnIoN/**/sElEcT NuLl,NuLl",
		"x UnIoN sElEcT NuLl,NuLl",
		"x uNiOn AlL sElEcT nUlL, NULL , null FROM t",
		"WAITFOR\tDELAY '0:0:5'",
		"wAiTfOr\n\tdElAy '0:0:5'",
		"InFoRmAtIoN_sChEmA.tables",
		"; dRoP TABLE t",
		";\n\tExEcUtE x",
		"exec(",
		"ExEc   (@x)",
		"EXECUTE   IMMEDIATE 'x'",
		"PREPARE s FROM 'x'",
		"pRePaRe   s1\tfRoM 'x'",
		"INTO    OUTFILE '/x'",
		"iNtO DuMpFiLe '/x'",
		"xP_cMdShElL",
		"Sp_ExEcUtEsQl",
		"sP_oAcReAtE",
		"uTl_HtTp.request('x')",
		"DbMs_LdAp.init",
		"DbMs_LoCk.SlEeP(5)",
		"eXeC   MaStEr..xp_dirtree",
		"lOaD_fIlE ('/x')",
		"Pg_SlEeP (1)",
		"SELECT * FROM t WHERE a=1 --",
		"SELECT * FROM t WHERE a=1 --   ",
		"SELECT * FROM t WHERE a='x'-- '",
		"a /*! x */",
		"a /* c */",
		"a /** c **/   ",
		"x #",
		"x #\t ",
		"SELECT 1; --",
	)

	// Unicode simple-fold tricks: U+017F (long s) and U+212A (Kelvin sign) match
	// ASCII 's' and 'k' under (?i).
	corpus = append(corpus,
		"ſleep(1)",
		"SLEEP(1)",
		"pg_ſleep(1)",
		"BENCHMARK(1,1)",
		"DBMS_LOCK.SLEEP(1)",
		"DBMS_LOCK.ſLEEP(1)",
		"ſp_executesql",
		"ſp_oacreate",
		"xp_cmdſhell",
		"union ſelect null,null",
		"union all ſelect null,null from information_ſchema.tables",
		"or True",
		"x OR TRUE y",
		"BENCHMARK(1,1)",
		"KILL; DROP TABLE t",
		"; DROP TABLE Kelvin",
		"or true K ſ",
		"; ExEcUte ſp_x",
		"ü UNION SELECT NULL, NULL",
		"日本語 WAITFOR DELAY '1'",
	)

	// Near-misses: contain a prefilter literal but must not match the regex.
	corpus = append(corpus,
		"sleepy_user",
		"SELECT sleep_time FROM t",
		"unionized",
		"union_select_x",
		"truely",
		"orange true",
		"executed_at",
		"exec_time",
		"master_data",
		"semicolon;in;string",
		"select information_schemas from t",
		"SELECT 'a' = 'b'",
		"SELECT 1 = 2",
		"SELECT a = b",
		"prepare from",
		"into outfiles",
	)

	// Structural edge cases.
	corpus = append(corpus,
		"",
		" ",
		";",
		";;;",
		"--",
		"/*",
		"$$",
		"$tag$ SLEEP(1) $tag$",
		"$$; DROP TABLE t$$",
		"$$; DROP TABLE t$$; DROP TABLE u",
		"$a$ x $b$ y $a$ SLEEP(1)",
		"$unterminated$ SLEEP(1)",
		"SELECT $1",
		"SELECT $1, $2 WHERE a = $3",
		"\xff\xfeSLEEP(1)",
		"\xff\xfe\xfd",
		"SLEEP\xff(1)",
		"\x00SLEEP(1)",
	)

	// Length edges: payloads after the former 10,000-byte cap.
	pad := strings.Repeat("SELECT 1 ", 1200)
	corpus = append(corpus,
		pad+" UNION SELECT NULL,NULL FROM information_schema.tables",
		pad+" -- ",
		pad+" OR 1=1",
		pad+" WHERE 'a'='a' AND SLEEP(5)",
		pad+"; DROP TABLE t --",
		pad+" ſleep(1)",
		strings.Repeat("SELECT a, b, c FROM t WHERE x = 1 ORDER BY a; ", 1600), // ~70 KiB clean
	)

	return corpus
}

// TestRequiredLiterals_Golden pins the literal prefilter derived for every pattern
// expression. If a pattern changes, re-derive and review the literal set: each
// literal must be a substring of every possible match of its regex.
func TestRequiredLiterals_Golden(t *testing.T) {
	tests := []struct {
		expr string
		want []string
	}{
		// Time-based
		{`(?i)\bSLEEP\s*\(`, []string{"sleep", "("}},
		{`(?i)\bWAITFOR\s+DELAY\b`, []string{"waitfor", "delay"}},
		{`(?i)\bpg_sleep\s*\(`, []string{"pg_sleep", "("}},
		{`(?i)\bBENCHMARK\s*\(`, []string{"benchmark", "("}},
		{`(?i)\bDBMS_LOCK\.SLEEP\s*\(`, []string{"dbms_lock.sleep", "("}},
		// Out-of-band
		{`(?i)\bxp_cmdshell\b`, []string{"xp_cmdshell"}},
		{`(?i)\bLOAD_FILE\s*\(`, []string{"load_file", "("}},
		{`(?i)\bINTO\s+OUTFILE\b`, []string{"into", "outfile"}},
		{`(?i)\bINTO\s+DUMPFILE\b`, []string{"into", "dumpfile"}},
		{`(?i)\bUTL_HTTP\b`, []string{"utl_http"}},
		{`(?i)\bDBMS_LDAP\b`, []string{"dbms_ldap"}},
		{`(?i)\bEXEC\s+master\b`, []string{"exec", "master"}},
		{`(?i)\bsp_oacreate\b`, []string{"sp_oacreate"}},
		// Dangerous functions
		{`(?i)\bEXEC\s*\(`, []string{"exec", "("}},
		{`(?i)\bEXECUTE\s+IMMEDIATE\b`, []string{"execute", "immediate"}},
		{`(?i)\bsp_executesql\b`, []string{"sp_executesql"}},
		{`(?i)\bPREPARE\s+\w+\s+FROM\b`, []string{"prepare", "from"}},
		// Tautology
		{`(?i)\bOR\s+TRUE\b`, []string{"or", "true"}},
		// UNION
		{`(?i)UNION\s+(ALL\s+)?SELECT.*\b(information_schema|pg_catalog|mysql\b|sys\.)\b`, []string{"union", "select"}},
		{`(?i)UNION\s+(ALL\s+)?SELECT\s+(?:NULL,?\s*){2,}`, []string{"union", "select", "null"}},
		{`(?i)\binformation_schema\b`, []string{"information_schema"}},
		{`(?i)\bUNION\s+(ALL\s+)?SELECT\b`, []string{"union", "select"}},
		// Stacked queries
		{`;\s*(?i)(DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER)\b`, []string{";"}},
		{`;\s*(?i)EXEC\b`, []string{";", "exec"}},
		{`;\s*(?i)EXECUTE\b`, []string{";", "execute"}},
		// Comments
		{`--\s*$`, []string{"--"}},
		{`--\s*['")\]]`, []string{"--"}},
		{`/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*$`, []string{"/*", "*", "/"}},
		{`/\*!.*\*/`, []string{"/*!", "*/"}},
		{`#\s*$`, []string{"#"}},
		{`;\s*--`, []string{";", "--"}},
		// Tautology captures
		{`(?i)\b(\d{1,6})\s*=\s*(\d{1,6})\b`, []string{"="}},
		{`(?i)('[^']{0,50}')\s*=\s*('[^']{0,50}')`, []string{"'", "="}},
		{`(?i)\b([a-z_][a-z0-9_.]{0,50})\s*=\s*([a-z_][a-z0-9_.]{0,50})\b`, []string{"="}},
		// Edge cases
		{`(?i)é`, nil},        // non-ASCII literal dropped
		{`(?i)xé`, nil},       // run containing non-ASCII dropped entirely
		{`a|b`, nil},          // alternation contributes nothing
		{`(ab)*`, nil},        // star contributes nothing
		{`x+`, []string{"x"}}, // plus contributes its body
		{`(?i)ab{2,}`, []string{"ab", "b"}},
		{`(?i)ab{0,3}c`, []string{"a", "c"}},
		{`abc(?:def)?ghi`, []string{"abc", "ghi"}},
		{`[`, nil}, // unparsable: no prefilter
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			var got []string
			for _, l := range requiredLiterals(tt.expr) {
				got = append(got, string(l))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("requiredLiterals(%q) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}

// allCompiledPatterns returns every compiled pattern used by ScanSQL.
func allCompiledPatterns(t *testing.T) []compiledPattern {
	t.Helper()
	NewScanner() // initialize the package-level tables
	var all []compiledPattern
	for _, pt := range []PatternType{
		PatternTautology, PatternTimeBased, PatternOutOfBand, PatternDangerousFunc,
		PatternUnionInjection, PatternUnionGeneric, PatternStackedQuery,
	} {
		g, ok := regexGroups[pt]
		if !ok {
			t.Fatalf("regexGroups missing %s", pt)
		}
		all = append(all, g.patterns...)
	}
	for _, p := range commentPatterns {
		all = append(all, p.compiledPattern)
	}
	all = append(all, tautologyCapturePatterns...)
	return all
}

// TestCompiledPatterns_AllHaveLiterals ensures every prefilter is non-vacuous and
// sound for foldASCII (lowercase ASCII only), and that no pattern matches the
// empty string (which justifies using FindString in detectRegexPatterns).
func TestCompiledPatterns_AllHaveLiterals(t *testing.T) {
	all := allCompiledPatterns(t)
	if len(all) != 36 {
		t.Errorf("expected 36 compiled patterns (27 group + 6 comment + 3 tautology), got %d", len(all))
	}
	for _, p := range all {
		if len(p.lits) == 0 {
			t.Errorf("%s: no required literal", p.re)
		}
		for _, l := range p.lits {
			if len(l) == 0 {
				t.Errorf("%s: empty literal", p.re)
			}
			for _, c := range l {
				if c >= utf8.RuneSelf || ('A' <= c && c <= 'Z') {
					t.Errorf("%s: literal %q is not lowercase ASCII", p.re, l)
				}
			}
		}
		if p.re.MatchString("") {
			t.Errorf("%s: matches the empty string", p.re)
		}
	}
}

func TestFoldASCII(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"SELECT Id", "select id"},
		{"ſleep", "sleep"},
		{"BENCHMAR\u212A", "benchmark"},
		{"BENCHMARK", "benchmark"},
		{"é", "é"},
		{"ÉTÉ", "ÉtÉ"},
		{"\xff\xfeX", "\xff\xfex"},
		{"a\x00B", "a\x00b"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := string(foldASCII(nil, tt.in)); got != tt.want {
			t.Errorf("foldASCII(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	// Appends to dst rather than overwriting it.
	if got := string(foldASCII([]byte("x:"), "AB")); got != "x:ab" {
		t.Errorf("foldASCII append = %q, want %q", got, "x:ab")
	}
}

// TestFoldASCII_Completeness fails if a Unicode table update ever adds a non-ASCII
// rune to the simple-fold orbit of an ASCII letter, which would make foldASCII
// (and therefore the prefilters) unsound for (?i) patterns.
func TestFoldASCII_Completeness(t *testing.T) {
	allowed := map[rune]byte{0x017F: 's', 0x212A: 'k'}
	for _, start := range []rune{'a', 'A'} {
		for i := rune(0); i < 26; i++ {
			c := start + i
			for r := unicode.SimpleFold(c); r != c; r = unicode.SimpleFold(r) {
				if r < utf8.RuneSelf {
					continue
				}
				want, ok := allowed[r]
				if !ok {
					t.Errorf("U+%04X folds with %q but foldASCII does not map it", r, c)
					continue
				}
				if got := foldASCII(nil, string(r)); string(got) != string(want) {
					t.Errorf("foldASCII(U+%04X) = %q, want %q", r, got, want)
				}
			}
		}
	}
}

// TestScanSQL_PrefilterEquivalence proves the literal prefilters never change
// findings: the prefiltered path must match the run-every-regex reference path.
func TestScanSQL_PrefilterEquivalence(t *testing.T) {
	high, err := NewScannerWithSeverity(SeverityHigh)
	if err != nil {
		t.Fatalf("NewScannerWithSeverity: %v", err)
	}
	scanners := map[string]*Scanner{"default": NewScanner(), "high": high}
	corpus := equivalenceCorpus(t)
	for name, s := range scanners {
		for i, in := range corpus {
			// Equivalence is not a concurrency property; under -race check a
			// quarter of the corpus and no large inputs. Non-race runs check all.
			if raceEnabled && (i%4 != 0 || len(in) > 16<<10) {
				continue
			}
			got := s.scanSQL(in, true)
			want := s.scanSQL(in, false)
			if !reflect.DeepEqual(got, want) {
				shown := in
				if len(shown) > 200 {
					shown = shown[:200] + "..."
				}
				t.Errorf("%s scanner, input %d %q:\n prefiltered: %+v\n reference:   %+v", name, i, shown, got, want)
			}
		}
	}
}

// TestScanSQL_Concurrent_FoldPool exercises fold-buffer pool reuse across
// goroutines (run under -race) and checks results never get contaminated.
func TestScanSQL_Concurrent_FoldPool(t *testing.T) {
	inputs := []string{
		"SELECT id, name FROM users WHERE active = true",
		"SELECT * FROM users WHERE id = 1 OR 1=1 --",
		"x UNION SELECT NULL, NULL FROM information_schema.tables",
		"SELECT ſleep(5); DROP TABLE t",
		strings.Repeat("SELECT a FROM t WHERE b = 2; ", 2500) + " SLEEP(1)", // > 64 KiB
		"",
		"$$ SLEEP(1) $$",
	}
	s := NewScanner()
	want := make([]*ScanResult, len(inputs))
	for i, in := range inputs {
		want[i] = s.ScanSQL(in)
	}

	// The race detector makes each 64 KiB+ scan ~20x slower; fewer iterations
	// still interleave every input across all goroutines.
	const goroutines = 32
	iterations := 200
	if raceEnabled {
		iterations = 25
	}
	var wg sync.WaitGroup
	errs := make(chan string, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				idx := (g + it) % len(inputs)
				if got := s.ScanSQL(inputs[idx]); !reflect.DeepEqual(got, want[idx]) {
					errs <- fmt.Sprintf("goroutine %d iteration %d input %d: got %+v want %+v", g, it, idx, got, want[idx])
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestScanSQL_ObfuscatedPayloadsDetected checks behaviour on case, whitespace
// and Unicode-fold obfuscations, and that near-misses stay clean.
func TestScanSQL_ObfuscatedPayloadsDetected(t *testing.T) {
	tests := []struct {
		name    string
		sql     string
		pattern PatternType
		want    bool
	}{
		// RE2's \b is ASCII-only, so U+017F can only stand in for 's' where no
		// word boundary is required before it.
		{"long s pg_sleep", "SELECT pg_ſleep(1)", PatternTimeBased, true},
		{"long s after word char", "SELECT xſleep(1)", PatternTimeBased, true},
		{"long s sp_executesql after word char", "EXEC xſp_executesql", PatternDangerousFunc, true},
		{"long s in information_schema", "SELECT * FROM information_ſchema.tables", PatternUnionInjection, true},
		{"benchmark", "SELECT BENCHMARK(1,1)", PatternTimeBased, true},
		{"kelvin benchmark", "SELECT BENCHMAR\u212A(1,1)", PatternTimeBased, true},
		{"mixed case union null", "x uNiOn SeLeCt NULL,NULL", PatternUnionInjection, true},
		{"waitfor tab", "x; WAITFOR\tDELAY '0:0:5'", PatternTimeBased, true},
		{"stacked drop", "x; dRoP TABLE x", PatternStackedQuery, true},
		{"info schema", "SELECT * FROM InFoRmAtIoN_sChEmA.tables", PatternUnionInjection, true},
		{"sleepy user", "SELECT sleepy_user FROM t", PatternTimeBased, false},
		{"unionized", "SELECT unionized FROM t", PatternUnionGeneric, false},
		{"executed at", "SELECT executed_at FROM t", PatternDangerousFunc, false},
	}
	s := NewScanner()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := s.ScanSQL(tt.sql)
			found := false
			for _, f := range res.Findings {
				if f.Pattern == tt.pattern {
					found = true
					break
				}
			}
			if found != tt.want {
				t.Errorf("ScanSQL(%q): found %s = %v, want %v (findings: %+v)", tt.sql, tt.pattern, found, tt.want, res.Findings)
			}
		})
	}
}
