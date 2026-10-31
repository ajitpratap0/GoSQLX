// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/scaletest"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func wpPHasPattern(result *ScanResult, pattern PatternType) bool {
	for _, f := range result.Findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

func TestWPPDollarOpenersRespectLexicalContext(t *testing.T) {
	for _, prefix := range []string{
		`SELECT '$tag$'`, `SELECT "$tag$"`, "SELECT `$tag$`",
		"SELECT 1 -- $tag$\n", "SELECT 1 # $tag$\n",
		"SELECT 1 /* $tag$ */", "SELECT 1 /* outer /* $tag$ */ outer */",
	} {
		t.Run(prefix, func(t *testing.T) {
			sql := prefix + " ; DROP TABLE accounts; SELECT $tag$"
			if !wpPHasPattern(NewScanner().ScanSQL(sql), PatternStackedQuery) {
				t.Fatalf("false dollar opener hid executable DROP: %q", sql)
			}
		})
	}
	for _, sql := range []string{
		`SELECT foo$tag$; DROP TABLE accounts; $tag$`,
		`SELECT foo$$; DROP TABLE accounts; $$`,
		`SELECT $9tag$; DROP TABLE accounts; $9tag$`,
		`SELECT $bad-tag$; DROP TABLE accounts; $bad-tag$`,
		`SELECT 'backslash\' $tag$; DROP TABLE accounts; $tag$`,
	} {
		t.Run(sql, func(t *testing.T) {
			if !wpPHasPattern(NewScanner().ScanSQL(sql), PatternStackedQuery) {
				t.Fatalf("ambiguous or invalid dollar opener hid DROP: %q", sql)
			}
		})
	}
	for _, sql := range []string{
		`SELECT $$; DROP TABLE accounts; SLEEP(1)$$`,
		`SELECT $_tag9$; DROP TABLE accounts; SLEEP(1)$_tag9$`,
		`SELECT $tag$' -- /* ; DROP TABLE accounts $tag$`,
	} {
		if result := NewScanner().ScanSQL(sql); result.HasHighOrAbove() {
			t.Errorf("dollar literal body was scanned: %q: %+v", sql, result.Findings)
		}
	}
}

func TestWPPStripDollarQuotedStringsLexicalRules(t *testing.T) {
	for _, sql := range []string{
		`SELECT '$tag$' ; DROP TABLE t; $tag$`,
		`SELECT "$tag$" ; DROP TABLE t; $tag$`,
		"SELECT `$tag$` ; DROP TABLE t; $tag$",
		"SELECT 1 -- $tag$\n; DROP TABLE t; $tag$",
		"SELECT 1 # $tag$\n; DROP TABLE t; $tag$",
		"SELECT 1 /* $tag$ */; DROP TABLE t; $tag$",
		"SELECT 1 /* outer /* inner */ $tag$ outer */; DROP TABLE t; $tag$",
		`SELECT 'a''$tag$' ; DROP TABLE t; $tag$`,
		`SELECT "a""$tag$" ; DROP TABLE t; $tag$`,
		"SELECT `a``$tag$` ; DROP TABLE t; $tag$",
		`SELECT 'backslash\' $tag$; DROP TABLE t; $tag$`,
		`SELECT foo$tag$; DROP TABLE t; $tag$`,
		`SELECT 名$tag$; DROP TABLE t; $tag$`,
		`SELECT foo$$; DROP TABLE t; $$`,
		`SELECT $9tag$; DROP TABLE t; $9tag$`,
		`SELECT $bad-tag$; DROP TABLE t; $bad-tag$`,
	} {
		if got := stripDollarQuotedStrings(sql); got != sql {
			t.Errorf("strip changed non-opener context: %q -> %q", sql, got)
		}
	}
	for _, tt := range []struct{ sql, want string }{
		{"SELECT $$payload$$", "SELECT $$$$"},
		{"SELECT $_tag9$payload$_tag9$", "SELECT $_tag9$$_tag9$"},
		{"SELECT $Case$payload$Case$", "SELECT $Case$$Case$"},
		{"SELECT $Case$payload$case$", "SELECT $Case$payload$case$"},
		{"SELECT $tag$unterminated", "SELECT $tag$unterminated"},
	} {
		if got := stripDollarQuotedStrings(tt.sql); got != tt.want {
			t.Errorf("strip(%q) = %q, want %q", tt.sql, got, tt.want)
		}
	}
}

type wpPBypassCase struct {
	name, sql string
	pattern   PatternType
}

func wpPCommentBypasses() []wpPBypassCase {
	return []wpPBypassCase{
		{"union empty", "SELECT 1 UNION/**/SELECT 2", PatternUnionGeneric},
		{"union all", "SELECT 1 UNION/*a*/ALL/*b*/SELECT 2", PatternUnionGeneric},
		{"union adjacent", "SELECT 1 UNION/*a*//*b*/SELECT 2", PatternUnionGeneric},
		{"union mixed case", "SELECT 1 UnIoN/*x*/aLl/**/sElEcT 2", PatternUnionGeneric},
		{"union nested", "SELECT 1 UNION/* outer /* inner */ outer */SELECT 2", PatternUnionGeneric},
		{"union line", "SELECT 1 UNION-- ignored\nSELECT 2", PatternUnionGeneric},
		{"null padding", "SELECT 1,2 UNION/**/SELECT/**/NULL,/**/NULL", PatternUnionInjection},
		{"sleep", "SELECT SLEEP/**/(5)", PatternTimeBased},
		{"pg sleep", "SELECT pg_sleep/*pause*/(5)", PatternTimeBased},
		{"waitfor", "WAITFOR/*pause*/DELAY '0:0:5'", PatternTimeBased},
		{"stacked", "SELECT 1;/*pause*/DROP TABLE accounts", PatternStackedQuery},
		{"stacked line", "SELECT 1;-- ignored\nDROP TABLE accounts", PatternStackedQuery},
		{"numeric tautology", "SELECT 1 WHERE x=2 OR/**/1/*x*/=/*x*/1", PatternTautology},
		{"true tautology", "SELECT 1 WHERE x=2 OR/*x*/TRUE", PatternTautology},
		{"executable comment", "SELECT 1 /*! UNION SELECT NULL,NULL */", PatternUnionInjection},
		{"versioned executable comment", "SELECT 1 /*!50000 UNION SELECT NULL,NULL */", PatternUnionInjection},
		{"tight versioned union", "SELECT 1 /*!50000UNION*/ SELECT password FROM users", PatternUnionGeneric},
		{"executable stacked", "SELECT * FROM t; /*!DROP TABLE users*/", PatternStackedQuery},
	}
}

func wpPRound2Bypasses() []wpPBypassCase {
	return []wpPBypassCase{
		{"escaped single union", `SELECT 1 FROM t WHERE a='\'' UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"escaped E string union", `SELECT 1 FROM t WHERE a=E'\'' UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"escaped single stacked", `SELECT 1 FROM t WHERE a='\'' ;/**/DROP TABLE x`, PatternStackedQuery},
		{"escaped single tautology", `SELECT 1 FROM t WHERE a='\'' OR /**/ 1 /**/ = /**/ 1`, PatternTautology},
		{"three backslashes union", `SELECT 'a\\\'' UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"escaped double dollar opener", `SELECT "a\" $a$ " ; DROP TABLE users; -- $a$`, PatternStackedQuery},
		{"escaped double union", `SELECT "\"" UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"bracket dollar opener", `SELECT [a $x$ ]; DROP TABLE users; SELECT 1 AS [$x$]`, PatternStackedQuery},
		{"bracket quote union", `SELECT [a'] UNION/**/SELECT 1,2 FROM [b']`, PatternUnionGeneric},
		{"hash union", "SELECT 1 UNION#\nSELECT 2", PatternUnionGeneric},
		{"mysql dash arithmetic union", `SELECT 1--1 UNION/**/SELECT 2`, PatternUnionGeneric},
		{"mysql dash arithmetic stacked", `SELECT 1--1 ;/**/DROP TABLE x`, PatternStackedQuery},
		{"pg E string then plain backslash union", `SELECT E'\'', 'a\' UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"pg E string then plain backslash stacked", `SELECT E'\'', 'a\' ;/**/DROP TABLE x`, PatternStackedQuery},
		{"pg plain E plain union", `SELECT 'a\' || E'\'' || 'b\' UNION/**/SELECT 1,2`, PatternUnionGeneric},
		{"pg E string dollar opener", `SELECT E'\'', 'a\' $x$'; DROP TABLE users; SELECT '$x$'`, PatternStackedQuery},
		{"hash stacked", "SELECT 1 ;#\nDROP TABLE x", PatternStackedQuery},
		{"hash sleep", "SELECT SLEEP#\n(5)", PatternTimeBased},
		{"overlapping comment union", "SELECT 1 /* x /*/ UNION/**/SELECT 2", PatternUnionGeneric},
		{"overlapping comment sleep", "SELECT 1 /* x /*/ SLEEP/**/(5)", PatternTimeBased},
		{"mariadb executable union", "SELECT 1 /*M!100100 UNION*/ /*M!100100 SELECT 2*/", PatternUnionGeneric},
		{"vertical tab union", "SELECT 1 UNION\vSELECT 2", PatternUnionGeneric},
		{"form feed union", "SELECT 1 UNION\fSELECT 2", PatternUnionGeneric},
	}
}

func TestWPPRound2Bypasses(t *testing.T) {
	for _, tt := range wpPRound2Bypasses() {
		t.Run(tt.name, func(t *testing.T) {
			result := NewScanner().ScanSQL(tt.sql)
			found := false
			for _, f := range result.Findings {
				if f.Pattern == tt.pattern {
					found = true
					if f.Severity != SeverityHigh && f.Severity != SeverityCritical {
						t.Errorf("%s severity = %s, want HIGH or CRITICAL", tt.pattern, f.Severity)
					}
				}
			}
			if !found {
				t.Errorf("missing %s for %q: %+v", tt.pattern, tt.sql, result.Findings)
			}
			if strings.Contains(tt.sql, "/*M!") && !wpPHasPattern(result, PatternComment) {
				t.Errorf("missing MariaDB executable comment finding: %+v", result.Findings)
			}
		})
	}
}

func TestWPPTautologyAllocationBound(t *testing.T) {
	const size = 1 << 20
	sql := strings.Repeat("1=2 ", size/4)
	scanner := NewScanner()
	_ = scanner.ScanSQL(sql) // Warm pattern initialization and the folded buffer pool.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result := scanner.ScanSQL(sql)
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(result)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("ScanSQL allocated %d bytes for %d bytes of unequal pairs", allocated, len(sql))
	if allocated > 4*uint64(len(sql)) {
		t.Errorf("ScanSQL allocated %d bytes for %d bytes of unequal pairs; want <= 4x input", allocated, len(sql))
	}
}

func TestWPPCommentNormalizedDetection(t *testing.T) {
	for _, tt := range wpPCommentBypasses() {
		t.Run(tt.name, func(t *testing.T) {
			result := NewScanner().ScanSQL(tt.sql)
			if !wpPHasPattern(result, tt.pattern) {
				t.Fatalf("missing %s: %+v", tt.pattern, result.Findings)
			}
			if strings.Contains(tt.sql, "/*!") && !wpPHasPattern(result, PatternComment) {
				t.Fatalf("lost raw COMMENT_BYPASS finding: %+v", result.Findings)
			}
			if strings.Contains(tt.sql, "/*!") {
				conditional := false
				for _, f := range result.Findings {
					if f.Pattern == PatternComment && strings.Contains(f.Description, "MySQL conditional") {
						conditional = true
					}
				}
				if !conditional {
					t.Errorf("missing MySQL conditional comment description: %+v", result.Findings)
				}
			}
		})
	}
}

func TestWPPCommentFindingsPreserveMetadataAndDeduplicate(t *testing.T) {
	result := NewScanner().ScanSQL("SELECT 1 UNION/**/SELECT 2; --")
	want := map[string]Severity{
		"Trailing SQL comment may indicate injection": SeverityMedium,
		"Statement terminator followed by comment":    SeverityHigh,
	}
	unionCount := 0
	for _, finding := range result.Findings {
		if finding.Pattern == PatternUnionGeneric {
			unionCount++
		}
		if finding.Pattern != PatternComment {
			continue
		}
		severity, ok := want[finding.Description]
		if !ok {
			t.Fatalf("unexpected or duplicated comment finding: %+v", finding)
		}
		if finding.Severity != severity {
			t.Errorf("comment severity = %s, want %s", finding.Severity, severity)
		}
		delete(want, finding.Description)
	}
	if len(want) != 0 {
		t.Errorf("missing raw comment metadata: %+v", want)
	}
	if unionCount != 1 {
		t.Errorf("UNION finding count = %d, want 1: %+v", unionCount, result.Findings)
	}
}

func TestWPPDollarQuotedFunctionBodyIsInert(t *testing.T) {
	sql := "CREATE FUNCTION cleanup() RETURNS void AS $body$ BEGIN; DROP TABLE accounts; END; $body$ LANGUAGE plpgsql"
	if result := NewScanner().ScanSQL(sql); wpPHasPattern(result, PatternStackedQuery) {
		t.Fatalf("dollar-quoted function body reported stacked query: %+v", result.Findings)
	}
}

func TestWPPBenignCommentGuards(t *testing.T) {
	if result := NewScanner().ScanSQL("SELECT 'UNION/*' , x FROM t WHERE y = '*/SELECT'"); wpPHasPattern(result, PatternUnionGeneric) {
		t.Errorf("normalization joined markers across strings: %+v", result.Findings)
	}
	for _, sql := range []string{
		"SELECT /* fetch users */ id FROM users WHERE id = 42",
		"SELECT id -- pick id\nFROM users WHERE id = 42",
		"SELECT a /* note */, b FROM t WHERE c = 'x'",
		"SELECT '/* not a comment */' AS s FROM t",
		"SELECT 'a--b' AS s FROM t",
		"SELECT /*+ INDEX(t idx) */ a FROM t WHERE b = 2",
	} {
		if result := NewScanner().ScanSQL(sql); !result.IsClean() {
			t.Errorf("benign comment or string marker produced findings: %q: %+v", sql, result.Findings)
		}
	}
	for _, sql := range []string{
		`SELECT '/*' AS marker, 1 UNION SELECT '*/', 2`,
		`SELECT '--' AS marker, 1 UNION SELECT '#', 2`,
	} {
		result := NewScanner().ScanSQL(sql)
		if !wpPHasPattern(result, PatternUnionGeneric) {
			t.Errorf("string comment marker hid UNION: %q", sql)
		}
	}
}

func TestWPPFullInputDetection(t *testing.T) {
	for _, size := range []int{10050, 200000} {
		for _, whitespace := range []string{" ", "\n"} {
			padding := strings.Repeat(whitespace, size)
			for _, tt := range []wpPBypassCase{
				{"tautology", padding + "SELECT 1 WHERE x=2 OR 1=1", PatternTautology},
				{"trailing comment", padding + "SELECT 1 --", PatternComment},
				{"union comment", padding + "SELECT 1 UNION/**/SELECT NULL,NULL", PatternUnionGeneric},
				{"trailing comment padding", "SELECT 1 --" + padding, PatternComment},
			} {
				t.Run(fmt.Sprintf("%d/%q/%s", size, whitespace, tt.name), func(t *testing.T) {
					if result := NewScanner().ScanSQL(tt.sql); !wpPHasPattern(result, tt.pattern) {
						t.Errorf("missing %s beyond old cutoff: %+v", tt.pattern, result.Findings)
					}
				})
			}
		}
	}
}

func TestWPPParsedNullUnion(t *testing.T) {
	for _, tt := range []struct {
		sql  string
		want bool
	}{
		{"SELECT a,b FROM accounts UNION SELECT NULL,NULL", true},
		{"SELECT a,b FROM accounts UNION SELECT NULL AS x,NULL AS y", true},
		{"SELECT a,b FROM accounts UNION SELECT NULL,NULL FROM u", true},
		{"SELECT a,b FROM accounts UNION SELECT NULL AS x,NULL AS y FROM u", true},
		{"SELECT a,b FROM accounts UNION SELECT c,NULL FROM u", false},
		{"SELECT a,b FROM accounts UNION SELECT NULL,7", false},
		{"SELECT a,b FROM accounts UNION SELECT 7 AS x,8 AS y", false},
	} {
		t.Run(tt.sql, func(t *testing.T) {
			tree := parseForScan(t, tt.sql)
			defer ast.ReleaseAST(tree)
			result := NewScanner().Scan(tree)
			count := 0
			for _, f := range result.Findings {
				if f.Pattern == PatternUnionBased && f.Description == "UNION SELECT with multiple NULL columns detected" {
					count++
					if f.Severity != SeverityHigh {
						t.Errorf("NULL padding severity = %s, want HIGH", f.Severity)
					}
				}
			}
			want := 0
			if tt.want {
				want = 1
			}
			if count != want {
				t.Errorf("NULL UNION finding count = %d, want %d: %+v", count, want, result.Findings)
			}
		})
	}
}

func TestWPPScanInputLimit(t *testing.T) {
	if MaxScanInputSize != tokenizer.MaxInputSize {
		t.Fatalf("scan limit = %d, tokenizer limit = %d", MaxScanInputSize, tokenizer.MaxInputSize)
	}
	// A valid clean input at the boundary must be scanned rather than rejected.
	clean := "SELECT 1" + strings.Repeat(" ", MaxScanInputSize-len("SELECT 1"))
	if result := NewScanner().ScanSQL(clean); !result.IsClean() {
		t.Fatalf("exact-limit input rejected: %+v", result.Findings)
	}
	for _, sql := range []string{clean + " ", strings.Repeat(" ", MaxScanInputSize+1) + " OR 1=1; DROP TABLE accounts --"} {
		result := NewScanner().ScanSQL(sql)
		if len(result.Findings) != 1 || result.Findings[0].Pattern != PatternInputTooLarge || result.Findings[0].Severity != SeverityCritical {
			t.Fatalf("oversized input needs exactly one CRITICAL INPUT_TOO_LARGE finding: %+v", result.Findings)
		}
		wantDescription := fmt.Sprintf("input exceeds maximum scannable size (%d bytes > %d bytes); not scanned", len(sql), MaxScanInputSize)
		if result.Findings[0].Description != wantDescription {
			t.Errorf("oversize description = %q, want %q", result.Findings[0].Description, wantDescription)
		}
		if result.TotalCount != 1 || result.HighCount != 0 || result.CriticalCount != 1 || !result.HasHighOrAbove() || !result.HasCritical() || result.IsClean() {
			t.Fatalf("oversize summary counts incorrect: %+v", result)
		}
		critical, err := NewScannerWithSeverity(SeverityCritical)
		if err != nil {
			t.Fatal(err)
		}
		for _, scanner := range []*Scanner{critical, {MinSeverity: Severity("UNKNOWN")}} {
			result := scanner.ScanSQL(sql)
			if len(result.Findings) != 1 || result.Findings[0].Pattern != PatternInputTooLarge || result.Findings[0].Severity != SeverityCritical || result.IsClean() || !result.HasCritical() {
				t.Fatalf("oversize input looked clean under MinSeverity %q: %+v", scanner.MinSeverity, result)
			}
		}
	}
}

func TestWPPPrefilterEquivalence(t *testing.T) {
	for _, tt := range append(wpPCommentBypasses(), wpPRound2Bypasses()...) {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner()
			if got, want := s.scanSQL(tt.sql, true), s.scanSQL(tt.sql, false); !reflect.DeepEqual(got, want) {
				t.Errorf("prefilter changed findings: got %+v, want %+v", got, want)
			}
		})
	}
	for _, pattern := range allCompiledPatterns(t) {
		for _, literal := range requiredLiterals(pattern.re.String()) {
			if strings.ContainsAny(string(literal), " \t\n\r\f\v") {
				t.Errorf("requiredLiterals(%q) includes whitespace: %q", pattern.re.String(), literal)
			}
		}
	}
}

func TestWPPScanSQLLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing regression; skipped under -short")
	}
	input := func(size int) string {
		const chunk = "/**/ --x\n a = b "
		return strings.Repeat(chunk, (size+len(chunk)-1)/len(chunk))[:size]
	}
	scanner := NewScanner()
	small, large := input(16<<10), input(64<<10)
	scaletest.AssertLinearGrowth(t, "ScanSQL 16KiB -> 64KiB", 10,
		func() { _ = scanner.ScanSQL(small) },
		func() { _ = scanner.ScanSQL(large) })
}

// The old captures provide a small-input oracle for the streaming implementation.
func TestWPPStreamingTautologyCaptureEquivalence(t *testing.T) {
	scanner := NewScanner()
	for i, sql := range []string{
		"", "SELECT 1", "1=2 3=4 a=b", "1=1 2=2 'a'='a' col=COL",
		strings.Repeat("1=2 a=b 'x'='y' ", 40) + " 7=7 'tail'='TAIL' tail=TAIL",
		"'a=b' = 'A=B'", "'a=b' = 'a=c' 'c=d'='C=D'", "''=''",
		"'a = b' = 'A = B'", "'a'='b' 'x=y'='X=Y' 'q'='q'",
		"ſ=S K=k", "xſ=XS xK=XK", "S=ſ K=K", "ſ=ſ K=K",
		"a1=1 12=12z _1=1 0=0", "11=12,13=13", "a=b/c=C", "foo.bar=FOO.BAR",
		"1234567=1234567", "x1=x2 x3=X3", "1\v=\f1 a\v=\fA",
		strings.Repeat("a1=2 ", 10000) + "1=2 3=3",
		strings.Repeat("1=2x ", 100) + "1=2 3=3",
		strings.Repeat("0a=b ", 100) + "a=b c=C",
	} {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			var want []Finding
			for _, p := range tautologyCapturePatterns {
				for _, match := range p.re.FindAllStringSubmatch(sql, -1) {
					if len(match) >= 3 && strings.EqualFold(match[1], match[2]) {
						want = append(want, Finding{
							Severity: SeverityCritical, Pattern: PatternTautology,
							Description: "Always-true condition detected (tautology): " + match[0],
							Risk:        "Authentication bypass via always-true condition",
							Suggestion:  "Use parameterized queries to prevent tautology injection",
						})
						break
					}
				}
			}
			got := &ScanResult{}
			scanner.detectTautologyInSQL([]string{sql}, nil, got)
			if !reflect.DeepEqual(got.Findings, want) {
				t.Errorf("stream differs from capture oracle: got %+v, want %+v", got.Findings, want)
			}
		})
	}
}

func TestWPPStreamingTautologyFullInput(t *testing.T) {
	falsePairs := strings.Repeat("1=2 ", (1<<20)/4)
	for _, sql := range []string{falsePairs + " 3=3", "3=3 " + falsePairs} {
		result := &ScanResult{}
		NewScanner().detectTautologyInSQL([]string{sql}, nil, result)
		if len(result.Findings) != 1 || result.Findings[0].Description != "Always-true condition detected (tautology): 3=3" {
			t.Errorf("lost first true numeric pair in full input: %+v", result.Findings)
		}
	}
}

func TestWPPBracketRegions(t *testing.T) {
	for _, sql := range []string{
		`SELECT [a]] $x$ ]; DROP TABLE users; SELECT [$x$]`,
		`SELECT [a']] $x$ ]; DROP TABLE users; SELECT [$x$]`,
	} {
		if got := stripDollarQuotedStrings(sql); got != sql {
			t.Errorf("stripped dollar marker inside escaped bracket identifier: %q -> %q", sql, got)
		}
		if result := NewScanner().ScanSQL(sql); !wpPHasPattern(result, PatternStackedQuery) {
			t.Errorf("bracket identifier hid DROP: %+v", result.Findings)
		}
	}
	for _, sql := range []string{
		`SELECT [a]]b], [c'd] FROM t`,
		`SELECT [a/*b], [c*/d], [e--f], [g#h] FROM t`,
		`SELECT [a']]b] /* fetch identifiers */ FROM t`,
	} {
		if result := NewScanner().ScanSQL(sql); !result.IsClean() {
			t.Errorf("benign bracket identifier produced findings for %q: %+v", sql, result.Findings)
		}
	}
}

func TestWPPCommentEscapeInterpretationCrossProduct(t *testing.T) {
	prefixes := []string{
		`SELECT '\''`, `SELECT E'\''`, `SELECT "\""`,
		`SELECT [a']]name]`, `SELECT [a']]name], '\''`,
		`SELECT [a']]name], "\""`,
	}
	gaps := []string{"/**/", "--x\n", "#x\n", "/* outer /* inner */ outer */", "/* x /*/"}
	for _, prefix := range prefixes {
		for _, gap := range gaps {
			sql := prefix + " UNION" + gap + "SELECT 1,2"
			t.Run(sql, func(t *testing.T) {
				result := NewScanner().ScanSQL(sql)
				if !wpPHasPattern(result, PatternUnionGeneric) {
					t.Errorf("dialect interpretation lost UNION: %+v", result.Findings)
				}
				if got, want := NewScanner().scanSQL(sql, true), NewScanner().scanSQL(sql, false); !reflect.DeepEqual(got, want) {
					t.Errorf("prefilter differs across dialect interpretations: got %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestWPPNumericPrefilterNecessaryCondition(t *testing.T) {
	scanner := NewScanner()
	corpus := []string{
		"", "=", "1=", "=1", "1=2", "1=1", "01=1", "01=01",
		"1==1", "=1=1=", "1=2=2", "1=1=2", "12=12 13=14",
		"ſ1=1ſ", "K1=1K", "ſ123=123", "123=123ſ",
		"a1=1a", "_1=1_", "11=11z 3=3", "'123=123'", "'1'='1'",
		"123456=123456", "1234567=1234567", "0123456789=0123456789",
		"1234567=123456 123456=1234567", "1234567.123456=123456",
		strings.Repeat("1=2 ", 256) + "3=3", "3=3 " + strings.Repeat("1=2 ", 256),
		"1/**/=/**/1", "1#x\n=1", "SELECT '\\'' OR/**/1/**/=/**/1",
	}
	for _, whitespace := range []string{"", " ", "\t", "\n", "\r", "\v", "\f", " \t\n\r\v\f"} {
		for _, left := range []string{"0", "1", "01", "123456", "1234567"} {
			for _, right := range []string{"0", "1", "01", "123456", "1234567"} {
				corpus = append(corpus, left+whitespace+"="+whitespace+right)
			}
		}
	}
	for i, sql := range corpus {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			for _, match := range tautologyCapturePatterns[0].re.FindAllStringSubmatch(sql, -1) {
				if len(match) >= 3 && strings.EqualFold(match[1], match[2]) && !hasEqualNumericPair(sql) {
					t.Errorf("numeric prefilter rejected equal capture %q in %q", match[0], sql)
				}
			}
			if got, want := scanner.scanSQL(sql, true), scanner.scanSQL(sql, false); !reflect.DeepEqual(got, want) {
				t.Errorf("numeric prefilter changed findings for %q: got %+v, want %+v", sql, got, want)
			}
		})
	}
}

func TestWPPStreamingMatchEndBoundaries(t *testing.T) {
	_ = NewScanner()
	for i, tt := range []struct {
		pattern               int
		prefix, match, suffix string
	}{
		{0, "a1=2 ", "1=2", ""},
		{0, "1=2x ", "1=2", ""},
		{0, "_1=2 1=2_ ", "1=2", ""},
		{0, "ſ", "1=2", "K"},
		{0, strings.Repeat("a1=2 ", 10000), "1=2", " 3=3"},
		{1, "x", "'a'='b'", "y"},
		{1, "ſ", "'a=b'='a=c'", "K"},
		{1, "'x'='y' ", "'a'='b'", ""},
		{2, "0a=b ", "a=b", ""},
		{2, "a=" + strings.Repeat("b", 60) + " ", "a=b", ""},
		{2, "ſ", "a=b", "K"},
		{2, "0foo=BAZ ", "foo=BAZ", ""},
	} {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			sql := tt.prefix + tt.match + tt.suffix
			p := tautologyCapturePatterns[tt.pattern]
			indices := p.re.FindStringIndex(sql)
			if len(indices) != 2 {
				t.Fatalf("expected capture-pattern match for %q", sql)
			}
			// The earlier quoted pair is itself valid; unlike numeric and
			// identifier patterns it requires no surrounding word boundaries.
			want := len(tt.prefix) + len(tt.match)
			if tt.pattern == 1 && strings.HasPrefix(tt.prefix, "'x'") {
				want = len("'x'='y'")
			}
			if indices[1] != want {
				t.Fatalf("regex match end = %d, want %d", indices[1], want)
			}
			if got := sqlPairMatchEnd(sql, p.re.FindString(sql)); got != indices[1] {
				t.Errorf("stream match end = %d, regex match end = %d", got, indices[1])
			}
		})
	}
}
