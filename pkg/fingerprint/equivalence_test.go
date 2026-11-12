// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/namequote"
	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func equivalenceCorpus(t *testing.T) []benchcorpus.Statement {
	t.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	return set.All()
}
func corpusDialect(s benchcorpus.Statement) keywords.SQLDialect {
	if s.Dialect == benchcorpus.GenericDialect {
		return ""
	}
	return keywords.SQLDialect(s.Dialect)
}
func equivalenceTokens(sql string, d keywords.SQLDialect) ([]models.TokenWithSpan, error) {
	tk := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tk)
	if d != "" {
		tk.SetDialect(d)
	}
	ts, err := tk.TokenizeString(sql)
	if err != nil {
		return nil, err
	}
	out := make([]models.TokenWithSpan, 0, len(ts))
	for _, x := range ts {
		if x.Token.Type != models.TokenTypeEOF {
			out = append(out, x)
		}
	}
	return out, nil
}
func TestNormalizeV2Idempotent(t *testing.T) {
	for _, s := range equivalenceCorpus(t) {
		for _, d := range []keywords.SQLDialect{"", corpusDialect(s)} {
			o := fingerprint.Options{Dialect: d}
			a, e := fingerprint.NormalizeWithOptions(s.SQL, o)
			if e != nil {
				continue
			}
			b, e := fingerprint.NormalizeWithOptions(a, o)
			if e != nil || a != b {
				t.Fatalf("%s dialect=%q: N=%q N(N)=%q error=%v", s.Key(), d, a, b, e)
			}
		}
	}
}

// mutationOracle is independent of tokens.go: structural literals and keyword
// name parts are determined directly from N2, N4a, N4b, N5 and N14.
type mutationOracle struct {
	kept, flip []bool
	raw        []string
	start, end []int
}

func sourceOffset(s string, l models.Location) int {
	p := 0
	for n := 1; n < l.Line; n++ {
		i := strings.IndexByte(s[p:], '\n')
		if i < 0 {
			return len(s)
		}
		p += i + 1
	}
	return p + l.Column - 1
}
func stringLiteral(k models.TokenType) bool {
	return k >= models.TokenRangeStringStart && k < models.TokenRangeStringEnd && k != models.TokenTypeDoubleQuotedString
}
func quotedOracle(x models.TokenWithSpan) bool {
	return x.Token.Type == models.TokenTypeDoubleQuotedString || (x.Token.Type == models.TokenTypeIdentifier && (x.Token.Quote != 0 || x.Start.Line != x.End.Line || x.End.Column-x.Start.Column > len(x.Token.Value)))
}
func oracleFor(sql string, ts []models.TokenWithSpan) mutationOracle {
	o := mutationOracle{make([]bool, len(ts)), make([]bool, len(ts)), make([]string, len(ts)), make([]int, len(ts)), make([]int, len(ts))}
	var stack []int
	cast := map[int]bool{}
	ddl := false
	for i, x := range ts {
		k := x.Token.Type
		o.start[i] = sourceOffset(sql, x.Start)
		o.end[i] = sourceOffset(sql, x.End)
		o.raw[i] = sql[o.start[i]:o.end[i]]
		if i == 0 || ts[i-1].Token.Type == models.TokenTypeSemicolon {
			ddl = k == models.TokenTypeCreate || k == models.TokenTypeAlter
			stack = nil
		}
		prev := models.TokenTypeEOF
		if i > 0 {
			prev = ts[i-1].Token.Type
		}
		next := models.TokenTypeEOF
		if i+1 < len(ts) {
			next = ts[i+1].Token.Type
		}
		inCast := len(stack) > 0 && cast[stack[len(stack)-1]]
		o.flip[i] = (k.IsKeyword() && prev != models.TokenTypePeriod && next != models.TokenTypePeriod) || (k == models.TokenTypeIdentifier && !quotedOracle(x) && stringLiteral(next))
		if k == models.TokenTypeLParen {
			c := i > 0 && !quotedOracle(ts[i-1]) && (strings.EqualFold(ts[i-1].Token.Value, "CAST") || strings.EqualFold(ts[i-1].Token.Value, "TRY_CAST") || strings.EqualFold(ts[i-1].Token.Value, "SAFE_CAST") || strings.EqualFold(ts[i-1].Token.Value, "XMLATTRIBUTES") || strings.EqualFold(ts[i-1].Token.Value, "XMLFOREST"))
			cast[i] = c
			typeName := i > 0 && (prev == models.TokenTypeIdentifier || quotedOracle(ts[i-1]) || prev.IsDataType())
			context := ddl || (i > 1 && ts[i-2].Token.Value == "::") || (i > 1 && ts[i-2].Token.Type == models.TokenTypeAs && inCast)
			if typeName && context {
				j := i + 1
				for j < len(ts) && (ts[j].Token.Type == models.TokenTypeNumber || ts[j].Token.Type == models.TokenTypeComma) {
					j++
				}
				if j < len(ts) && ts[j].Token.Type == models.TokenTypeRParen {
					for n := i + 1; n < j; n++ {
						if ts[n].Token.Type == models.TokenTypeNumber {
							o.kept[n] = true
						}
					}
				}
			}
			stack = append(stack, i)
		} else if k == models.TokenTypeRParen && len(stack) > 0 {
			stack = stack[:len(stack)-1]
		}
		if stringLiteral(k) && prev == models.TokenTypeAs && !inCast {
			o.kept[i] = true
		}
		if k == models.TokenTypeTrue || k == models.TokenTypeFalse {
			o.kept[i] = prev == models.TokenTypeIs || (prev == models.TokenTypeNot && i > 1 && ts[i-2].Token.Type == models.TokenTypeIs)
		}
		if k == models.TokenTypeNull {
			o.kept[i] = prev == models.TokenTypeIs || prev == models.TokenTypeNot || (ddl && prev != models.TokenTypeDefault)
		}
	}
	return o
}
func flipASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		} else if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
func otherString(raw string) string {
	if strings.HasPrefix(raw, "$") {
		if i := strings.IndexByte(raw[1:], '$'); i >= 0 {
			tag := raw[:i+2]
			content := "zz"
			if raw == tag+content+tag {
				content = "zzz"
			}
			return tag + content + tag
		}
	}
	i := strings.IndexAny(raw, "'\"")
	if i < 0 {
		return raw
	}
	q := raw[i : i+1]
	if strings.HasPrefix(raw[i:], strings.Repeat(q, 3)) {
		q = strings.Repeat(q, 3)
	}
	content := "zz"
	prefix := strings.ToUpper(raw[:i])
	if prefix == "X" {
		content = "AB"
	}
	if prefix == "B" {
		content = "01"
	}
	if strings.TrimSuffix(strings.TrimPrefix(raw, raw[:i]+q), q) == content {
		switch prefix {
		case "X":
			content = "CD"
		case "B":
			content = "10"
		default:
			content = "zzz"
		}
	}
	return raw[:i] + q + content + q
}
func sameTypes(a, b []models.TokenWithSpan) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Token.Type != b[i].Token.Type {
			return false
		}
	}
	return true
}
func rebuiltVariant(sql string, ts []models.TokenWithSpan, o mutationOracle, seed uint64, literals, layout, conservative bool, d keywords.SQLDialect) string {
	sep := []string{" ", "\t", "\n", "  ", "/* c */", "-- c\n"}
	if d == keywords.DialectMySQL || d == keywords.DialectMariaDB {
		sep = append(sep, "# c\n")
	}
	var b strings.Builder
	for i, x := range ts {
		if i > 0 {
			gap := sql[o.end[i-1]:o.start[i]]
			if layout && (!conservative || strings.ContainsAny(gap, " \t\r\n")) {
				separator := sep[(seed+uint64(i))%uint64(len(sep))]
				// Run 5: a -- separator immediately after a minus would
				// consume that original token. Preserve it with a padded gap.
				if conservative && strings.HasPrefix(separator, "--") && strings.HasSuffix(o.raw[i-1], "-") {
					separator = " " + separator
				}
				b.WriteString(separator)
			} else {
				b.WriteString(gap)
			}
		}
		raw := o.raw[i]
		k := x.Token.Type
		if literals && !o.kept[i] {
			switch {
			case k == models.TokenTypeNumber:
				raw = "42"
				if o.raw[i] == "42" {
					raw = "43"
				}
			case stringLiteral(k):
				raw = otherString(raw)
			case k == models.TokenTypeTrue:
				raw = "FALSE"
			case k == models.TokenTypeFalse:
				raw = "TRUE"
			}
		}
		if layout && o.flip[i] {
			raw = flipASCII(raw)
		}
		b.WriteString(raw)
	}
	return b.String()
}

// Measured by the external driver in W5-08/t2.log. Unrestricted separator
// insertion changes the significant token sequence at these tokenizer-sensitive
// gaps; keeping separators at existing whitespace (and padding -- after a minus)
// preserves both token sequence and normal form. Count/key changes need a reason.
const literalLayoutFallbackCount = 28

var literalLayoutFallbackKeys = [literalLayoutFallbackCount]string{
	"realworld/clickhouse/01_app_crud.sql#13",
	"realworld/clickhouse/02_reporting.sql#1",
	"realworld/clickhouse/08_etl_pipelines.sql#32",
	"realworld/clickhouse/09_deep_nesting.sql#13",
	"realworld/mariadb/08_complex_queries.sql#5",
	"realworld/mariadb/09_mysql_compat_misc.sql#31",
	"realworld/mysql/09_deep_nesting.sql#1",
	"realworld/oracle/06_etl_merge.sql#23",
	"realworld/oracle/07_admin_ops.sql#39",
	"realworld/postgresql/02_reporting.sql#6",
	"realworld/postgresql/06_cte_dml_etl.sql#0",
	"realworld/postgresql/08_supabase_rls_misc.sql#16",
	"realworld/sqlite/08_reporting.sql#3",
	"realworld/sqlite/11_deep_nesting.sql#0",
	"realworld/sqlite/11_deep_nesting.sql#3",
	"realworld/sqlserver/02_reporting.sql#1",
	"realworld/sqlserver/02_reporting.sql#15",
	"realworld/sqlserver/04_window_analytics.sql#12",
	"real_world/05_sales_funnel_analysis.sql#0",
	"real_world/09_financial_reconciliation.sql#0",
	"real_world/10_marketing_campaign_roi.sql#0",
	"real_world/12_fraud_detection.sql#0",
	"real_world/13_ab_test_analysis.sql#0",
	"real_world/16_log_analysis_error_tracking.sql#0",
	"real_world/23_recommendation_collaborative_filtering.sql#0",
	"corpus/tpch/q03_shipping_priority.sql#0",
	"corpus/tpch/q15_top_supplier.sql#0",
	"corpus/tpcds/q19_store_brand_revenue.sql#0",
}

func TestNormalizeV2LiteralAndLayoutInvariance(t *testing.T) {
	fallback := 0
	seenFallback := make(map[string]bool, literalLayoutFallbackCount)
	for _, s := range equivalenceCorpus(t) {
		d := corpusDialect(s)
		ts, e := equivalenceTokens(s.SQL, d)
		if e != nil {
			continue
		}
		o := oracleFor(s.SQL, ts)
		want, e := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Dialect: d})
		if e != nil {
			continue
		}
		h := fnv.New64a()
		_, _ = h.Write([]byte(s.Key()))
		seed := h.Sum64()
		variants := [3]string{}
		// TRUE/FALSE deliberately exchange token types. Separator safety is
		// checked against the literal-only variant, so only layout is measured.
		literalTokens, literalErr := equivalenceTokens(rebuiltVariant(s.SQL, ts, o, seed, true, false, false, d), d)
		if literalErr != nil {
			t.Fatalf("%s literal variant: %v", s.Key(), literalErr)
		}
		needFallback := false
		for n := range variants {
			variants[n] = rebuiltVariant(s.SQL, ts, o, seed, n != 1, n != 0, false, d)
			vt, ve := equivalenceTokens(variants[n], d)
			expected := ts
			if n != 1 {
				expected = literalTokens
			}
			if ve != nil || !sameTypes(expected, vt) {
				needFallback = true
			}
		}
		if needFallback {
			fallback++
			seenFallback[s.Key()] = true
			t.Logf("separator fallback: %s", s.Key())
			for n := range variants {
				variants[n] = rebuiltVariant(s.SQL, ts, o, seed, n != 1, n != 0, true, d)
				vt, ve := equivalenceTokens(variants[n], d)
				expected := ts
				if n != 1 {
					expected = literalTokens
				}
				if ve != nil || !sameTypes(expected, vt) {
					t.Fatalf("%s conservative variant %d changes token sequence: %v\n%s", s.Key(), n, ve, variants[n])
				}
			}
		}
		for n, v := range variants {
			got, err := fingerprint.NormalizeWithOptions(v, fingerprint.Options{Dialect: d})
			if err != nil || got != want {
				t.Fatalf("%s variant %d error=%v\nsource=%s\nvariant=%s\nwant=%q\ngot=%q", s.Key(), n, err, s.SQL, v, want, got)
			}
		}
	}
	t.Logf("T3 fallback_count=%d", fallback)
	if fallback != literalLayoutFallbackCount {
		t.Errorf("fallback count=%d want=%d", fallback, literalLayoutFallbackCount)
	}
	for _, key := range literalLayoutFallbackKeys {
		if !seenFallback[key] {
			t.Errorf("recorded separator fallback %s no longer occurs; review the pinned list/count", key)
		}
	}
}
func replaceOracle(sql string, o mutationOracle, i int, value string) string {
	return sql[:o.start[i]] + value + sql[o.end[i]:]
}
func TestNormalizeV2StructureSensitivity(t *testing.T) {
	counts := map[string]int{}
	for _, s := range equivalenceCorpus(t) {
		d := corpusDialect(s)
		ts, e := equivalenceTokens(s.SQL, d)
		if e != nil {
			continue
		}
		o := oracleFor(s.SQL, ts)
		want, e := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Dialect: d})
		if e != nil {
			continue
		}
		mutations := map[string]string{}
		// A BETWEEN at the current parenthesis depth consumes its own AND.
		// Nested expressions have independent counters, so their logical AND
		// tokens cannot consume the enclosing range's delimiter.
		between := []int{0}
		for i, x := range ts {
			k := x.Token.Type
			next := models.TokenTypeEOF
			if i+1 < len(ts) {
				next = ts[i+1].Token.Type
			}
			namePart := next == models.TokenTypePeriod || (i > 0 && ts[i-1].Token.Type == models.TokenTypePeriod)
			betweenDelimiter := false
			switch k {
			case models.TokenTypeLParen:
				between = append(between, 0)
			case models.TokenTypeRParen:
				if len(between) > 1 {
					between = between[:len(between)-1]
				}
			case models.TokenTypeSemicolon:
				between = []int{0}
			case models.TokenTypeBetween:
				if !namePart {
					between[len(between)-1]++
				}
			case models.TokenTypeAnd:
				if !namePart && between[len(between)-1] > 0 {
					between[len(between)-1]--
					betweenDelimiter = true
				}
			}
			if _, ok := mutations["a"]; !ok && k == models.TokenTypeIdentifier && !quotedOracle(x) && next != models.TokenTypeLParen {
				mutations["a"] = replaceOracle(s.SQL, o, i, o.raw[i]+"_zz")
			}
			if _, ok := mutations["b"]; !ok && (x.Token.Value == "=" || x.Token.Value == "<") {
				v := "<>"
				if x.Token.Value == "<" {
					v = ">"
				}
				mutations["b"] = replaceOracle(s.SQL, o, i, v)
			}
			if k == models.TokenTypeAnd && !namePart && !betweenDelimiter && i+1 < len(ts) {
				end := i + 1
				depth := 0
				for end < len(ts) {
					z := ts[end].Token.Type
					if z == models.TokenTypeLParen {
						depth++
					}
					if z == models.TokenTypeRParen {
						if depth == 0 {
							break
						}
						depth--
					}
					if depth == 0 && (z == models.TokenTypeOrderBy || z == models.TokenTypeGroupBy || z == models.TokenTypeLimit || z == models.TokenTypeSemicolon) {
						break
					}
					end++
				}
				if end > i+1 {
					p := len(s.SQL)
					if end < len(ts) {
						p = o.start[end]
					}
					mutations["c"] = s.SQL[:o.start[i]] + s.SQL[p:]
				}
			}
			if _, ok := mutations["d"]; !ok && o.kept[i] {
				if k == models.TokenTypeNumber {
					v, err := strconv.ParseFloat(x.Token.Value, 64)
					if err == nil {
						mutations["d"] = replaceOracle(s.SQL, o, i, strconv.FormatFloat(v+1, 'f', -1, 64))
					}
				} else if stringLiteral(k) {
					mutations["d"] = replaceOracle(s.SQL, o, i, otherString(o.raw[i]))
				}
			}
			if _, ok := mutations["e"]; !ok && k.IsKeyword() && !o.flip[i] && flipASCII(o.raw[i]) != o.raw[i] {
				mutations["e"] = replaceOracle(s.SQL, o, i, flipASCII(o.raw[i]))
			}
			if _, ok := mutations["f"]; !ok && o.kept[i] && (k == models.TokenTypeTrue || k == models.TokenTypeFalse) {
				v := "TRUE"
				if k == models.TokenTypeTrue {
					v = "FALSE"
				}
				mutations["f"] = replaceOracle(s.SQL, o, i, v)
			}
		}
		for _, class := range []string{"a", "b", "c", "d", "e", "f"} {
			v, ok := mutations[class]
			if !ok {
				continue
			}
			counts[class]++
			got, err := fingerprint.NormalizeWithOptions(v, fingerprint.Options{Dialect: d})
			if err != nil || got == want {
				t.Fatalf("%s mutation %s error=%v\nsource=%s\nvariant=%s\nnormalized=%q", s.Key(), class, err, s.SQL, v, got)
			}
		}
	}
	for _, c := range []string{"a", "b", "c", "d", "e", "f"} {
		t.Logf("T4 %s exercised=%d", c, counts[c])
	}
	if counts["d"] == 0 || counts["e"] == 0 {
		t.Fatal("kept-literal and dotted-keyword mutations must exercise the corpus")
	}
}

// Each exception must identify the exact corpus pair and a reason. A change
// here requires review because it changes the documented legacy partition.
var legacyMergeV2SplitAllowlist = map[string]string{
	"realworld/mariadb/03_ddl_migrations.sql#14 | realworld/mysql/03_ddl_migrations.sql#30":           "N4a keeps DDL identifier modifiers email(20) and email(10); legacy redacts both prefix-index lengths as email(?).",
	"realworld/clickhouse/05_dialect_specific.sql#2 | realworld/clickhouse/05_dialect_specific.sql#4": "The dialect-aware legacy formatter drops SAMPLE clauses, while N17 preserves SAMPLE ? versus SAMPLE ? OFFSET ?.",
	"realworld/mysql/10_misc_functions.sql#23 | realworld/mysql/10_misc_functions.sql#29":             "Legacy emits SELECT ? for adjacent string literals SELECT 'a' 'b'; N4 independently redacts both tokens as SELECT ? ?, distinct from SELECT 1.",
	"realworld/mysql/10_misc_functions.sql#23 | realworld/mysql/10_misc_functions.sql#30":             "Legacy emits SELECT ? for adjacent string literals SELECT 'a' 'b'; N4 independently redacts both tokens as SELECT ? ?, distinct from SELECT 2.",
	"realworld/mysql/10_misc_functions.sql#23 | realworld/mysql/12_orm_misc.sql#10":                   "Legacy emits SELECT ? for adjacent string literals SELECT 'a' 'b'; N4 independently redacts both tokens as SELECT ? ?, distinct from the single literal in the ORM statement.",
	"realworld/mysql/10_misc_functions.sql#23 | realworld/mysql/91_hash_comments.sql#2":               "Legacy emits SELECT ? for adjacent string literals SELECT 'a' 'b'; N4 independently redacts both tokens as SELECT ? ?, distinct from the single literal in the hash-comment statement.",
	"realworld/oracle/05_dialect_specific.sql#67 | realworld/oracle/05_dialect_specific.sql#68":       "The dialect-aware legacy formatter rewrites UNIQUE to DISTINCT; N17 preserves the two source spellings.",
}

func coarseningSignature(sql string, redact, lists, keywordCase bool) (string, error) {
	ts, e := equivalenceTokens(sql, "")
	if e != nil {
		return "", e
	}
	var words []string
	for _, x := range ts {
		k := x.Token.Type
		v := x.Token.Value
		if redact && (k == models.TokenTypeNumber || stringLiteral(k) || k == models.TokenTypeTrue || k == models.TokenTypeFalse) {
			v = "?"
		} else if quotedOracle(x) {
			v = fmt.Sprintf("quoted:%d:%s", k, v)
		} else if keywordCase && k.IsKeyword() {
			v = strings.ToUpper(v)
		}
		words = append(words, v)
	}
	if !lists {
		return strings.Join(words, "\x00"), nil
	}
	// Collapse homogeneous question-mark lists and repeated VALUES rows. This
	// classifier works on legacy outputs, never calls the v2 implementation.
	for i := 0; i+2 < len(words); i++ {
		if words[i] != "IN" || words[i+1] != "(" || words[i+2] != "?" {
			continue
		}
		j := i + 3
		for j+1 < len(words) && words[j] == "," && words[j+1] == "?" {
			j += 2
		}
		if j < len(words) && words[j] == ")" {
			words = append(words[:i+3], words[j:]...)
		}
	}
	for i := 0; i < len(words); i++ {
		if !strings.EqualFold(words[i], "VALUES") {
			continue
		}
		j := i + 1
		for j < len(words) && words[j] == "(" {
			end := j + 1
			depth := 1
			for end < len(words) && depth > 0 {
				if words[end] == "(" {
					depth++
				}
				if words[end] == ")" {
					depth--
				}
				end++
			}
			if end+1 >= len(words) || words[end] != "," || words[end+1] != "(" {
				break
			}
			n := end - j
			if end+1+n <= len(words) && reflect.DeepEqual(words[j:end], words[end+1:end+1+n]) {
				words = append(words[:end], words[end+1+n:]...)
			} else {
				j = end + 1
			}
		}
	}
	return strings.Join(words, "\x00"), nil
}

func coarseningClass(a, b string) string {
	for _, c := range []struct {
		name                       string
		redact, lists, keywordCase bool
	}{
		{"literal", true, false, false},
		{"list", false, true, false},
		{"keyword-case", false, false, true},
		{"literal+list", true, true, false},
		{"literal+keyword-case", true, false, true},
		{"list+keyword-case", false, true, true},
		{"literal+list+keyword-case", true, true, true},
	} {
		x, ex := coarseningSignature(a, c.redact, c.lists, c.keywordCase)
		y, ey := coarseningSignature(b, c.redact, c.lists, c.keywordCase)
		if ex == nil && ey == nil && x == y {
			return c.name
		}
	}
	return "unclassified"
}
func TestNormalizeV2GroupsLikeLegacy(t *testing.T) {
	all := equivalenceCorpus(t)
	type partitionScope struct {
		name, corpus string
		dialect      keywords.SQLDialect
	}
	scopes := []partitionScope{{name: "realworld-default"}, {name: "all-default"}}
	for _, c := range benchcorpus.Corpora {
		if c.Kind == benchcorpus.KindRealWorld {
			scopes = append(scopes, partitionScope{name: "realworld-dialect/" + c.Dialect, corpus: c.Name, dialect: keywords.SQLDialect(c.Dialect)})
		}
	}
	for _, scope := range scopes {
		t.Run(scope.name, func(t *testing.T) {
			type row struct{ key, l, v string }
			var rows []row
			legacyErrors, v2Errors, total := 0, 0, 0
			lg, vg := map[string][]int{}, map[string][]int{}
			for _, s := range all {
				if scope.name != "all-default" && !strings.HasPrefix(s.Corpus, "realworld/") {
					continue
				}
				if scope.corpus != "" && scope.corpus != s.Corpus {
					continue
				}
				total++
				d := scope.dialect
				l, le := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Mode: fingerprint.ModeLegacy, Dialect: d})
				v, ve := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Dialect: d})
				if le != nil {
					legacyErrors++
				}
				if ve != nil {
					v2Errors++
				}
				if le != nil || ve != nil {
					continue
				}
				i := len(rows)
				rows = append(rows, row{s.Key(), l, v})
				lg[l] = append(lg[l], i)
				vg[v] = append(vg[v], i)
			}
			split, coarse := 0, 0
			classes := map[string]int{}
			for _, g := range lg {
				for a := 0; a < len(g); a++ {
					for b := a + 1; b < len(g); b++ {
						x, y := rows[g[a]], rows[g[b]]
						if x.v == y.v {
							continue
						}
						split++
						key := x.key + " | " + y.key
						if reason := legacyMergeV2SplitAllowlist[key]; reason == "" {
							t.Errorf("unallowlisted legacy merge/v2 split: %s\nlegacy=%s\nv2a=%s\nv2b=%s", key, x.l, x.v, y.v)
						}
					}
				}
			}
			for _, g := range vg {
				for a := 0; a < len(g); a++ {
					for b := a + 1; b < len(g); b++ {
						x, y := rows[g[a]], rows[g[b]]
						if x.l == y.l {
							continue
						}
						coarse++
						class := coarseningClass(x.l, y.l)
						if class == "unclassified" {
							t.Errorf("unclassified v2 merge/legacy split: %s | %s\nlegacyA=%s\nlegacyB=%s\nv2=%s", x.key, y.key, x.l, y.l, x.v)
						} else {
							classes[class]++
						}
					}
				}
			}
			t.Logf("T5 scope statements legacy_accepted v2_accepted both legacy_groups v2_groups legacy_merge_v2_split v2_merge_legacy_split\n%s %d %d %d %d %d %d %d %d", scope.name, total, total-legacyErrors, total-v2Errors, len(rows), len(lg), len(vg), split, coarse)
			t.Logf("T5 coarsening classes: %v", classes)
		})
	}
}

func formatEquivalenceCompact(sql string) (string, error) {
	tree, e := gosqlx.Parse(sql)
	if e != nil {
		return "", e
	}
	defer ast.ReleaseAST(tree)
	var parts []string
	for _, s := range tree.Statements {
		p, e := formatter.FormatStatementChecked(s, ast.CompactStyle())
		if e != nil {
			return "", e
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; "), nil
}

type classifiedToken struct {
	kind   models.TokenType
	value  string
	quoted bool
}

func classificationTokens(sql string) ([]classifiedToken, error) {
	ts, e := equivalenceTokens(sql, "")
	if e != nil {
		return nil, e
	}
	out := make([]classifiedToken, 0, len(ts))
	for _, x := range ts {
		out = append(out, classifiedToken{x.Token.Type, x.Token.Value, quotedOracle(x)})
	}
	return out, nil
}
func tokenBag(ts []classifiedToken, paren bool) map[string]int {
	m := map[string]int{}
	for _, x := range ts {
		if paren && (x.value == "(" || x.value == ")") {
			continue
		}
		m[fmt.Sprintf("%d:%s", x.kind, x.value)]++
	}
	return m
}
func strippedTokens(ts []classifiedToken, remove string) []classifiedToken {
	out := make([]classifiedToken, 0, len(ts))
	for _, x := range ts {
		if !((remove == "()" && (x.value == "(" || x.value == ")")) || (remove == ";" && x.value == ";")) {
			out = append(out, x)
		}
	}
	return out
}

func equalASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'a' && x <= 'z' {
			x -= 'a' - 'A'
		}
		if y >= 'a' && y <= 'z' {
			y -= 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// Run 5's sole extra P5 split class: sequence and token kinds must match;
// only IDENTIFIER values may differ, and then only in ASCII letter case.
func identifierCaseOnly(x, y []classifiedToken) bool {
	if len(x) != len(y) {
		return false
	}
	different := false
	for i, a := range x {
		b := y[i]
		if a == b {
			continue
		}
		if a.kind != models.TokenTypeIdentifier || b.kind != models.TokenTypeIdentifier || a.quoted != b.quoted || !equalASCIIFold(a.value, b.value) {
			return false
		}
		different = true
	}
	return different
}

func TestNormalizeV2IdentifierCaseClassification(t *testing.T) {
	for _, tt := range []struct {
		name, a, b string
		want       bool
	}{
		{"bare contextual name", "SHOW server_version", "SHOW SERVER_VERSION", true},
		{"non-ASCII bytes unchanged", "SELECT café", "SELECT CAFé", true},
		{"non-ASCII folding forbidden", "SELECT café", "SELECT CAFÉ", false},
		{"keyword case forbidden", "select a", "SELECT a", false},
		{"quoted name forbidden", `SELECT "Foo"`, `SELECT "foo"`, false},
		{"literal difference forbidden", "SELECT foo + 1", "SELECT FOO + 2", false},
		{"renaming forbidden", "SELECT foo", "SELECT bar", false},
		{"sequence length forbidden", "SELECT foo", "SELECT FOO, bar", false},
		{"no difference", "SELECT foo", "SELECT foo", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x, e := classificationTokens(tt.a)
			if e != nil {
				t.Fatal(e)
			}
			y, e := classificationTokens(tt.b)
			if e != nil {
				t.Fatal(e)
			}
			if got := identifierCaseOnly(x, y); got != tt.want {
				t.Errorf("identifierCaseOnly(%q,%q)=%t want=%t", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func formatDifferenceClass(a, b string) string {
	// Specific transformations precede the broad strict-submultiset check:
	// dropping only parentheses or statement separators is also token loss,
	// but belongs to its named class. Each divergence gets one class.
	x, e := classificationTokens(a)
	if e != nil {
		return "unclassified"
	}
	y, e := classificationTokens(b)
	if e != nil {
		return "unclassified"
	}
	hasCast, hasColon := false, false
	for _, z := range x {
		hasColon = hasColon || z.value == "::"
	}
	for _, z := range y {
		hasCast = hasCast || strings.EqualFold(z.value, "CAST")
	}
	if hasColon && hasCast {
		return "cast"
	}
	if reflect.DeepEqual(tokenBag(x, false), tokenBag(y, false)) {
		return "reorder"
	}
	if reflect.DeepEqual(strippedTokens(x, "()"), strippedTokens(y, "()")) {
		return "paren"
	}
	if reflect.DeepEqual(tokenBag(x, true), tokenBag(y, true)) {
		return "reorder+paren"
	}
	// This is PLAN's presence predicate, as for cast above. Quoting a
	// keyword-named alias can additionally affect N9's AS removal, so equal
	// token counts are deliberately not a prerequisite for this class.
	for _, source := range x {
		if !source.kind.IsKeyword() {
			continue
		}
		for _, rendered := range y {
			if rendered.quoted && rendered.value == strings.ToLower(source.value) {
				return "keyword-name"
			}
		}
	}
	if reflect.DeepEqual(strippedTokens(x, ";"), strippedTokens(y, ";")) {
		return "split"
	}
	bx, by := tokenBag(x, false), tokenBag(y, false)
	subset, strict := true, false
	for k, n := range by {
		if n > bx[k] {
			subset = false
		}
	}
	for k, n := range bx {
		if n > by[k] {
			strict = true
		}
	}
	if subset && strict {
		return "legacy-lossy"
	}
	if identifierCaseOnly(x, y) {
		return "ident-case"
	}
	return "unclassified"
}

// Go maps cannot be constants. These literal counts are the frozen baseline;
// changing one requires a corpus or formatter explanation in the review.
const formatIdentCaseCount = 7 // Run 5 decision; bare contextual words upcased by legacy.

var formatDifferenceCounts = map[string]int{
	"cast": 31, "reorder": 6, "paren": 4, "reorder+paren": 1,
	"keyword-name": 7, "legacy-lossy": 1, "split": 4,
	"ident-case": formatIdentCaseCount, "unclassified": 0,
}

func TestNormalizeV2FormatInvariant(t *testing.T) {
	counts := map[string]int{}
	example := map[string]string{}
	accepted, same := 0, 0
	for _, s := range equivalenceCorpus(t) {
		if _, e := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Mode: fingerprint.ModeLegacy}); e != nil {
			continue
		}
		f, e := formatEquivalenceCompact(s.SQL)
		if e != nil {
			t.Fatalf("%s format: %v", s.Key(), e)
		}
		a, e := fingerprint.Normalize(s.SQL)
		if e != nil {
			t.Fatalf("%s normalize: %v", s.Key(), e)
		}
		b, e := fingerprint.Normalize(f)
		if e != nil {
			t.Fatalf("%s normalized format: %v", s.Key(), e)
		}
		accepted++
		if a == b {
			same++
			continue
		}
		c := formatDifferenceClass(a, b)
		counts[c]++
		if example[c] == "" {
			example[c] = s.Key()
		}
		if c == "unclassified" {
			t.Errorf("%s unclassified format divergence\na=%s\nb=%s", s.Key(), a, b)
		}
	}
	t.Logf("T6 accepted=%d equal=%d", accepted, same)
	for _, c := range []string{"cast", "reorder", "paren", "reorder+paren", "keyword-name", "legacy-lossy", "split", "ident-case", "unclassified"} {
		t.Logf("T6 %s %d %s", c, counts[c], example[c])
		if want, ok := formatDifferenceCounts[c]; ok && want != counts[c] {
			t.Errorf("%s count=%d want=%d", c, counts[c], want)
		}
	}
}

type intendedName struct {
	kind   models.TokenType
	value  string
	quoted bool
}

func nameProjection(ts []models.TokenWithSpan, d keywords.SQLDialect, source bool) []intendedName {
	var names []intendedName
	for i, x := range ts {
		k := x.Token.Type
		dotted := k.IsKeyword() && ((i > 0 && ts[i-1].Token.Type == models.TokenTypePeriod) || (i+1 < len(ts) && ts[i+1].Token.Type == models.TokenTypePeriod))
		if k != models.TokenTypeIdentifier && k != models.TokenTypeDoubleQuotedString && !dotted {
			continue
		}
		q := quotedOracle(x)
		value := x.Token.Value
		if !dotted {
			k = models.TokenTypeIdentifier
		}
		if source {
			if q {
				q = namequote.MustStayQuoted(value, d)
			} else if !dotted && i+1 < len(ts) && stringLiteral(ts[i+1].Token.Type) {
				// N14 is the sole identifier-spelling change in normal form.
				var b strings.Builder
				for j := 0; j < len(value); j++ {
					c := value[j]
					if c >= 'a' && c <= 'z' {
						c -= 'a' - 'A'
					}
					b.WriteByte(c)
				}
				value = b.String()
			}
		}
		names = append(names, intendedName{k, value, q})
	}
	return names
}

func assertNameSoundness(t *testing.T, key string, source, normalized []models.TokenWithSpan, d keywords.SQLDialect) int {
	t.Helper()
	want := nameProjection(source, d, true)
	got := nameProjection(normalized, d, false)
	present := make(map[intendedName]bool, len(got))
	position := 0
	for _, name := range got {
		present[name] = true
		for position < len(want) && want[position] != name {
			position++
		}
		if position == len(want) {
			t.Fatalf("%s unexpected or reordered normalized name: %+v\nintended=%+v\nnormalized=%+v", key, name, want, got)
		}
		position++
	}
	// N7 can remove repeated IN elements and VALUES rows, so multiplicities
	// may decrease. Their identical normalized text ensures every distinct
	// intended name still appears, in the original relative order.
	for _, name := range want {
		if !present[name] {
			t.Fatalf("%s intended name lost or re-tokenized incorrectly: %+v\nnormalized=%+v", key, name, got)
		}
	}
	return len(got)
}

// limitOffsetQuestion is the sole exception after placeholder substitution.
// Match tokens, so strings, named placeholders and FETCH/TOP are not skipped.
func limitOffsetQuestion(ts []models.TokenWithSpan) bool {
	for i := 1; i < len(ts); i++ {
		if ts[i].Token.Type == models.TokenTypeQuestion &&
			(ts[i-1].Token.Type == models.TokenTypeLimit || ts[i-1].Token.Type == models.TokenTypeOffset) {
			return true
		}
	}
	return false
}

func TestLimitOffsetQuestion(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      bool
	}{
		{"limit", "SELECT x FROM t LIMIT ?", true},
		{"offset", "SELECT x FROM t OFFSET ?", true},
		{"comment_gap", "SELECT x FROM t LIMIT /* gap */ ?", true},
		{"offset_after_limit", "SELECT x FROM t LIMIT 1 OFFSET ?", true},
		{"integer", "SELECT x FROM t LIMIT 1", false},
		{"named_placeholder", "SELECT x FROM t LIMIT $1", false},
		{"parenthesized", "SELECT x FROM t LIMIT (?)", false},
		{"elsewhere", "SELECT ? FROM t LIMIT 1", false},
		{"fetch", "SELECT x FROM t FETCH FIRST ? ROWS ONLY", false},
		{"top", "SELECT TOP ? x FROM t", false},
		{"string", "SELECT 'LIMIT ?'", false},
		{"quoted_name", `SELECT "LIMIT", ?`, false},
		{"statement_boundary", "SELECT x LIMIT; SELECT ?", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := equivalenceTokens(tc.sql, "")
			if err != nil {
				t.Fatal(err)
			}
			if got := limitOffsetQuestion(ts); got != tc.want {
				t.Errorf("limitOffsetQuestion(%q)=%v want=%v", tc.sql, got, tc.want)
			}
		})
	}
}

// substituteQuestionTokens tests normal-form syntax without depending on the
// parser accepting QUESTION placeholders. Retokenization/name soundness above
// still examines the actual normal form. Token spans preserve question marks
// inside kept string aliases and delimited identifiers.
func substituteQuestionTokens(sql string, ts []models.TokenWithSpan) (string, int) {
	var b strings.Builder
	last, count := 0, 0
	for _, x := range ts {
		if x.Token.Type != models.TokenTypeQuestion {
			continue
		}
		if count == 0 {
			b.Grow(len(sql) + 2)
		}
		start, end := sourceOffset(sql, x.Start), sourceOffset(sql, x.End)
		b.WriteString(sql[last:start])
		b.WriteString("'x'")
		last = end
		count++
	}
	if count == 0 {
		return sql, 0
	}
	b.WriteString(sql[last:])
	return b.String(), count
}

// Do not hide a failure elsewhere merely because the query has LIMIT/OFFSET ?.
// Only a structured error at that substituted value qualifies for the skip.
func limitOffsetSubstitutionFailure(original, substituted string, ts []models.TokenWithSpan, err error) bool {
	var parseErr *sqlerrors.Error
	if !limitOffsetQuestion(ts) || !errors.As(err, &parseErr) || parseErr.Location.Line < 1 || parseErr.Location.Column < 1 {
		return false
	}
	offset := sourceOffset(substituted, parseErr.Location)
	shift := 0
	for i, x := range ts {
		if x.Token.Type != models.TokenTypeQuestion {
			continue
		}
		start := sourceOffset(original, x.Start) + shift
		if i > 0 && (ts[i-1].Token.Type == models.TokenTypeLimit || ts[i-1].Token.Type == models.TokenTypeOffset) && offset >= start && offset < start+len("'x'") {
			return true
		}
		shift += len("'x'") - len("?")
	}
	return false
}

func TestLimitOffsetSubstitutionFailure(t *testing.T) {
	for _, tc := range []struct {
		name, sql, at string
		want          bool
	}{
		{"limit", "SELECT x FROM t LIMIT ?", "'x'", true},
		{"offset", "SELECT x FROM t OFFSET ?", "'x'", true},
		{"multiline", "SELECT ? FROM t\nLIMIT ?", "LIMIT 'x'", true},
		{"other_question", "SELECT ? FROM t LIMIT ?", "'x'", false},
		{"other_failure", "SELECT x alias FROM t LIMIT ?", "alias", false},
		{"fetch", "SELECT x FROM t FETCH FIRST ? ROWS ONLY", "'x'", false},
		{"integer_limit", "SELECT ? FROM t LIMIT 1", "'x'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := equivalenceTokens(tc.sql, "")
			if err != nil {
				t.Fatal(err)
			}
			substituted, _ := substituteQuestionTokens(tc.sql, ts)
			start := strings.Index(substituted, tc.at)
			if start < 0 {
				t.Fatalf("error marker %q missing from %q", tc.at, substituted)
			}
			if tc.name == "multiline" {
				start += len("LIMIT ")
			}
			prefix := substituted[:start]
			location := models.Location{Line: strings.Count(prefix, "\n") + 1, Column: start - strings.LastIndex(prefix, "\n")}
			err = fmt.Errorf("wrapped: %w", sqlerrors.NewError(sqlerrors.ErrCodeUnexpectedToken, "test failure", location))
			if got := limitOffsetSubstitutionFailure(tc.sql, substituted, ts, err); got != tc.want {
				t.Errorf("skip=%v want=%v at %+v in %q", got, tc.want, location, substituted)
			}
		})
	}
}

func TestSubstituteQuestionTokens(t *testing.T) {
	for _, tc := range []struct {
		name, sql, want string
		count           int
	}{
		{"none", "SELECT x FROM t", "SELECT x FROM t", 0},
		{"values", "VALUES (?, ?)", "VALUES ('x', 'x')", 2},
		{"typed", "SELECT DATE ?, INTERVAL ? DAY", "SELECT DATE 'x', INTERVAL 'x' DAY", 2},
		{"limit_offset", "SELECT x FROM t LIMIT ? OFFSET ?", "SELECT x FROM t LIMIT 'x' OFFSET 'x'", 2},
		{"named", "SELECT $1, :name, ?", "SELECT $1, :name, 'x'", 1},
		{"quoted", `SELECT '?' AS "?", ?`, `SELECT '?' AS "?", 'x'`, 1},
		{"alias", "SELECT x AS '?', ?", "SELECT x AS '?', 'x'", 1},
		{"multiline", "SELECT ?;\nSELECT ?", "SELECT 'x';\nSELECT 'x'", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := equivalenceTokens(tc.sql, "")
			if err != nil {
				t.Fatal(err)
			}
			got, count := substituteQuestionTokens(tc.sql, ts)
			if got != tc.want || count != tc.count {
				t.Errorf("substitution=(%q, %d) want=(%q, %d)", got, count, tc.want, tc.count)
			}
		})
	}
}

// implicitAliasReparses classifies a parser gap only if inserting AS at the
// reported alias tokens makes the entire substituted statement parse. Each
// retry must advance to a later original token, so unrelated failures and
// repeated failures at the same location cannot be hidden by this class.
func implicitAliasReparses(sql string, err error) bool {
	lastOffset := -1
	for err != nil {
		var parseErr *sqlerrors.Error
		located := err
		for {
			if !errors.As(located, &parseErr) {
				return false
			}
			if parseErr.Location.Line > 0 && parseErr.Location.Column > 0 {
				break
			}
			// CREATE VIEW wraps its query error without a location; inspect
			// the underlying structured error rather than guessing an alias.
			located = errors.Unwrap(parseErr)
		}
		offset := sourceOffset(sql, parseErr.Location)
		if offset <= lastOffset || offset > len(sql) {
			return false
		}
		ts, tokenErr := equivalenceTokens(sql, "")
		if tokenErr != nil {
			return false
		}
		alias := false
		var requiredAS []bool
		for i, token := range ts {
			if token.Token.Type == models.TokenTypeLParen {
				keep := false
				if i > 0 && !quotedOracle(ts[i-1]) {
					switch strings.ToUpper(ts[i-1].Token.Value) {
					case "CAST", "TRY_CAST", "SAFE_CAST", "XMLATTRIBUTES", "XMLFOREST":
						keep = true
					}
				}
				requiredAS = append(requiredAS, keep)
			} else if token.Token.Type == models.TokenTypeRParen && len(requiredAS) > 0 {
				requiredAS = requiredAS[:len(requiredAS)-1]
			}
			if sourceOffset(sql, token.Start) == offset && i > 0 &&
				(token.Token.Type == models.TokenTypeIdentifier || quotedOracle(token)) &&
				ts[i-1].Token.Type != models.TokenTypeAs &&
				(len(requiredAS) == 0 || !requiredAS[len(requiredAS)-1]) {
				alias = true
				break
			}
		}
		if !alias {
			return false
		}
		sql = sql[:offset] + "AS " + sql[offset:]
		lastOffset = offset + len("AS ")
		tree, nextErr := gosqlx.Parse(sql)
		if nextErr == nil {
			ast.ReleaseAST(tree)
			return true
		}
		err = nextErr
	}
	return false
}

func TestImplicitAliasReparses(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		want      bool
	}{
		{"bare", "SELECT id customer_id FROM customers", true},
		{"qualified", "SELECT a.id first_id, b.id second_id FROM a JOIN b ON a.id = b.id", true},
		{"returning", "DELETE FROM customers RETURNING id deleted_id", true},
		{"nested", "SELECT * FROM (SELECT a.id old_id FROM a) q", true},
		{"view", "CREATE VIEW customers AS SELECT id customer_id FROM source", true},
		{"multiline", "SELECT a.id first_id,\nb.id second_id FROM a, b", true},
		{"unrelated", "SELECT id customer_id FROM", false},
		{"missing_comma", "SELECT id customer_id other_id FROM customers", false},
		{"bad_limit", "SELECT id customer_id FROM customers LIMIT )", false},
		{"batch_without_semicolons", "BEGIN TRANSACTION UPDATE t SET id = 1 COMMIT TRANSACTION", false},
		{"xml_requires_as", "SELECT XMLELEMENT(NAME employee, XMLATTRIBUTES(employee_id id)) FROM employees", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.Parse(tc.sql)
			if err == nil {
				ast.ReleaseAST(tree)
				t.Fatal("fixture must fail before AS insertion")
			}
			if got := implicitAliasReparses(tc.sql, err); got != tc.want {
				t.Errorf("implicit-alias=%v want=%v: %v", got, tc.want, err)
			}
		})
	}
}

// F1 must drive this independently detected implicit-alias parser gap to zero.
const wantImplicitAliasReparseFailures = 44

// Only failures not repaired by explicit AS belong here. Every entry must
// still fail the symmetric substituted parse and explain the remaining gap.
var reparseLimitations = map[string]string{
	"realworld/mysql/11_stored_programs.sql#11":          "SRID requires a numeric value; N4's placeholder substituted with 'x' is not accepted",
	"realworld/sqlserver/11_batches_no_semicolons.sql#3": "the parser requires statement separators in this transaction batch; legacy formatting inserts semicolons but token normalization preserves their absence",
}

func TestNormalizeV2Reparses(t *testing.T) {
	retokenized, names, legacyAccepted, legacyReparseSkipped, limitOffsetSkipped, reparsed := 0, 0, 0, 0, 0, 0
	substitutedStatements, substitutedQuestions, implicitAliases, failures := 0, 0, 0, 0
	allowlistedFailures := make(map[string]bool, len(reparseLimitations))
	for _, s := range equivalenceCorpus(t) {
		// Tokenization/name soundness covers every v2-accepted statement,
		// including SQL the parse-and-format algorithm does not accept.
		n, e := fingerprint.Normalize(s.SQL)
		if e != nil {
			continue
		}
		source, e := equivalenceTokens(s.SQL, "")
		if e != nil {
			t.Fatalf("%s source tokenization: %v", s.Key(), e)
		}
		ts, e := equivalenceTokens(n, "")
		if e != nil {
			t.Fatalf("%s v2 re-tokenization: %v\nnormalized=%s", s.Key(), e, n)
		}
		retokenized++
		names += assertNameSoundness(t, s.Key(), source, ts, "")
		legacy, e := fingerprint.NormalizeWithOptions(s.SQL, fingerprint.Options{Mode: fingerprint.ModeLegacy})
		if e != nil {
			continue
		}
		legacyAccepted++
		legacyTokens, e := equivalenceTokens(legacy, "")
		if e != nil {
			t.Fatalf("%s legacy re-tokenization: %v", s.Key(), e)
		}
		legacyParseText, _ := substituteQuestionTokens(legacy, legacyTokens)
		baseline, e := gosqlx.Parse(legacyParseText)
		if e != nil {
			legacyReparseSkipped++
			continue
		}
		ast.ReleaseAST(baseline)
		parseText, count := substituteQuestionTokens(n, ts)
		if count > 0 {
			substitutedStatements++
			substitutedQuestions += count
		}
		tree, e := gosqlx.Parse(parseText)
		if e != nil {
			if implicitAliasReparses(parseText, e) {
				implicitAliases++
				t.Logf("T7 implicit-alias parser gap %s", s.Key())
				continue
			}
			if reason, ok := reparseLimitations[s.Key()]; ok {
				allowlistedFailures[s.Key()] = true
				t.Logf("T7 known parser limitation %s: %s", s.Key(), reason)
				continue
			}
			// M2: keep the narrow LIMIT/OFFSET exception only when the
			// substituted text still fails. Successful cases are counted
			// as reparsed even if their original form has LIMIT/OFFSET ?.
			if limitOffsetSubstitutionFailure(n, parseText, ts, e) {
				limitOffsetSkipped++
				continue
			}
			failures++
			t.Errorf("%s substituted v2 reparse fails while legacy normalized text reparses: %v\nlegacy=%s\nv2=%s\nsubstituted=%s", s.Key(), e, legacy, n, parseText)
			continue
		}
		ast.ReleaseAST(tree)
		reparsed++
	}
	if implicitAliases != wantImplicitAliasReparseFailures {
		t.Errorf("implicit-alias failures=%d want=%d; review the symmetric oracle and update the F1 count", implicitAliases, wantImplicitAliasReparseFailures)
	}
	for key, reason := range reparseLimitations {
		if !allowlistedFailures[key] {
			t.Errorf("%s allowlisted parser limitation no longer fails the substituted parse; remove or review the entry: %s", key, reason)
		}
	}
	t.Logf("T7 retokenized=%d names=%d legacy_accepted=%d legacy_reparse_skipped=%d legacy_parseable=%d substituted_statements=%d substituted_questions=%d limit_offset_placeholder_skipped=%d eligible=%d reparsed=%d implicit_alias_failures=%d allowlisted_failures=%d failures=%d", retokenized, names, legacyAccepted, legacyReparseSkipped, legacyAccepted-legacyReparseSkipped, substitutedStatements, substitutedQuestions, limitOffsetSkipped, legacyAccepted-legacyReparseSkipped-limitOffsetSkipped, reparsed, implicitAliases, len(allowlistedFailures), failures)
}
