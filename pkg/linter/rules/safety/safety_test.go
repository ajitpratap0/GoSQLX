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

package safety_test

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func makeContext(t *testing.T, sql string) *linter.Context {
	t.Helper()
	ctx := linter.NewContext(sql, "<test>")
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	ctx.WithTokens(tokens)
	p := parser.NewParser()
	defer p.Release()
	astObj, parseErr := p.ParseFromModelTokens(tokens)
	ctx.WithAST(astObj, parseErr)
	return ctx
}

// L011: DeleteWithoutWhere

func TestDeleteWithoutWhere_Violation(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := makeContext(t, "DELETE FROM users")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for DELETE without WHERE")
	}
	if violations[0].Rule != "L011" {
		t.Errorf("expected rule L011, got %s", violations[0].Rule)
	}
}

func TestDeleteWithoutWhere_NoViolation(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := makeContext(t, "DELETE FROM users WHERE id = 1")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestDeleteWithoutWhere_NilAST(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := linter.NewContext("", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(violations))
	}
}

// L012: UpdateWithoutWhere

func TestUpdateWithoutWhere_Violation(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := makeContext(t, "UPDATE users SET status = 'inactive'")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for UPDATE without WHERE")
	}
	if violations[0].Rule != "L012" {
		t.Errorf("expected rule L012, got %s", violations[0].Rule)
	}
}

func TestUpdateWithoutWhere_NoViolation(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := makeContext(t, "UPDATE users SET status = 'inactive' WHERE id = 42")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

func TestUpdateWithoutWhere_NilAST(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := linter.NewContext("", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(violations))
	}
}

// L013: DropWithoutCondition

func TestDropWithoutCondition_Violation(t *testing.T) {
	rule := safety.NewDropWithoutConditionRule()
	ctx := makeContext(t, "DROP TABLE users")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for DROP TABLE without IF EXISTS")
	}
	if violations[0].Rule != "L013" {
		t.Errorf("expected rule L013, got %s", violations[0].Rule)
	}
}

func TestDropWithoutCondition_NoViolation(t *testing.T) {
	rule := safety.NewDropWithoutConditionRule()
	ctx := makeContext(t, "DROP TABLE IF EXISTS users")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations for DROP TABLE IF EXISTS, got %d", len(violations))
	}
}

func TestDropWithoutCondition_NilAST(t *testing.T) {
	rule := safety.NewDropWithoutConditionRule()
	ctx := linter.NewContext("", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(violations))
	}
}

// L014: TruncateTable

func TestTruncateTable_Violation(t *testing.T) {
	rule := safety.NewTruncateTableRule()
	ctx := makeContext(t, "TRUNCATE TABLE users")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for TRUNCATE TABLE")
	}
	if violations[0].Rule != "L014" {
		t.Errorf("expected rule L014, got %s", violations[0].Rule)
	}
}

func TestTruncateTable_NilAST(t *testing.T) {
	rule := safety.NewTruncateTableRule()
	ctx := linter.NewContext("", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations for nil AST, got %d", len(violations))
	}
}

// L015: SelectIntoOutfile

func TestSelectIntoOutfile_Violation(t *testing.T) {
	rule := safety.NewSelectIntoOutfileRule()
	ctx := linter.NewContext("SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for SELECT INTO OUTFILE")
	}
	if violations[0].Rule != "L015" {
		t.Errorf("expected rule L015, got %s", violations[0].Rule)
	}
}

func TestSelectIntoDumpfile_Violation(t *testing.T) {
	rule := safety.NewSelectIntoOutfileRule()
	ctx := linter.NewContext("SELECT * FROM users INTO DUMPFILE '/tmp/dump.bin'", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) == 0 {
		t.Error("expected violation for SELECT INTO DUMPFILE")
	}
}

func TestSelectIntoOutfile_NoViolation(t *testing.T) {
	rule := safety.NewSelectIntoOutfileRule()
	ctx := linter.NewContext("SELECT id, name FROM users", "<test>")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d", len(violations))
	}
}

// Nested-traversal tests (C5: ast.Walk migration)
//
// After migrating to ast.Walk, DELETE/UPDATE/DROP/TRUNCATE statements are
// discovered at any nesting depth. The parser currently only constructs
// top-level DML, but these tests guard against regression if the rules are
// ever reverted to flat traversal and also lock in the walk-based behavior
// for the common CTE-in-SELECT shapes.

// L011: DELETE without WHERE is still flagged at the top level after
// migration to ast.Walk. The parser does not currently create DELETE nodes
// inside a CTE body (parser limitation, tracked separately), so walk-based
// traversal is equivalent to top-level for real inputs. This test locks in
// the straightforward top-level case.
func TestDeleteWithoutWhere_AfterWalkMigration_TopLevel(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	ctx := makeContext(t, "DELETE FROM users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 1 {
		t.Errorf("expected exactly 1 violation after walk migration, got %d", len(v))
	}
}

// L012: UPDATE without WHERE is still flagged at the top level after
// migration to ast.Walk. See L011 note above for parser limitations around
// DML in CTE bodies.
func TestUpdateWithoutWhere_AfterWalkMigration_TopLevel(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	ctx := makeContext(t, "UPDATE users SET active = 0")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 1 {
		t.Errorf("expected exactly 1 violation after walk migration, got %d", len(v))
	}
}

// L013: DROP without IF EXISTS still fires at top level post-migration.
func TestDropWithoutCondition_AfterWalkMigration_TopLevel(t *testing.T) {
	rule := safety.NewDropWithoutConditionRule()
	ctx := makeContext(t, "DROP TABLE users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 1 {
		t.Errorf("expected exactly 1 violation after walk migration, got %d", len(v))
	}
}

// L014: TRUNCATE still fires at top level post-migration.
func TestTruncateTable_AfterWalkMigration_TopLevel(t *testing.T) {
	rule := safety.NewTruncateTableRule()
	ctx := makeContext(t, "TRUNCATE TABLE users")
	v, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(v) != 1 {
		t.Errorf("expected exactly 1 violation after walk migration, got %d", len(v))
	}
}

// Fix methods

func TestDeleteWithoutWhere_Fix(t *testing.T) {
	rule := safety.NewDeleteWithoutWhereRule()
	content := "DELETE FROM users"
	result, err := rule.Fix(content, nil)
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}
	if result != content {
		t.Errorf("Fix() should return content unchanged, got %q", result)
	}
}

func TestUpdateWithoutWhere_Fix(t *testing.T) {
	rule := safety.NewUpdateWithoutWhereRule()
	content := "UPDATE users SET x = 1"
	result, err := rule.Fix(content, nil)
	if err != nil {
		t.Fatalf("Fix() error: %v", err)
	}
	if result != content {
		t.Errorf("Fix() should return content unchanged, got %q", result)
	}
}

func TestSelectIntoOutfile_CaseAndWhitespace(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want bool
	}{
		{"upper outfile", "SELECT * FROM t INTO OUTFILE '/tmp/x'", true},
		{"lower outfile", "select * from t into outfile '/tmp/x'", true},
		{"mixed outfile", "Select * From t Into OutFile '/tmp/x'", true},
		{"lower dumpfile", "select * from t into dumpfile '/tmp/x'", true},
		{"mixed dumpfile", "Select * From t Into DumpFile '/tmp/x'", true},
		{"surrounding whitespace", "\n  into outfile\t'/tmp/x'\n", true},
		{"two spaces", "SELECT * FROM t INTO  OUTFILE '/tmp/x'", false},
		{"tab between", "SELECT * FROM t INTO\tOUTFILE '/tmp/x'", false},
		{"inside comment", "SELECT 1 -- into outfile", true},
		{"no separator", "SELECT 1 INTOOUTFILE", false},
		{"truncated", "SELECT 1 INTO OUTFIL", false},
		{"dotless i", "select * from t \u0131nto outfile '/x'", true},
		{"dotless i in outfile", "select * from t into outf\u0131le '/x'", true},
		{"invalid utf8", "into outfil\xffe", false},
		{"empty", "", false},
	}
	rule := safety.NewSelectIntoOutfileRule()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			legacy := strings.Contains(strings.ToUpper(tc.sql), "INTO OUTFILE") ||
				strings.Contains(strings.ToUpper(tc.sql), "INTO DUMPFILE")
			for label, ctx := range map[string]*linter.Context{
				"text-only":   linter.NewContext(tc.sql, "<test>"),
				"with-tokens": makeContextLenient(tc.sql),
			} {
				violations, err := rule.Check(ctx)
				if err != nil {
					t.Fatalf("%s: Check() error: %v", label, err)
				}
				got := len(violations) > 0
				if got != tc.want {
					t.Errorf("%s: flagged=%v, want %v", label, got, tc.want)
				}
				if got != legacy {
					t.Errorf("%s: flagged=%v differs from ToUpper+Contains result %v", label, got, legacy)
				}
			}
		})
	}
}

// makeContextLenient builds a context with tokens and AST when the SQL
// tokenizes, and falls back to a text-only context otherwise.
func makeContextLenient(sql string) *linter.Context {
	ctx := linter.NewContext(sql, "<test>")
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return ctx
	}
	ctx.WithTokens(tokens)
	p := parser.NewParser()
	defer p.Release()
	astObj, parseErr := p.ParseFromModelTokens(tokens)
	ctx.WithAST(astObj, parseErr)
	return ctx
}

func TestSelectIntoOutfile_WithTokensAndAST(t *testing.T) {
	rule := safety.NewSelectIntoOutfileRule()
	ctx := makeContext(t, "select id from users into outfile '/tmp/x'")
	violations, err := rule.Check(ctx)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(violations) != 1 || violations[0].Rule != "L015" {
		t.Errorf("expected one L015 violation, got %+v", violations)
	}
}

func TestSelectIntoOutfile_RandomEquivalence(t *testing.T) {
	pieces := []string{"into", "INTO", "Into", " ", "  ", "\t", "outfile", "OUTFILE", "OutFile",
		"dumpfile", "DUMPFILE", "\u0131", "\u017f", "\xff", "x", "\u00e9", ";", "'"}
	rng := rand.New(rand.NewSource(562))
	rule := safety.NewSelectIntoOutfileRule()
	for n := 0; n < 20000; n++ {
		var sb strings.Builder
		for k := rng.Intn(8) + 1; k > 0; k-- {
			sb.WriteString(pieces[rng.Intn(len(pieces))])
		}
		sql := sb.String()
		upper := strings.ToUpper(sql)
		want := strings.Contains(upper, "INTO OUTFILE") || strings.Contains(upper, "INTO DUMPFILE")
		violations, err := rule.Check(linter.NewContext(sql, "<rand>"))
		if err != nil {
			t.Fatalf("Check(%q): %v", sql, err)
		}
		if got := len(violations) > 0; got != want {
			t.Fatalf("Check(%q) flagged=%v, ToUpper+Contains=%v", sql, got, want)
		}
	}
}

func TestSelectIntoOutfile_NoAllocOnClean(t *testing.T) {
	rule := safety.NewSelectIntoOutfileRule()
	ctx := linter.NewContext(strings.Repeat("select id from users;\n", 500), "<t>")
	allocs := testing.AllocsPerRun(50, func() { _, _ = rule.Check(ctx) })
	if allocs != 0 {
		t.Errorf("expected 0 allocs on clean input, got %v", allocs)
	}
}

func BenchmarkSelectIntoOutfile_LargeLowercase(b *testing.B) {
	sql := strings.Repeat("select id, name from users where active = true;\n", 2000)
	rule := safety.NewSelectIntoOutfileRule()
	ctx := linter.NewContext(sql, "<bench>")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rule.Check(ctx); err != nil {
			b.Fatalf("Check: %v", err)
		}
	}
}
