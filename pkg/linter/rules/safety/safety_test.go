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
