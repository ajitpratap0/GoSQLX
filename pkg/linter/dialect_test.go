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

package linter

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// captureRule records whether the linting context contained a successfully
// parsed AST, so tests can observe dialect-aware parsing behavior.
type captureRule struct {
	BaseRule
	parsedOK bool
}

func (r *captureRule) Check(ctx *Context) ([]Violation, error) {
	r.parsedOK = ctx.AST != nil && ctx.ParseErr == nil
	return nil, nil
}

func (r *captureRule) Fix(content string, _ []Violation) (string, error) {
	return content, nil
}

// TestLinter_SetDialect verifies that SetDialect threads the dialect into the
// linter's internal tokenize/parse step. MySQL's `LIMIT offset, count` fails to
// parse under the default dialect but succeeds under MySQL.
func TestLinter_SetDialect(t *testing.T) {
	const sql = "SELECT a, b FROM t LIMIT 10, 20"

	// Default dialect: parsing fails, so the AST is unavailable to rules.
	def := &captureRule{BaseRule: NewBaseRule("T001", "capture", "captures parse state", SeverityInfo, false)}
	New(def).LintString(sql, "test.sql")
	if def.parsedOK {
		t.Fatal("expected parse failure under default dialect, but AST was available")
	}

	// MySQL dialect: parsing succeeds, so the AST is available to rules.
	my := &captureRule{BaseRule: NewBaseRule("T001", "capture", "captures parse state", SeverityInfo, false)}
	l := New(my)
	l.SetDialect(keywords.DialectMySQL)
	l.LintString(sql, "test.sql")
	if !my.parsedOK {
		t.Fatal("expected successful parse under mysql dialect, but AST was unavailable")
	}
}
