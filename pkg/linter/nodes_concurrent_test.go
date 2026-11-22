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

package linter_test

import (
	"reflect"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// TestContextConcurrentRuleCheck guards the documented contract that rules may
// Check one shared Context concurrently (pkg/linter/doc.go). Run under -race.
func TestContextConcurrentRuleCheck(t *testing.T) {
	const sql = "SELECT * FROM a, b WHERE a.id = b.id"
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defer ast.ReleaseAST(tree)

	rules := []linter.Rule{
		performance.NewSelectStarRule(),
		safety.NewDeleteWithoutWhereRule(),
		performance.NewImplicitCrossJoinRule(),
	}
	for _, pair := range visitorRulePairs() {
		rules = append(rules, pair[0])
	}
	expected := make([][]linter.Violation, len(rules))
	for i, rule := range rules {
		expected[i], err = rule.Check(linter.NewContext(sql, "concurrent.sql").WithAST(tree, nil))
		if err != nil {
			t.Fatal(err)
		}
	}
	for iter := 0; iter < 50; iter++ {
		ctx := linter.NewContext(sql, "concurrent.sql").WithAST(tree, nil)
		var wg sync.WaitGroup
		for g := 0; g < len(rules)*2; g++ {
			index := g % len(rules)
			rule := rules[index]
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := rule.Check(ctx)
				if err != nil || !reflect.DeepEqual(got, expected[index]) {
					t.Errorf("%s: got %v, error %v", rule.ID(), got, err)
				}
				independent := linter.NewContext(sql, "concurrent.sql").WithAST(tree, nil)
				got, err = rule.Check(independent)
				if err != nil || !reflect.DeepEqual(got, expected[index]) {
					t.Errorf("independent %s: got %v, error %v", rule.ID(), got, err)
				}
				if len(ctx.Nodes()) == 0 {
					t.Errorf("Nodes() empty")
				}
			}()
		}
		wg.Wait()
	}
}
