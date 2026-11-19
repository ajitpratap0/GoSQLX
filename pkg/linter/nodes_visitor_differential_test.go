// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package linter_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/naming"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// The old_walk_* test files preserve the pre-migration implementations.
func visitorRulePairs() [][2]linter.Rule {
	return [][2]linter.Rule{
		{style.NewAliasingConsistencyRule(true), NewAliasingConsistencyRule(true)},
		{naming.NewUnionAllPreferredRule(), NewUnionAllPreferredRule()},
		{performance.NewLeadingWildcardRule(), NewLeadingWildcardRule()},
		{performance.NewNotInWithNullRule(), NewNotInWithNullRule()},
		{performance.NewOrInsteadOfInRule(), NewOrInsteadOfInRule()},
	}
}

func TestVisitorRulesOldWalkDifferential(t *testing.T) {
	cases := []lintCorpusInput{
		{"where-subquery", "SELECT * FROM outer_t WHERE id IN (SELECT id FROM inner_t WHERE name LIKE '%x')"},
		{"derived", "SELECT * FROM (SELECT * FROM a x JOIN b ON x.id = b.id) d"},
		{"cte", "WITH c AS (SELECT * FROM a WHERE x NOT IN (SELECT x FROM b)) SELECT * FROM c"},
		{"set-right", "SELECT 1 UNION ALL SELECT x FROM t WHERE x=1 OR x=2 OR x=3"},
		{"second-statement", "SELECT 1; SELECT * FROM t WHERE a LIKE '%a' AND b LIKE '%b'"},
		{"nested-union", "SELECT * FROM (SELECT x FROM a UNION SELECT x FROM b) d"},
		{"fallback", "SELECT users.id FROM users u JOIN orders ON"},
		{"empty", ""},
	}
	pairs := visitorRulePairs()
	hits := make(map[string]int)
	multi := false
	parsed := 0
	for _, dialect := range nodeTestDialects {
		inputs := append(lintCorpusInputs(t, dialect, true), cases...)
		for _, input := range inputs {
			tree, parseErr := gosqlx.ParseWithDialect(input.sql, keywords.SQLDialect(dialect))
			ctx := linter.NewContext(input.sql, input.name).WithAST(tree, parseErr)
			for _, pair := range pairs {
				got, gotErr := pair[0].Check(ctx)
				want, wantErr := pair[1].Check(ctx)
				gotBytes, gotJSONErr := json.Marshal(got)
				wantBytes, wantJSONErr := json.Marshal(want)
				if gotJSONErr != nil || wantJSONErr != nil || !bytes.Equal(gotBytes, wantBytes) || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
					t.Fatalf("%s/%s/%s: got %#v (%v), want %#v (%v)", dialect, input.name, pair[0].ID(), got, gotErr, want, wantErr)
				}
				hits[pair[0].ID()] += len(got)
				if len(got) >= 2 {
					multi = true
				}
			}
			if tree != nil {
				ast.ReleaseAST(tree)
			}
			if parseErr == nil {
				parsed++
			}
		}
	}
	for _, pair := range pairs {
		if hits[pair[0].ID()] == 0 {
			t.Errorf("%s never fired", pair[0].ID())
		}
	}
	if !multi {
		t.Error("no multi-hit case")
	}
	if parsed == 0 {
		t.Fatal("no parsed inputs")
	}
	t.Logf("parsed=%d hits=%v", parsed, hits)
}

func TestVisitorRulesNilASTAndParseError(t *testing.T) {
	for _, parseErr := range []error{nil, fmt.Errorf("parse failure")} {
		ctx := linter.NewContext("SELECT users.id FROM users u JOIN orders ON", "fallback.sql").WithAST(nil, parseErr)
		for _, pair := range visitorRulePairs() {
			got, gotErr := pair[0].Check(ctx)
			want, wantErr := pair[1].Check(ctx)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
				t.Fatalf("%s: got %#v (%v), want %#v (%v)", pair[0].ID(), got, gotErr, want, wantErr)
			}
		}
	}
}

func TestAliasingParseErrorWithASTUsesFallback(t *testing.T) {
	tree, err := gosqlx.Parse("SELECT * FROM a x JOIN b ON x.id = b.id")
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	ctx := linter.NewContext("SELECT users.id FROM users u JOIN orders ON", "fallback.sql").WithAST(tree, fmt.Errorf("parse failure"))
	pair := visitorRulePairs()[0]
	got, gotErr := pair[0].Check(ctx)
	want, wantErr := pair[1].Check(ctx)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotErr, wantErr) {
		t.Fatalf("got %#v (%v), want %#v (%v)", got, gotErr, want, wantErr)
	}
}

func TestVisitorRulesNestedTriggers(t *testing.T) {
	cases := []struct {
		name, sql, id string
		min           int
	}{
		{"where subquery", "SELECT * FROM outer_t WHERE id IN (SELECT id FROM inner_t WHERE name LIKE '%x')", "L018", 1},
		{"derived table", "SELECT * FROM (SELECT * FROM a x JOIN b ON x.id = b.id) d", "L009", 1},
		{"cte", "WITH c AS (SELECT * FROM a WHERE x NOT IN (SELECT x FROM b)) SELECT * FROM c", "L019", 1},
		{"set right", "SELECT 1 UNION ALL SELECT x FROM t WHERE x=1 OR x=2 OR x=3", "L021", 1},
		{"second statement", "SELECT 1; SELECT * FROM t WHERE a LIKE '%a' AND b LIKE '%b'", "L018", 2},
		{"nested union", "SELECT * FROM (SELECT x FROM a UNION SELECT x FROM b) d", "L027", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, err := gosqlx.Parse(tc.sql)
			if err != nil {
				t.Fatal(err)
			}
			defer ast.ReleaseAST(tree)
			ctx := linter.NewContext(tc.sql, tc.name).WithAST(tree, nil)
			for _, pair := range visitorRulePairs() {
				if pair[0].ID() == tc.id {
					got, err := pair[0].Check(ctx)
					if err != nil || len(got) < tc.min {
						t.Fatalf("%s got %v, %v; want >= %d", tc.id, got, err, tc.min)
					}
					return
				}
			}
			t.Fatalf("rule %s missing", tc.id)
		})
	}
}
