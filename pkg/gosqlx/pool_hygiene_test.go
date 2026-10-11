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

package gosqlx

import (
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// These tests read process-global pool counters, so they use before/after
// deltas, never call metrics.ResetPoolStats and never run in parallel.

func poolDelta(before, after map[string]metrics.PoolStat, name string) (gets, puts int64) {
	return after[name].Gets - before[name].Gets, after[name].Puts - before[name].Puts
}

func TestPoolHygiene_Balanced(t *testing.T) {
	const n = 50
	tests := []struct {
		name    string
		run     func() error
		wantErr bool
	}{
		{"ValidateMultiple", func() error {
			return ValidateMultiple([]string{"SELECT 1", "SELECT a FROM t WHERE a = 1", "INSERT INTO t (a) VALUES (1)"})
		}, false},
		{"ValidateMultiple_invalid", func() error {
			return ValidateMultiple([]string{"SELECT 1", "SELECT FROM WHERE"})
		}, true},
		{"Analyze", func() error {
			_, err := Analyze("SELECT * FROM users u JOIN orders o ON o.uid = u.id")
			return err
		}, false},
		{"ParseMultiple_error", func() error {
			res, err := ParseMultiple([]string{"SELECT 1", "SELECT 2", "SELECT FROM WHERE"})
			if res != nil {
				t.Errorf("results must be nil on error, got %d", len(res))
			}
			return err
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := metrics.GetPoolStats()
			for i := 0; i < n; i++ {
				err := tt.run()
				if (err != nil) != tt.wantErr {
					t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
				}
			}
			after := metrics.GetPoolStats()
			for _, pool := range []string{"ast", "parser", "tokenizer"} {
				g, p := poolDelta(before, after, pool)
				if g != p {
					t.Errorf("%s pool unbalanced: gets=%d puts=%d", pool, g, p)
				}
			}
			if g, _ := poolDelta(before, after, "ast"); g < n {
				t.Errorf("ast pool gets = %d, want >= %d", g, n)
			}
		})
	}
}

func TestParseMultiple_SuccessCallerOwns(t *testing.T) {
	before := metrics.GetPoolStats()
	results, err := ParseMultiple([]string{"SELECT 1", "SELECT 2", "SELECT 3"})
	if err != nil {
		t.Fatalf("ParseMultiple: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	g, p := poolDelta(before, metrics.GetPoolStats(), "ast")
	if g-p != 3 {
		t.Errorf("outstanding ASTs = %d, want 3", g-p)
	}
	for _, r := range results {
		ast.ReleaseAST(r)
	}
	g, p = poolDelta(before, metrics.GetPoolStats(), "ast")
	if g != p {
		t.Errorf("after release: gets=%d puts=%d", g, p)
	}
}

// poolContaminationRound validates a batch, then parses an unrelated query and
// checks the result is not polluted by nodes recycled from the batch.
func poolContaminationRound() error {
	if err := ValidateMultiple([]string{"SELECT a, b FROM t1 WHERE a = 1", "INSERT INTO t2 (x) VALUES (1)"}); err != nil {
		return err
	}
	// Invalid input in the mix exercises the error path.
	if err := ValidateMultiple([]string{"SELECT 1", "SELECT FROM WHERE"}); err == nil {
		return errUnexpectedSuccess
	}
	tree, err := Parse("SELECT c FROM t3 WHERE c > 2")
	if err != nil {
		return err
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		return errContaminated("statement count")
	}
	sel, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		return errContaminated("statement type")
	}
	if len(sel.Columns) != 1 {
		return errContaminated("column count")
	}
	if id, ok := sel.Columns[0].(*ast.Identifier); !ok || id.Name != "c" {
		return errContaminated("column identity")
	}
	if len(sel.From) != 1 || sel.From[0].Name != "t3" {
		return errContaminated("from table")
	}
	if sel.Where == nil {
		return errContaminated("where")
	}
	return nil
}

type contaminationError string

func (e contaminationError) Error() string { return "pool contamination: " + string(e) }

func errContaminated(what string) error { return contaminationError(what) }

var errUnexpectedSuccess = contaminationError("invalid batch validated successfully")

func TestValidateMultiple_ParseReleaseParseContamination(t *testing.T) {
	for i := 0; i < 100; i++ {
		if err := poolContaminationRound(); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := poolContaminationRound(); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestAnalyze_ResultIndependentOfPool(t *testing.T) {
	res, err := Analyze("SELECT * FROM users")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	for i := 0; i < 100; i++ {
		tree, err := Parse("SELECT id, name FROM other WHERE id = 5")
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		ast.ReleaseAST(tree)
	}
	if len(res.Suggestions) == 0 || res.Suggestions[0].RuleID != "OPT-001" {
		t.Errorf("suggestions = %+v, want first RuleID OPT-001", res.Suggestions)
	}
	if res.QueryComplexity != "simple" {
		t.Errorf("QueryComplexity = %q, want simple", res.QueryComplexity)
	}
	if res.Score != 90 {
		t.Errorf("Score = %d, want 90", res.Score)
	}
}
