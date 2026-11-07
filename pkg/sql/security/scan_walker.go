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
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// maxPooledScanDepth is the number of ancestor slots kept when a walker is
// returned to the pool (1024 interface slots, 16 KiB); deeper stacks are dropped.
const maxPooledScanDepth = 1024

// scanWalker is exclusively owned between acquire and release. Between scans,
// len(ancestors) == 0 and every slot in ancestors[:cap(ancestors)] is nil.
type scanWalker struct {
	s         *Scanner
	result    *ScanResult
	ancestors []ast.Node
}

var scanWalkerPool = sync.Pool{New: func() interface{} {
	return &scanWalker{ancestors: make([]ast.Node, 0, 16)}
}}

func (w *scanWalker) reset(s *Scanner, r *ScanResult) {
	w.s, w.result = s, r
	w.ancestors = w.ancestors[:0]
}

func acquireScanWalker(s *Scanner, r *ScanResult) *scanWalker {
	w, ok := scanWalkerPool.Get().(*scanWalker)
	if !ok {
		w = &scanWalker{ancestors: make([]ast.Node, 0, 16)}
	}
	w.reset(s, r)
	return w
}

func (w *scanWalker) release() (pooled bool) {
	w.s, w.result = nil, nil
	if cap(w.ancestors) > maxPooledScanDepth {
		return false
	}
	w.ancestors = w.ancestors[:0]
	scanWalkerPool.Put(w)
	return true
}

func (w *scanWalker) Visit(node ast.Node) (ast.Visitor, error) {
	if w.visit(node) {
		return w, nil
	}
	return nil, nil
}

func (w *scanWalker) visit(node ast.Node) bool {
	if node == nil {
		w.ancestors[len(w.ancestors)-1] = nil
		w.ancestors = w.ancestors[:len(w.ancestors)-1]
		return false
	}
	var parent ast.Node
	if len(w.ancestors) > 0 {
		parent = w.ancestors[len(w.ancestors)-1]
	}
	if join, ok := parent.(*ast.JoinClause); ok && node == &join.Left {
		// Left repeats FROM or an earlier join's right reference,
		// including its subquery and table function.
		return false
	}
	switch n := node.(type) {
	case *ast.FunctionCall:
		w.s.scanFunctionCall(n, w.result)
		w.s.scanCondition(n.Filter, w.result)
	case *ast.TableReference:
		w.s.scanTableReference(n, w.result)
	case *ast.SetOperation:
		// Direct operands are already checked by the outer operation.
		// Operations inside CTEs and subqueries start a new check.
		if _, nested := parent.(*ast.SetOperation); !nested {
			w.s.checkUnionInjection(n, false, w.result)
		}
	case *ast.SelectStatement:
		w.s.scanCondition(n.Where, w.result)
		w.s.scanCondition(n.Having, w.result)
		w.s.scanCondition(n.Qualify, w.result)
		w.s.scanCondition(n.PrewhereClause, w.result)
		w.s.scanCondition(n.StartWith, w.result)
	case *ast.ConnectByClause:
		w.s.scanCondition(n.Condition, w.result)
	case *ast.JoinClause:
		w.s.scanCondition(n.Condition, w.result)
		w.s.scanCondition(n.MatchCondition, w.result)
	case *ast.UpdateStatement:
		w.s.scanCondition(n.Where, w.result)
	case *ast.Update:
		w.s.scanCondition(n.Where, w.result)
	case *ast.DeleteStatement:
		w.s.scanCondition(n.Where, w.result)
	case *ast.Delete:
		w.s.scanCondition(n.Where, w.result)
	case *ast.MergeStatement:
		w.s.scanCondition(n.OnCondition, w.result)
	case *ast.MergeWhenClause:
		w.s.scanCondition(n.Condition, w.result)
	case *ast.MergeAction:
		w.s.scanCondition(n.Where, w.result)
		w.s.scanCondition(n.DeleteWhere, w.result)
	case *ast.WhenClause:
		w.s.scanCondition(n.Condition, w.result)
	case *ast.OnConflict:
		w.s.scanCondition(n.TargetWhere, w.result)
		w.s.scanCondition(n.Action.Where, w.result)
	case *ast.Values:
		w.s.scanStatementText(n.SQL(), w.result)
		return false
	case *ast.UtilityStatement:
		w.s.scanStatementText(n.Text, w.result)
		return false
	case *ast.SetStatement:
		w.s.scanStatementText(n.Text, w.result)
		return false
	case *ast.TransactionStatement:
		w.s.scanStatementText(n.Text, w.result)
		return false
	case *ast.UseStatement:
		w.s.scanStatementText(n.Text, w.result)
		return false
	case *ast.UnsupportedStatement:
		w.s.scanStatementText(n.RawSQL, w.result)
		return false
	}
	w.ancestors = append(w.ancestors, node)
	return true
}
