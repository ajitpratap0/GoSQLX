// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// frozen pre-W6-02 implementation, the reference for TestScanWalkerEquivalence; do not edit
func scanInspectReference(s *Scanner, tree *ast.AST) *ScanResult {
	result := &ScanResult{
		Findings: make([]Finding, 0),
	}

	if tree == nil {
		return result
	}

	// Ancestry is local to the scan, so concurrent scans share no walk state.
	// Preallocated so typical nesting depths need no regrowth.
	ancestors := make([]ast.Node, 0, 16)
	ast.Inspect(tree, func(node ast.Node) bool {
		if node == nil {
			ancestors = ancestors[:len(ancestors)-1]
			return false
		}
		var parent ast.Node
		if len(ancestors) > 0 {
			parent = ancestors[len(ancestors)-1]
		}
		if join, ok := parent.(*ast.JoinClause); ok && node == &join.Left {
			// Left repeats FROM or an earlier join's right reference,
			// including its subquery and table function.
			return false
		}
		switch n := node.(type) {
		case *ast.FunctionCall:
			s.scanFunctionCall(n, result)
			s.scanCondition(n.Filter, result)
		case *ast.TableReference:
			s.scanTableReference(n, result)
		case *ast.SetOperation:
			// Direct operands are already checked by the outer operation.
			// Operations inside CTEs and subqueries start a new check.
			if _, nested := parent.(*ast.SetOperation); !nested {
				s.checkUnionInjection(n, false, result)
			}
		case *ast.SelectStatement:
			s.scanCondition(n.Where, result)
			s.scanCondition(n.Having, result)
			s.scanCondition(n.Qualify, result)
			s.scanCondition(n.PrewhereClause, result)
			s.scanCondition(n.StartWith, result)
		case *ast.ConnectByClause:
			s.scanCondition(n.Condition, result)
		case *ast.JoinClause:
			s.scanCondition(n.Condition, result)
			s.scanCondition(n.MatchCondition, result)
		case *ast.UpdateStatement:
			s.scanCondition(n.Where, result)
		case *ast.Update:
			s.scanCondition(n.Where, result)
		case *ast.DeleteStatement:
			s.scanCondition(n.Where, result)
		case *ast.Delete:
			s.scanCondition(n.Where, result)
		case *ast.MergeStatement:
			s.scanCondition(n.OnCondition, result)
		case *ast.MergeWhenClause:
			s.scanCondition(n.Condition, result)
		case *ast.MergeAction:
			s.scanCondition(n.Where, result)
			s.scanCondition(n.DeleteWhere, result)
		case *ast.WhenClause:
			s.scanCondition(n.Condition, result)
		case *ast.OnConflict:
			s.scanCondition(n.TargetWhere, result)
			s.scanCondition(n.Action.Where, result)
		case *ast.Values:
			s.scanStatementText(n.SQL(), result)
			return false
		case *ast.UtilityStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.SetStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.TransactionStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.UseStatement:
			s.scanStatementText(n.Text, result)
			return false
		case *ast.UnsupportedStatement:
			s.scanStatementText(n.RawSQL, result)
			return false
		}
		ancestors = append(ancestors, node)
		return true
	})

	// Update counts
	s.updateCounts(result)

	return result
}

type scanWalkerCase struct {
	name    string
	sql     string
	dialect keywords.SQLDialect
}

// scanWalkerTargetCases is also used by the concurrent pool test. Keep the
// small tree immediately after the deep tree to exercise the next scan.
func scanWalkerTargetCases() []scanWalkerCase {
	const pg = keywords.DialectPostgreSQL
	const ch = keywords.DialectClickHouse
	return []scanWalkerCase{
		{"table function join", "SELECT * FROM url('http://x') AS a JOIN s3('y') AS b ON a.id = b.id", ch},
		{"three table functions", "SELECT * FROM url('http://x') AS a JOIN s3('y') AS b ON a.id = b.id JOIN remote('z') AS c ON b.id = c.id", ch},
		{"CTE set operations", "WITH c AS (SELECT a FROM t UNION SELECT b FROM u UNION SELECT NULL, NULL FROM information_schema.tables) SELECT * FROM c", pg},
		{"subquery set operations", "SELECT * FROM (SELECT a FROM t UNION SELECT b FROM u UNION SELECT NULL, NULL FROM information_schema.tables) AS c", pg},
		{"right set operation", "SELECT a FROM t UNION (SELECT b FROM u UNION SELECT NULL, NULL FROM information_schema.tables)", pg},
		{"nested VALUES", "SELECT * FROM (VALUES (pg_sleep(5))) v", pg},
		{"utility text", "EXEC xp_cmdshell 'dir'", keywords.DialectSQLServer},
		{"set text", "SET @a = SLEEP(5)", keywords.DialectMySQL},
		{"transaction text", "COMMIT PREPARED 'OR 1=1'", pg},
		{"use text", "USE `OR 1=1`", keywords.DialectMySQL},
		{"VALUES text", "VALUES (pg_sleep(5))", pg},
		{"merge condition", "MERGE INTO t USING s ON t.id = s.other_id WHEN MATCHED AND 1=1 THEN UPDATE SET x = s.x", pg},
		{"conflict condition", "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET x = 1 WHERE 1=1", pg},
		{"START WITH condition", "SELECT * FROM t START WITH 1=1 CONNECT BY PRIOR id = pid", keywords.DialectOracle},
		{"deep chain", "SELECT * FROM t WHERE " + strings.Repeat("1=1 OR ", 4999) + "1=1", pg},
		{"small after deep", "SELECT pg_sleep(5)", pg},
	}
}

func scanWalkerResultDump(r *ScanResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "total=%d critical=%d high=%d medium=%d low=%d\n", r.TotalCount, r.CriticalCount, r.HighCount, r.MediumCount, r.LowCount)
	for i, f := range r.Findings {
		fmt.Fprintf(&b, "%d: Severity=%q Pattern=%q Line=%d Column=%d Description=%q Risk=%q SQL=%q Suggestion=%q\n", i, f.Severity, f.Pattern, f.Line, f.Column, f.Description, f.Risk, f.SQL, f.Suggestion)
	}
	return b.String()
}

func TestScanWalkerEquivalence(t *testing.T) {
	s := NewScanner()
	compare := func(t *testing.T, tree *ast.AST, requireFinding bool) (int, int) {
		t.Helper()
		got, want := s.Scan(tree), scanInspectReference(s, tree)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Scan/reference mismatch\nScan:\n%sreference:\n%s", scanWalkerResultDump(got), scanWalkerResultDump(want))
		}
		if again := s.Scan(tree); !reflect.DeepEqual(got, again) {
			t.Fatalf("Scan changed across calls\nfirst:\n%ssecond:\n%s", scanWalkerResultDump(got), scanWalkerResultDump(again))
		}
		if requireFinding && len(got.Findings) == 0 {
			t.Fatal("targeted fixture must produce at least one finding")
		}
		return len(got.Findings), len(want.Findings)
	}
	parseCompare := func(t *testing.T, sql string, dialect keywords.SQLDialect, requireFinding bool) (int, int) {
		t.Helper()
		tree, err := gosqlx.ParseWithDialect(sql, dialect)
		if err != nil {
			if requireFinding {
				t.Fatalf("targeted fixture parse: %v", err)
			}
			t.Skipf("unparseable corpus statement: %v", err)
		}
		defer ast.ReleaseAST(tree)
		return compare(t, tree, requireFinding)
	}
	corpus, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	stride := 1
	if raceEnabled || testing.Short() {
		stride = 4
	}
	t.Run("corpus", func(t *testing.T) {
		for i, st := range corpus.All() {
			if i%stride != 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", st.Dialect, i), func(t *testing.T) {
				parseCompare(t, st.SQL, keywords.SQLDialect(st.Dialect), false)
			})
		}
	})
	total, referenceTotal := 0, 0
	t.Run("realworld suffixes", func(t *testing.T) {
		suffixes := []string{"", " OR 1=1", " OR a=a", " UNION SELECT NULL,NULL FROM information_schema.tables", "; DROP TABLE x", " AND SLEEP(5)", " OR 'a'='a'"}
		for _, dialect := range benchcorpus.Dialects() {
			for i, st := range corpus.RealWorld(dialect) {
				if i%stride != 0 {
					continue
				}
				for j, suffix := range suffixes {
					t.Run(fmt.Sprintf("%s/%d/%d", dialect, i, j), func(t *testing.T) {
						n, ref := parseCompare(t, st.SQL+suffix, keywords.SQLDialect(dialect), false)
						total += n
						referenceTotal += ref
					})
				}
			}
		}
		if total == 0 || referenceTotal == 0 {
			t.Fatalf("realworld suffix matrix is vacuous: Scan findings=%d reference findings=%d", total, referenceTotal)
		}
	})
	t.Run("targeted", func(t *testing.T) {
		for _, tc := range scanWalkerTargetCases() {
			t.Run(tc.name, func(t *testing.T) { parseCompare(t, tc.sql, tc.dialect, true) })
		}
		t.Run("unsupported text", func(t *testing.T) {
			// The parser never constructs UnsupportedStatement; cover this legacy
			// node directly, as TestScan_RawStatementNodeTypes does.
			tree := &ast.AST{Statements: []ast.Statement{&ast.UnsupportedStatement{RawSQL: "SELECT pg_sleep(5)"}}}
			defer ast.ReleaseAST(tree)
			compare(t, tree, true)
		})
	})
}
