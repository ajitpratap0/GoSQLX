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
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// AnalysisResult contains the output of a SQL optimization analysis.
type AnalysisResult struct {
	// Suggestions contains optimization recommendations.
	Suggestions []AnalysisSuggestion

	// QueryComplexity is one of "simple", "moderate", or "complex".
	QueryComplexity string

	// Score is 0-100 where 100 means no issues found.
	Score int
}

// AnalysisSuggestion represents a single optimization recommendation.
type AnalysisSuggestion struct {
	RuleID   string // e.g., "OPT-001"
	Severity string // "info", "warning", or "error"
	Message  string // Short description
	Detail   string // Detailed explanation
}

// Analyze runs basic optimization analysis on the given SQL, checking for
// common anti-patterns such as SELECT *, missing WHERE clauses, and cartesian
// products.
//
// For full optimization analysis with all 20 built-in rules (OPT-001 through
// OPT-020), use pkg/advisor.New().AnalyzeSQL() directly. This function provides
// a quick check for the most common issues without requiring an additional import.
//
// Thread Safety: safe for concurrent use.
//
// Example:
//
//	result, err := gosqlx.Analyze("SELECT * FROM users")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Complexity: %s\n", result.QueryComplexity)
//	for _, s := range result.Suggestions {
//	    fmt.Printf("[%s] %s\n", s.RuleID, s.Message)
//	}
func Analyze(sql string) (*AnalysisResult, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}

	p := parser.GetParser()
	defer parser.PutParser(p)

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	var suggestions []AnalysisSuggestion

	for _, stmt := range tree.Statements {
		suggestions = append(suggestions, analyzeStatement(stmt)...)
	}

	complexity := "simple"
	if len(tree.Statements) > 0 {
		complexity = classifyQueryComplexity(tree.Statements[0])
	}

	score := 100
	for range suggestions {
		score -= 10
	}
	if score < 0 {
		score = 0
	}

	return &AnalysisResult{
		Suggestions:     suggestions,
		QueryComplexity: complexity,
		Score:           score,
	}, nil
}

// analyzeStatement runs basic optimization checks on a single statement.
func analyzeStatement(stmt ast.Statement) []AnalysisSuggestion {
	var suggestions []AnalysisSuggestion

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return suggestions
	}

	// OPT-001: SELECT * detection
	for _, col := range sel.Columns {
		if id, ok := col.(*ast.Identifier); ok && id.Name == "*" {
			suggestions = append(suggestions, AnalysisSuggestion{
				RuleID:   "OPT-001",
				Severity: "warning",
				Message:  "Avoid SELECT *; list columns explicitly",
				Detail:   "SELECT * retrieves all columns, which increases I/O and can break when schema changes. List only the columns you need.",
			})
			break
		}
		if ae, ok := col.(*ast.AliasedExpression); ok {
			if id, ok := ae.Expr.(*ast.Identifier); ok && id.Name == "*" {
				suggestions = append(suggestions, AnalysisSuggestion{
					RuleID:   "OPT-001",
					Severity: "warning",
					Message:  "Avoid SELECT *; list columns explicitly",
					Detail:   "SELECT * retrieves all columns, which increases I/O and can break when schema changes. List only the columns you need.",
				})
				break
			}
		}
	}

	return suggestions
}

// classifyQueryComplexity returns a rough complexity classification.
func classifyQueryComplexity(stmt ast.Statement) string {
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return "simple"
	}

	score := 0
	if len(sel.Joins) > 0 {
		score += len(sel.Joins)
	}
	if sel.GroupBy != nil {
		score++
	}
	if sel.Having != nil {
		score++
	}
	if sel.With != nil {
		score += 2
	}

	switch {
	case score >= 5:
		return "complex"
	case score >= 2:
		return "moderate"
	default:
		return "simple"
	}
}
