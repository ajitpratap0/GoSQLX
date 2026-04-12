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
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/naming"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

// LintResult represents the result of linting a SQL string.
type LintResult struct {
	Violations []linter.Violation
}

// Lint checks SQL for style, safety, and performance issues using all 30 built-in
// lint rules (L001-L030). Returns violations found and any error encountered.
//
// This is a convenience wrapper around the pkg/linter package that creates a
// linter with all rules enabled using sensible defaults. For fine-grained control
// over which rules to enable or their configuration, use pkg/linter directly.
//
// Thread Safety: safe for concurrent use.
//
// Example:
//
//	result, err := gosqlx.Lint("SELECT * FROM users")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, v := range result.Violations {
//	    fmt.Printf("[%s] %s: %s\n", v.Rule, v.RuleName, v.Message)
//	}
func Lint(sql string) (*LintResult, error) {
	l := linter.New(allRules()...)
	fileResult := l.LintString(sql, "<input>")
	if fileResult.Error != nil {
		return nil, fileResult.Error
	}
	return &LintResult{Violations: fileResult.Violations}, nil
}

// allRules returns all 30 built-in lint rules with sensible defaults.
func allRules() []linter.Rule {
	return []linter.Rule{
		// Whitespace rules (L001-L005, L010)
		whitespace.NewTrailingWhitespaceRule(),     // L001
		whitespace.NewMixedIndentationRule(),       // L002
		whitespace.NewConsecutiveBlankLinesRule(1),  // L003
		whitespace.NewIndentationDepthRule(4, 4),   // L004
		whitespace.NewLongLinesRule(120),            // L005
		whitespace.NewRedundantWhitespaceRule(),     // L010

		// Style rules (L006, L008, L009)
		style.NewColumnAlignmentRule(),                   // L006
		style.NewCommaPlacementRule(style.CommaTrailing), // L008
		style.NewAliasingConsistencyRule(true),           // L009

		// Keyword rules (L007)
		keywords.NewKeywordCaseRule(keywords.CaseUpper), // L007

		// Safety rules (L011-L015)
		safety.NewDeleteWithoutWhereRule(),  // L011
		safety.NewUpdateWithoutWhereRule(),  // L012
		safety.NewDropWithoutConditionRule(), // L013
		safety.NewTruncateTableRule(),       // L014
		safety.NewSelectIntoOutfileRule(),   // L015

		// Performance rules (L016-L023)
		performance.NewSelectStarRule(),        // L016
		performance.NewMissingWhereRule(),      // L017
		performance.NewLeadingWildcardRule(),   // L018
		performance.NewNotInWithNullRule(),     // L019
		performance.NewSubqueryInSelectRule(),  // L020
		performance.NewOrInsteadOfInRule(),     // L021
		performance.NewFunctionOnColumnRule(),  // L022
		performance.NewImplicitCrossJoinRule(), // L023

		// Naming rules (L024-L030)
		naming.NewTableAliasRequiredRule(),       // L024
		naming.NewReservedKeywordIdentifierRule(), // L025
		naming.NewImplicitColumnListRule(),       // L026
		naming.NewUnionAllPreferredRule(),        // L027
		naming.NewMissingOrderByLimitRule(),      // L028
		naming.NewSubqueryCanBeJoinRule(),        // L029
		naming.NewDistinctOnManyColumnsRule(),    // L030
	}
}
