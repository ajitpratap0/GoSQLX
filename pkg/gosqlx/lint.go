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
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	lintrules "github.com/ajitpratap0/GoSQLX/pkg/linter/rules"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/naming"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/performance"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/safety"
	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// LintResult represents the result of linting a SQL string.
type LintResult struct {
	Violations []linter.Violation
}

// defaultLinter returns the process-wide linter used by Lint, built once on
// first use. Sharing is safe because the Linter and every built-in rule are
// stateless after construction: rule Check methods read only immutable
// configuration set in their constructors and allocate all per-call state
// (visitors, violation slices) locally; LintString keeps its Context,
// tokenizer, parser and AST local to the call. Never call SetDialect (or
// otherwise mutate) the returned Linter; Lint has no dialect option. Any rule
// added to allRules must preserve this invariant.
var defaultLinter = sync.OnceValue(func() *linter.Linter {
	return linter.New(allRules()...)
})

// Lint checks SQL for style, safety, and performance issues using all 30 built-in
// lint rules (L001-L030). Returns violations found and any error encountered.
//
// This is a convenience wrapper around the pkg/linter package that uses a
// shared, lazily-built linter with all rules enabled using sensible defaults.
// For fine-grained control over which rules to enable or their configuration,
// use pkg/linter directly.
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
	l := defaultLinter()
	fileResult := l.LintString(sql, "<input>")
	if fileResult.Error != nil {
		return nil, fileResult.Error
	}
	return &LintResult{Violations: fileResult.Violations}, nil
}

// dialectLinters caches one linter per dialect for LintWithDialect. Only
// dialects accepted by sqlkeywords.IsValidDialect are ever stored, so the cache
// is bounded by the size of sqlkeywords.AllDialects(). Each cached
// Linter has its dialect set exactly once, before it is published, and is never
// mutated afterwards, so sharing it follows the same invariant as defaultLinter.
var dialectLinters sync.Map // sqlkeywords.SQLDialect -> *linter.Linter

func linterForDialect(dialect sqlkeywords.SQLDialect) *linter.Linter {
	if cached, ok := dialectLinters.Load(dialect); ok {
		if l, ok := cached.(*linter.Linter); ok {
			return l
		}
	}
	l := linter.New(allRules()...)
	l.SetDialect(dialect)
	actual, _ := dialectLinters.LoadOrStore(dialect, l)
	if shared, ok := actual.(*linter.Linter); ok {
		return shared
	}
	return l
}

// LintWithDialect is like Lint but tokenizes and parses the SQL with the given
// dialect, so the AST-based rules (L011-L030) also run on dialect-specific
// syntax such as SQL Server's TOP or [bracketed] identifiers. An empty dialect
// behaves exactly like Lint. An unknown dialect returns an error wrapping
// ErrUnsupportedDialect, matching ParseWithDialect.
//
// Thread Safety: safe for concurrent use.
func LintWithDialect(sql string, dialect sqlkeywords.SQLDialect) (*LintResult, error) {
	if dialect == "" {
		return Lint(sql)
	}
	if !sqlkeywords.IsValidDialect(string(dialect)) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDialect, dialect)
	}
	fileResult := linterForDialect(dialect).LintString(sql, "<input>")
	if fileResult.Error != nil {
		return nil, fileResult.Error
	}
	return &LintResult{Violations: fileResult.Violations}, nil
}

// allRules returns all 30 built-in lint rules with sensible defaults: the
// core rules L001-L010 from rules.CoreRules (with a 120-column L005 limit)
// followed by L011-L030.
func allRules() []linter.Rule {
	core := lintrules.DefaultCoreConfig()
	core.MaxLineLength = 120
	return append(lintrules.CoreRules(core),
		// Safety rules (L011-L015)
		safety.NewDeleteWithoutWhereRule(),   // L011
		safety.NewUpdateWithoutWhereRule(),   // L012
		safety.NewDropWithoutConditionRule(), // L013
		safety.NewTruncateTableRule(),        // L014
		safety.NewSelectIntoOutfileRule(),    // L015

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
		naming.NewTableAliasRequiredRule(),        // L024
		naming.NewReservedKeywordIdentifierRule(), // L025
		naming.NewImplicitColumnListRule(),        // L026
		naming.NewUnionAllPreferredRule(),         // L027
		naming.NewMissingOrderByLimitRule(),       // L028
		naming.NewSubqueryCanBeJoinRule(),         // L029
		naming.NewDistinctOnManyColumnsRule(),     // L030
	)
}
