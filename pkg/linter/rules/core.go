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

// Package rules assembles the built-in lint rules from its sub-packages
// (whitespace, style, keywords, safety, performance, naming) into ready-made
// rule sets. It lives above pkg/linter because every rule sub-package imports
// pkg/linter, so pkg/linter itself cannot import them.
package rules

import (
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

// CoreConfig holds the settings on which users of the core rule set
// (L001-L010) differ. The other core rules take no settings here: L006,
// L008 (trailing commas), L009 (explicit AS) and L007 (upper-case keywords)
// are configured identically everywhere.
type CoreConfig struct {
	// MaxConsecutiveBlankLines is the L003 limit.
	MaxConsecutiveBlankLines int
	// MaxIndentDepth and IndentSize configure L004.
	MaxIndentDepth int
	IndentSize     int
	// MaxLineLength is the L005 limit.
	MaxLineLength int
}

// DefaultCoreConfig returns the configuration of the `gosqlx lint` CLI
// command (L003 1 blank line, L004 depth 4 with 4-space indents, L005 100
// columns), which the MCP lint_sql tool and the C binding's gosqlx_lint share.
func DefaultCoreConfig() CoreConfig {
	return CoreConfig{
		MaxConsecutiveBlankLines: 1,
		MaxIndentDepth:           4,
		IndentSize:               4,
		MaxLineLength:            100,
	}
}

// CoreRules returns new instances of the ten core style rules L001-L010,
// configured by cfg. This is the single source of the rule set used by the
// `gosqlx lint` CLI, the `gosqlx action` command, the MCP lint_sql tool, the
// C binding and the first ten rules of gosqlx.Lint.
//
// The rules come grouped by sub-package, not by ID: whitespace (L001-L005,
// L010), then style (L006, L008, L009), then keywords (L007). The linter
// reports violations in rule order, so this order is part of the output.
func CoreRules(cfg CoreConfig) []linter.Rule {
	return []linter.Rule{
		// Whitespace rules (L001-L005, L010)
		whitespace.NewTrailingWhitespaceRule(),                                 // L001
		whitespace.NewMixedIndentationRule(),                                   // L002
		whitespace.NewConsecutiveBlankLinesRule(cfg.MaxConsecutiveBlankLines),  // L003
		whitespace.NewIndentationDepthRule(cfg.MaxIndentDepth, cfg.IndentSize), // L004
		whitespace.NewLongLinesRule(cfg.MaxLineLength),                         // L005
		whitespace.NewRedundantWhitespaceRule(),                                // L010

		// Style rules (L006, L008, L009)
		style.NewColumnAlignmentRule(),                   // L006
		style.NewCommaPlacementRule(style.CommaTrailing), // L008
		style.NewAliasingConsistencyRule(true),           // L009

		// Keyword rules (L007)
		keywords.NewKeywordCaseRule(keywords.CaseUpper), // L007
	}
}
