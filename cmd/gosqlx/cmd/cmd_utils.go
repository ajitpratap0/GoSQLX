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

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Valid output format constants
const (
	OutputFormatText  = "text"
	OutputFormatJSON  = "json"
	OutputFormatSARIF = "sarif"
)

// ValidOutputFormats lists all supported output formats for validation
var ValidOutputFormats = []string{OutputFormatText, OutputFormatJSON, OutputFormatSARIF}

// trackChangedFlags returns a map of flag names that were explicitly set on the command line.
// This includes both local flags and parent persistent flags.
func trackChangedFlags(cmd *cobra.Command) map[string]bool {
	flagsChanged := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		flagsChanged[f.Name] = true
	})
	if cmd.Parent() != nil && cmd.Parent().PersistentFlags() != nil {
		cmd.Parent().PersistentFlags().Visit(func(f *pflag.Flag) {
			flagsChanged[f.Name] = true
		})
	}
	return flagsChanged
}

// validateDialectName returns an error if dialect is a non-empty, unrecognized
// SQL dialect name. An empty string means "use the default dialect" and is
// always accepted.
func validateDialectName(dialect string) error {
	if dialect != "" && !keywords.IsValidDialect(dialect) {
		return fmt.Errorf("unknown SQL dialect %q; valid dialects: postgresql, mysql, mariadb, sqlserver, oracle, sqlite, snowflake, bigquery, redshift", dialect)
	}
	return nil
}

// tokenizerForDialect returns a tokenizer configured for the given dialect
// together with a release function that must be called when tokenization is
// complete (use defer).
//
// For the default (empty) dialect a pooled tokenizer is used and returned to the
// pool. For an explicit dialect a fresh, non-pooled tokenizer is created: the
// tokenizer pool's Reset does not clear dialect/keyword state, so returning a
// dialect-configured tokenizer to the pool would leak that state to later
// callers. Callers should validate the dialect with validateDialectName first;
// NewWithDialect silently falls back to PostgreSQL for unknown names.
func tokenizerForDialect(dialect string) (*tokenizer.Tokenizer, func(), error) {
	if dialect == "" {
		tkz := tokenizer.GetTokenizer()
		return tkz, func() { tokenizer.PutTokenizer(tkz) }, nil
	}
	tkz, err := tokenizer.NewWithDialect(keywords.SQLDialect(dialect))
	if err != nil {
		return nil, nil, err
	}
	return tkz, func() {}, nil
}

// parserForDialect builds a parser configured for the given dialect. An empty
// dialect yields the default parser.
func parserForDialect(dialect string) *parser.Parser {
	if dialect == "" {
		return parser.NewParser()
	}
	return parser.NewParser(parser.WithDialect(dialect))
}
