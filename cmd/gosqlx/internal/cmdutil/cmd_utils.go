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

package cmdutil

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// RootFlags holds pointers to the root command's persistent flag values.
// Sub-packages receive this to access global flags without circular imports.
type RootFlags struct {
	Verbose    *bool
	OutputFile *string
	Format     *string
}

// Valid output format constants
const (
	OutputFormatText  = "text"
	OutputFormatJSON  = "json"
	OutputFormatSARIF = "sarif"
)

// ValidOutputFormats lists all supported output formats for validation
var ValidOutputFormats = []string{OutputFormatText, OutputFormatJSON, OutputFormatSARIF}

// TrackChangedFlags returns a map of flag names that were explicitly set on the command line.
// This includes both local flags and parent persistent flags.
func TrackChangedFlags(cmd *cobra.Command) map[string]bool {
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
