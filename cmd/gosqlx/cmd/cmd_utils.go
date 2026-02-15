package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
