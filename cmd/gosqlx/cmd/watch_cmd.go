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
)

// watchCmd is the cobra command that registers the watch subcommand.
// The FileWatcher implementation lives in watch.go.
var watchCmd = &cobra.Command{
	Use:   "watch [file|dir...]",
	Short: "Watch SQL files and re-validate or re-format on change",
	Long: `Watch SQL files or directories and automatically re-process them when changes are detected.

Supports two modes:
  • validate (default): Re-run SQL validation on every file change
  • format: Re-format SQL files in-place on every file change

Examples:
  gosqlx watch *.sql
  gosqlx watch --mode format queries/
  gosqlx watch --debounce 500 schema.sql migrations/`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}

		fw, err := newWatcherFromCommand(cmd)
		if err != nil {
			return err
		}
		return fw.Watch(args)
	},
}

// newWatcherFromCommand keeps command options separate from the blocking watch loop.
func newWatcherFromCommand(cmd *cobra.Command) (*FileWatcher, error) {
	modeStr, err := cmd.Flags().GetString("mode")
	if err != nil {
		return nil, err
	}
	debounce, err := cmd.Flags().GetInt("debounce")
	if err != nil {
		return nil, err
	}
	clear, err := cmd.Flags().GetBool("clear")
	if err != nil {
		return nil, err
	}
	watchVerbose, err := cmd.Flags().GetBool("watch-verbose")
	if err != nil {
		return nil, err
	}
	dialect, err := cmd.Flags().GetString("dialect")
	if err != nil {
		return nil, err
	}
	if err := normalizeDialectFlag(&dialect); err != nil {
		return nil, err
	}

	var mode WatchMode
	switch modeStr {
	case "validate":
		mode = WatchModeValidate
	case "format":
		mode = WatchModeFormat
	default:
		return nil, fmt.Errorf("invalid --mode %q: want validate or format", modeStr)
	}
	fw, err := NewFileWatcher(WatchOptions{
		Mode:        mode,
		DebounceMs:  debounce,
		ClearScreen: clear,
		Verbose:     watchVerbose,
		Out:         cmd.OutOrStdout(),
		Err:         cmd.ErrOrStderr(),
	})
	if err != nil {
		return nil, err
	}
	fw.opts.ValidatorOpts.Dialect = dialect
	fw.opts.FormatterOpts.Dialect = dialect
	return fw, nil
}

func init() {
	watchCmd.Flags().String("dialect", "", dialectFlagUsage("default: postgresql"))
	watchCmd.Flags().String("mode", "validate", "watch mode: validate or format")
	watchCmd.Flags().Int("debounce", 300, "debounce delay in milliseconds")
	watchCmd.Flags().Bool("clear", false, "clear screen before each re-run")
	watchCmd.Flags().Bool("watch-verbose", false, "verbose output from watcher")
	rootCmd.AddCommand(watchCmd)
}
