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

		modeStr, _ := cmd.Flags().GetString("mode")
		debounce, _ := cmd.Flags().GetInt("debounce")
		clear, _ := cmd.Flags().GetBool("clear")
		watchVerbose, _ := cmd.Flags().GetBool("watch-verbose")

		mode := WatchModeValidate
		if modeStr == "format" {
			mode = WatchModeFormat
		}

		opts := WatchOptions{
			Mode:        mode,
			DebounceMs:  debounce,
			ClearScreen: clear,
			Verbose:     watchVerbose,
			Out:         cmd.OutOrStdout(),
			Err:         cmd.ErrOrStderr(),
		}

		fw, err := NewFileWatcher(opts)
		if err != nil {
			return err
		}
		return fw.Watch(args)
	},
}

func init() {
	watchCmd.Flags().String("mode", "validate", "watch mode: validate or format")
	watchCmd.Flags().Int("debounce", 300, "debounce delay in milliseconds")
	watchCmd.Flags().Bool("clear", false, "clear screen before each re-run")
	watchCmd.Flags().Bool("watch-verbose", false, "verbose output from watcher")
	rootCmd.AddCommand(watchCmd)
}
