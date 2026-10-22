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
	"bytes"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// The global -f/--format and -o/--output flags are inherited by every
// command. A command either honours a flag or rejects it when the user sets
// it; silently ignoring a flag the user typed is never an option.

// flagSet reports whether the user explicitly passed the named flag.
func flagSet(cmd *cobra.Command, name string) bool {
	f := cmd.Flags().Lookup(name)
	return f != nil && f.Changed
}

// formatSet reports whether -f/--format asks for something other than the
// default "auto". The value, not the flag's Changed state, is what matters:
// "-f auto" is the default spelled out.
func formatSet() bool { return format != "" && format != "auto" }

// rejectGlobalFormat fails when -f/--format was set to anything but "auto" on
// a command that has only one output format.
func rejectGlobalFormat(cmd *cobra.Command) error {
	if formatSet() {
		return fmt.Errorf("%s does not support -f/--format (got %q)", cmd.CommandPath(), format)
	}
	return nil
}

// outputSink returns the writer a command should print its result to and a
// finish function to call once it has printed. With -o the result is buffered
// and written to the file by finish; otherwise it goes straight to stdout.
func outputSink(cmd *cobra.Command) (io.Writer, func() error) {
	if outputFile == "" {
		return cmd.OutOrStdout(), func() error { return nil }
	}
	var buf bytes.Buffer
	return &buf, func() error {
		return WriteOutput(buf.Bytes(), outputFile, cmd.OutOrStdout())
	}
}
