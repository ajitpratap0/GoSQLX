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
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

// statsCmd shows current object pool utilization counters.
var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show pool utilization statistics",
	Long: `Display current object pool utilization counters.

Shows gets (pool retrievals), puts (pool returns), and active (currently borrowed)
counts for each named pool: tokenizer, parser, and ast.

Examples:
  gosqlx stats
  gosqlx stats --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		jsonOutput, _ := cmd.Flags().GetBool("json")
		stats := metrics.GetPoolStats()

		if jsonOutput {
			b, err := json.MarshalIndent(stats, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(b))
			return nil
		}

		// Human-readable table
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "%-20s %10s %10s %10s\n", "POOL", "GETS", "PUTS", "ACTIVE")
		fmt.Fprintf(out, "%-20s %10s %10s %10s\n", "----", "----", "----", "------")

		names := make([]string, 0, len(stats))
		for k := range stats {
			names = append(names, k)
		}
		sort.Strings(names)

		for _, name := range names {
			s := stats[name]
			fmt.Fprintf(out, "%-20s %10d %10d %10d\n", name, s.Gets, s.Puts, s.Active())
		}
		return nil
	},
}

func init() {
	statsCmd.Flags().Bool("json", false, "Output as JSON")
	rootCmd.AddCommand(statsCmd)
}
