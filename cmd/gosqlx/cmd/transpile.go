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
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

var transpileCmd = &cobra.Command{
	Use:   "transpile [SQL]",
	Short: "Convert SQL from one dialect to another",
	Long: `Transpile SQL between dialects.

Supported dialect pairs:
  mysql     → postgres
  postgres  → mysql
  postgres  → sqlite

SQL can be provided as a positional argument or piped via stdin.

Examples:
  gosqlx transpile --from mysql --to postgres "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)"
  echo "SELECT * FROM users WHERE name ILIKE '%alice%'" | gosqlx transpile --from postgres --to mysql
  gosqlx transpile --from postgres --to sqlite "CREATE TABLE t (id SERIAL PRIMARY KEY, tags TEXT)"`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fromStr, _ := cmd.Flags().GetString("from")
		toStr, _ := cmd.Flags().GetString("to")

		from, err := parseDialectFlag(fromStr)
		if err != nil {
			return fmt.Errorf("--from: %w", err)
		}
		to, err := parseDialectFlag(toStr)
		if err != nil {
			return fmt.Errorf("--to: %w", err)
		}

		var sql string
		if len(args) > 0 {
			sql = args[0]
		} else {
			// Read from stdin.
			data, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				return fmt.Errorf("reading stdin: %w", readErr)
			}
			sql = strings.TrimSpace(string(data))
		}

		if sql == "" {
			return fmt.Errorf("no SQL provided: pass as argument or via stdin")
		}

		result, err := gosqlx.Transpile(sql, from, to)
		if err != nil {
			return fmt.Errorf("transpile: %w", err)
		}
		fmt.Println(result)
		return nil
	},
}

func init() {
	transpileCmd.Flags().String("from", "mysql", "Source dialect (mysql, postgres, sqlite, sqlserver, oracle, snowflake, clickhouse, mariadb)")
	transpileCmd.Flags().String("to", "postgres", "Target dialect (mysql, postgres, sqlite, sqlserver, oracle, snowflake, clickhouse, mariadb)")
	rootCmd.AddCommand(transpileCmd)
}

// parseDialectFlag converts a dialect name string to a keywords.SQLDialect value.
func parseDialectFlag(s string) (keywords.SQLDialect, error) {
	switch strings.ToLower(s) {
	case "mysql":
		return keywords.DialectMySQL, nil
	case "postgres", "postgresql":
		return keywords.DialectPostgreSQL, nil
	case "sqlite":
		return keywords.DialectSQLite, nil
	case "sqlserver", "mssql":
		return keywords.DialectSQLServer, nil
	case "oracle":
		return keywords.DialectOracle, nil
	case "snowflake":
		return keywords.DialectSnowflake, nil
	case "clickhouse":
		return keywords.DialectClickHouse, nil
	case "mariadb":
		return keywords.DialectMariaDB, nil
	default:
		return keywords.DialectGeneric, fmt.Errorf(
			"unknown dialect %q; valid: mysql, postgres, sqlite, sqlserver, oracle, snowflake, clickhouse, mariadb", s)
	}
}
